package cmd

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	controlsession "github.com/maybeknott/luminet/contracts/session"
	"github.com/maybeknott/luminet/internal/adapters/api"
	"github.com/maybeknott/luminet/internal/analysis/provider"
	"github.com/maybeknott/luminet/internal/foundation/capabilities"
	"github.com/maybeknott/luminet/internal/foundation/config"
	"github.com/maybeknott/luminet/internal/foundation/store"
	"github.com/maybeknott/luminet/internal/platform/system"
	"github.com/maybeknott/luminet/internal/runtime/decoy"
	"github.com/maybeknott/luminet/internal/runtime/runtimecore"
	"github.com/maybeknott/luminet/internal/workflows/jobs"
	"github.com/spf13/cobra"
)

// servePort is the HTTP/WS listening port.
var servePort int

// serveHost is the bind address for the server.
var serveHost string

// apiKey is the optional API key for authentication.
var apiKey string

// allowedOrigins holds the list of allowed CORS origins.
var allowedOrigins []string

// noBrowser disables automatic browser opening on serve.
var noBrowser bool

// webMode starts the retired embedded web console instead of the native shell.
var webMode bool

// stdioMode starts the stdio MCP engine instead of HTTP server.
var stdioMode bool

// WebDist holds the embedded React UI files passed from package main.
var WebDist fs.FS

// serveCmd represents the serve command that starts the HTTP/WS API server.
var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start the LumiNet dashboard daemon and local API",
	Long:  `Starts the LumiNet local API daemon. Wails desktop app connects to this API.`,
	RunE:  runServe,
}

func init() {
	rootCmd.AddCommand(serveCmd)

	serveCmd.Flags().IntVarP(&servePort, "port", "p", 8470, "HTTP listen port")
	serveCmd.Flags().StringVar(&serveHost, "host", "127.0.0.1", "HTTP bind address")
	serveCmd.Flags().StringVar(&apiKey, "api-key", "", "API key for authentication (auto-generated for the session when empty)")
	serveCmd.Flags().StringSliceVar(&allowedOrigins, "allowed-origins", nil, "Allowed CORS origins (comma-separated; default: localhost only)")
	serveCmd.Flags().BoolVar(&noBrowser, "no-browser", false, "do not open the legacy web console automatically (deprecated: the legacy web console is retired and the browser is never opened)")
	_ = serveCmd.Flags().MarkHidden("no-browser")
	_ = serveCmd.Flags().MarkDeprecated("no-browser", "the legacy web console is retired; this flag has no effect")
	serveCmd.Flags().BoolVar(&webMode, "web", false, "start the retired embedded web console instead of native desktop")
	serveCmd.Flags().BoolVar(&stdioMode, "stdio", false, "start stdio MCP engine instead of HTTP server")
}

// runServe initializes all subsystems and starts the HTTP/WS server.
func runServe(cmd *cobra.Command, args []string) (retErr error) {
	dd := resolveDataDir()
	dbPath := filepath.Join(dd, "luminet.db")

	// Initialize config manager
	if cfgFile == "" {
		cfgFile = filepath.Join(dd, "config.json")
	}
	cfgMgr := config.NewManager(cfgFile)
	cfg, err := cfgMgr.Load()
	if err != nil {
		return fmt.Errorf("failed to load configuration: %w", err)
	}

	// One caller-owned lifetime controls every daemon background task.
	signalCtx, stopSignals := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
	defer stopSignals()
	ctx, cancelCause := context.WithCancelCause(signalCtx)
	defer cancelCause(nil)

	// A previous daemon may have crashed after mutating host routing. Restore
	// that durable state before this process establishes a new recovery owner.
	recoveryCtx, recoveryCancel := context.WithTimeout(context.Background(), 20*time.Second)
	if err := system.RecoverHostNetworkInDir(recoveryCtx, dd); err != nil {
		recoveryCancel()
		return fmt.Errorf("recover stale host-network state: %w", err)
	}
	recoveryCancel()

	watchdog, err := launchHostNetworkWatchdog(dd)
	if err != nil {
		return err
	}
	go monitorHostNetworkWatchdog(ctx, watchdog, cancelCause)
	defer func() {
		restoreCtx, restoreCancel := context.WithTimeout(context.Background(), 20*time.Second)
		restoreErr := system.RecoverHostNetworkInDir(restoreCtx, dd)
		restoreCancel()
		if restoreErr != nil {
			// Deliberately leave the watchdog alive. Once this parent exits it
			// gets a second independent attempt at the same durable recovery.
			retErr = errors.Join(retErr, fmt.Errorf("restore host-network state: %w", restoreErr))
			return
		}
		if err := watchdog.Stop(); err != nil {
			retErr = errors.Join(retErr, err)
		}
		if cause := context.Cause(ctx); cause != nil && !errors.Is(cause, context.Canceled) {
			retErr = errors.Join(retErr, cause)
		}
	}()

	// Open and migrate database
	db, err := store.OpenDB(dbPath)
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}
	defer db.Close()

	if err := db.Migrate(); err != nil {
		return fmt.Errorf("database migration failed: %w", err)
	}

	// Create job manager
	jobMgr := jobs.NewJobManager(ctx, db)
	defer jobMgr.Stop()

	// Passive daemon-wide network epochs are shared by runtime flow owners and
	// operator diagnostics. Monitoring observes only; it does not request routes,
	// acquire radios, or mutate host networking.
	networkMonitor := system.GetNetworkMonitor()
	networkMonitor.Start(ctx)
	defer networkMonitor.Stop()
	defer func() {
		if err := runtimecore.DefaultManager().Close(); err != nil {
			retErr = errors.Join(retErr, fmt.Errorf("stop runtime engines: %w", err))
		}
	}()

	if stdioMode {
		fmt.Println("Starting LumiNet in stdio MCP mode...")
		api.StdioRun(ctx, jobMgr, db)
		return nil
	}

	// Initialize scheduler
	runner, err := initScheduler(cfg)
	if err != nil {
		return fmt.Errorf("failed to initialize scheduler: %w", err)
	}

	if err := runner.Start(ctx); err != nil {
		return fmt.Errorf("failed to start scheduler: %w", err)
	}
	defer runner.Stop()

	// Start background decoy traffic manager if enabled
	var decoyMgr *decoy.Manager
	if cfg.DecoyTraffic.Enabled {
		decoyMgr = decoy.New(cfg.DecoyTraffic.Targets, cfg.DecoyTraffic.VolumePerMinute)
		decoyMgr.Start(ctx)
		fmt.Printf("Started background decoy traffic generator (%d KB/min)\n", cfg.DecoyTraffic.VolumePerMinute)
	}
	defer func() {
		if decoyMgr != nil {
			fmt.Println("Stopping background decoy traffic generator...")
			decoyMgr.Stop()
		}
	}()

	// Authentication is on by default: if no key was supplied, generate a
	// cryptographically random one for this session so the privileged control
	// API is never silently unauthenticated.
	effectiveKey := apiKey
	if effectiveKey == "" {
		effectiveKey = generateAPIKey()
		fmt.Printf("No --api-key supplied; generated a session API key:\n  %s\n", effectiveKey)
	}

	// Default CORS to the local serve origins only. A wildcard is never applied
	// implicitly; operators must opt in explicitly via --allowed-origins.
	origins := allowedOrigins
	if len(origins) == 0 {
		origins = defaultLocalOrigins(servePort)
	}

	if !isLoopbackHost(serveHost) {
		fmt.Printf("WARNING: binding to non-loopback address %q exposes the privileged control API to the network.\n"+
			"         Keep the API key secret and restrict --allowed-origins.\n", serveHost)
	}

	// Create API server
	serverConfig := &api.ServerConfig{
		Host:           serveHost,
		Port:           servePort,
		APIKey:         effectiveKey,
		AllowedOrigins: origins,
		RateLimitRPS:   100,
		WebDist:        WebDist,
		EnableWeb:      webMode,
	}
	if err := api.ValidateAPIConfig(serverConfig); err != nil {
		return fmt.Errorf("invalid privileged API configuration: %w", err)
	}

	// Initialize the canonical built-in provider corpus and legacy radix adapter.
	if err := provider.DefaultService.InitializeBuiltin(); err != nil {
		fmt.Printf("Warning: failed to initialize builtin provider corpus: %v\n", err)
	} else {
	}

	reg := capabilities.NewRegistry()
	srv := api.NewServer(ctx, serverConfig, jobMgr, db, cfgMgr, reg)

	addr := fmt.Sprintf("http://%s:%d", serveHost, servePort)
	fmt.Printf("LumiNet %s starting on %s\n", Version, addr)

	// Start server in a background goroutine
	serverErrChan := make(chan error, 1)
	go func() {
		if err := srv.Run(); err != nil && err != http.ErrServerClosed {
			serverErrChan <- err
		}
		close(serverErrChan)
	}()

	// Publish local discovery only after the daemon is actually healthy. The
	// descriptor is instance-owned so an older process cannot remove a newer
	// daemon's session file during shutdown.
	if discoveryURL, ok := localDiscoveryURL(serveHost, servePort); ok {
		readyCtx, readyCancel := context.WithTimeout(ctx, 5*time.Second)
		readyChan := make(chan error, 1)
		go func() {
			readyChan <- waitDaemonReady(readyCtx, discoveryURL, 25*time.Millisecond)
		}()
		select {
		case err := <-readyChan:
			readyCancel()
			if err != nil {
				_ = shutdownServer(srv)
				return fmt.Errorf("daemon readiness failed: %w", err)
			}
		case err := <-serverErrChan:
			readyCancel()
			if err == nil {
				return fmt.Errorf("daemon stopped before readiness")
			}
			return fmt.Errorf("server error before readiness: %w", err)
		}

		instanceID := generateInstanceID()
		sessionPath := filepath.Join(dd, "session.json")
		descriptor := controlsession.Descriptor{
			Version:    controlsession.CurrentVersion,
			InstanceID: instanceID,
			APIURL:     discoveryURL,
			APIKey:     effectiveKey,
		}
		if err := controlsession.WriteFileAtomic(sessionPath, descriptor); err != nil {
			_ = shutdownServer(srv)
			return fmt.Errorf("publish daemon session: %w", err)
		}
		defer func() {
			if err := controlsession.RemoveIfOwned(sessionPath, instanceID); err != nil {
				fmt.Printf("Warning: could not remove owned daemon session: %v\n", err)
			}
		}()
	} else {
		fmt.Printf("WARNING: daemon bind host %q has no safe loopback discovery endpoint; session discovery disabled.\n", serveHost)
	}

	// Wait for shutdown trigger or server error
	select {
	case <-ctx.Done():
		// Normal graceful shutdown path
	case err := <-serverErrChan:
		if err != nil {
			return fmt.Errorf("server error: %w", err)
		}
	}

	// Shutdown the HTTP server
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		fmt.Printf("Error during server shutdown: %v\n", err)
	}

	return nil
}

// localDiscoveryURL returns the loopback URL clients can safely discover for
// a local listener. Wildcard listeners are reachable via loopback; listeners
// bound to a specific non-loopback interface are deliberately not published.
func localDiscoveryURL(host string, port int) (string, bool) {
	host = strings.TrimSpace(host)
	switch host {
	case "", "0.0.0.0":
		host = "127.0.0.1"
	case "::", "[::]":
		host = "::1"
	case "localhost":
		// already safe
	default:
		ip := net.ParseIP(strings.Trim(host, "[]"))
		if ip == nil || !ip.IsLoopback() {
			return "", false
		}
		host = ip.String()
	}
	return "http://" + net.JoinHostPort(host, strconv.Itoa(port)), true
}

func shutdownServer(srv *api.Server) error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	return srv.Shutdown(ctx)
}

func generateInstanceID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic("luminet: failed to generate session instance id: " + err.Error())
	}
	return hex.EncodeToString(b)
}

// generateAPIKey returns a 256-bit cryptographically random key as hex.
func generateAPIKey() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand failure at startup is unrecoverable and must not result
		// in a weak or empty key.
		panic("luminet: failed to generate API key: " + err.Error())
	}
	return hex.EncodeToString(b)
}

// isLoopbackHost reports whether the bind host is a loopback address.
func isLoopbackHost(h string) bool {
	if h == "" || h == "localhost" {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

// defaultLocalOrigins returns the CORS origins permitted by default: the local
// serve origin over IPv4 loopback and the localhost hostname.
func defaultLocalOrigins(port int) []string {
	return []string{
		fmt.Sprintf("http://127.0.0.1:%d", port),
		fmt.Sprintf("http://localhost:%d", port),
	}
}
