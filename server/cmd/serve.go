package cmd

import (
	"context"
	"crypto/rand"
	"embed"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"
	"time"

	"github.com/maybeknott/luminet/internal/api"
	"github.com/maybeknott/luminet/internal/config"
	"github.com/maybeknott/luminet/internal/jobs"
	"github.com/maybeknott/luminet/internal/proxy"
	"github.com/maybeknott/luminet/internal/store"
	"github.com/maybeknott/luminet/internal/system"
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

// guiMode starts the native desktop window.
var guiMode bool

// WebDist holds the embedded React UI files passed from package main.
var WebDist embed.FS

// serveCmd represents the serve command that starts the HTTP/WS API server.
var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start the LumiNet native desktop app and local API",
	Long: `Starts the LumiNet local API and, by default on supported Windows builds,
opens the native desktop app. The embedded React console is retired from the
primary product path and remains available only with --web for compatibility.`,
	RunE: runServe,
}

func init() {
	rootCmd.AddCommand(serveCmd)

	serveCmd.Flags().IntVarP(&servePort, "port", "p", 8470, "HTTP listen port")
	serveCmd.Flags().StringVar(&serveHost, "host", "127.0.0.1", "HTTP bind address")
	serveCmd.Flags().StringVar(&apiKey, "api-key", "", "API key for authentication (auto-generated for the session when empty)")
	serveCmd.Flags().StringSliceVar(&allowedOrigins, "allowed-origins", nil, "Allowed CORS origins (comma-separated; default: localhost only)")
	serveCmd.Flags().BoolVar(&noBrowser, "no-browser", false, "do not open the legacy web console automatically")
	serveCmd.Flags().BoolVar(&guiMode, "gui", false, "start LumiNet inside the native desktop window")
	serveCmd.Flags().BoolVar(&webMode, "web", false, "start the retired embedded web console instead of native desktop")
}

// runServe initializes all subsystems and starts the HTTP/WS server.
func runServe(cmd *cobra.Command, args []string) error {
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

	// Cancelable context for managing shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Signal handling for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		fmt.Println("\nShutting down LumiNet...")
		cancel()
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
	jobMgr := jobs.NewJobManager(db)

	// Initialize scheduler
	runner, err := initScheduler(cfg)
	if err != nil {
		return fmt.Errorf("failed to initialize scheduler: %w", err)
	}

	if err := runner.Start(context.Background()); err != nil {
		return fmt.Errorf("failed to start scheduler: %w", err)
	}
	defer runner.Stop()

	// Start background decoy traffic manager if enabled
	var decoyMgr *proxy.DecoyTrafficManager
	if cfg.DecoyTraffic.Enabled {
		decoyMgr = proxy.NewDecoyTrafficManager(cfg.DecoyTraffic.Targets, cfg.DecoyTraffic.VolumePerMinute)
		decoyMgr.Start()
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

	// Initialize built-in provider corpus
	if err := proxy.InitBuiltinProviderCorpus(); err != nil {
		fmt.Printf("Warning: failed to initialize builtin provider corpus: %v\n", err)
	}

	srv := api.NewServer(serverConfig, jobMgr, db, cfgMgr)

	addr := fmt.Sprintf("http://%s:%d", serveHost, servePort)
	fmt.Printf("LumiNet %s starting on %s\n", Version, addr)

	useNativeShell := guiMode || (!webMode && nativeGUIDefault())

	// Open browser only for the retired web console path.
	if webMode && !noBrowser {
		go openBrowser(addr)
	}

	// Start server in a background goroutine
	serverErrChan := make(chan error, 1)
	go func() {
		if err := srv.Run(); err != nil && err != http.ErrServerClosed {
			serverErrChan <- err
		}
		close(serverErrChan)
	}()

	// Native desktop is the primary app shell. It blocks until the window closes.
	if useNativeShell {
		runGUI(addr, effectiveKey, cancel)
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

	// Revert system proxy if enabled
	liveCfg := cfgMgr.Get()
	if liveCfg.SystemProxy.Enabled {
		fmt.Println("Reverting system proxy settings...")
		_ = system.DisableSystemProxy(context.Background())
	}

	return nil
}

func nativeGUIDefault() bool {
	return runtime.GOOS == "windows" && nativeGUIAvailable()
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

// openBrowser opens the given URL in the default system browser.
func openBrowser(url string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("cmd", "/c", "start", url)
	case "darwin":
		cmd = exec.Command("open", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	_ = cmd.Run()
}
