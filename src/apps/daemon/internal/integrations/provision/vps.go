package provision

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"regexp"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/maybeknott/luminet/internal/platform/sshtrust"
)

type SSHRunner struct {
	client *ssh.Client
	logger *ProvisionLogger
}

const maxSSHCommandOutput = 1 << 20 // 1 MiB per remote command

var (
	aptPackageVersionPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.+:~_-]*$`)
	runtimeImageIDPattern    = regexp.MustCompile(`^sha256:[a-fA-F0-9]{64}$`)
)

type remoteCommandRunner interface {
	Run(context.Context, string) (string, error)
}

func aptCandidateVersion(output string) (string, error) {
	version := strings.TrimSpace(strings.SplitN(output, "\n", 2)[0])
	if version == "" || version == "(none)" || !aptPackageVersionPattern.MatchString(version) {
		return "", fmt.Errorf("invalid apt package candidate version %q", version)
	}
	return version, nil
}

func validateRuntimeImageEvidence(output string) error {
	expected := map[string]bool{
		"3xui_app":      false,
		"3xui_tor":      false,
		"3xui_postgres": false,
	}
	for _, line := range strings.Split(strings.TrimSpace(output), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 2 {
			return fmt.Errorf("malformed deployed image evidence line %q", line)
		}
		name := strings.TrimPrefix(fields[0], "/")
		if _, ok := expected[name]; !ok {
			return fmt.Errorf("unexpected deployed container %q in image evidence", name)
		}
		if !runtimeImageIDPattern.MatchString(fields[1]) {
			return fmt.Errorf("container %s reported non-immutable image ID %q", name, fields[1])
		}
		expected[name] = true
	}
	for name, seen := range expected {
		if !seen {
			return fmt.Errorf("missing deployed image ID for container %s", name)
		}
	}
	return nil
}

func installDockerFromTrustedRepo(ctx context.Context, runner remoteCommandRunner, logger *ProvisionLogger) error {
	if _, err := runner.Run(ctx, "command -v apt-get >/dev/null 2>&1 && command -v apt-cache >/dev/null 2>&1"); err != nil {
		return fmt.Errorf("automatic Docker bootstrap is supported only on apt-based Debian/Ubuntu hosts; install Docker before provisioning")
	}
	if _, err := runner.Run(ctx, "apt-get update"); err != nil {
		return fmt.Errorf("refresh apt metadata: %w", err)
	}
	candidate, err := runner.Run(ctx, "apt-cache policy docker.io | awk '/Candidate:/ {print $2; exit}'")
	if err != nil {
		return fmt.Errorf("resolve signed docker.io candidate: %w", err)
	}
	version, err := aptCandidateVersion(candidate)
	if err != nil {
		return err
	}
	logger.Logf("Installing Docker from signed distro repository at pinned version %s...", version)
	cmd := "DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends docker.io=" + version
	if _, err := runner.Run(ctx, cmd); err != nil {
		return fmt.Errorf("install pinned docker.io package: %w", err)
	}
	if _, err := runner.Run(ctx, "docker --version >/dev/null 2>&1"); err != nil {
		return fmt.Errorf("verify Docker after package installation: %w", err)
	}
	return nil
}

type boundedCapture struct {
	buf       bytes.Buffer
	remaining int
	truncated bool
}

func newBoundedCapture(limit int) *boundedCapture {
	if limit < 0 {
		limit = 0
	}
	return &boundedCapture{remaining: limit}
}

func (b *boundedCapture) Write(p []byte) (int, error) {
	written := len(p)
	if b.remaining == 0 {
		if written > 0 {
			b.truncated = true
		}
		return written, nil
	}
	keep := len(p)
	if keep > b.remaining {
		keep = b.remaining
		b.truncated = true
	}
	if keep > 0 {
		_, _ = b.buf.Write(p[:keep])
		b.remaining -= keep
	}
	return written, nil
}

func (b *boundedCapture) String() string {
	if !b.truncated {
		return b.buf.String()
	}
	return b.buf.String() + "\n[output truncated]"
}

func NewSSHRunner(cfg VpsConfig, logger *ProvisionLogger) (*SSHRunner, error) {
	auths := []ssh.AuthMethod{}
	if cfg.SSHPassword != "" {
		auths = append(auths, ssh.Password(cfg.SSHPassword))
	}
	if cfg.SSHKey != "" {
		signer, err := ssh.ParsePrivateKey([]byte(cfg.SSHKey))
		if err == nil {
			auths = append(auths, ssh.PublicKeys(signer))
		} else {
			logger.Logf("Failed to parse private key: %v. Falling back to password if set.", err)
		}
	}

	user := cfg.SSHUser
	if user == "" {
		user = "root"
	}

	hostIdentity, err := sshtrust.ParseSHA256(cfg.SSHHostKeySHA256)
	if err != nil {
		return nil, fmt.Errorf("invalid SSH host identity: %w", err)
	}

	clientConfig := &ssh.ClientConfig{
		User:            user,
		Auth:            auths,
		HostKeyCallback: hostIdentity.Callback(),
		Timeout:         15 * time.Second,
	}

	addr := net.JoinHostPort(cfg.IP, "22")
	logger.Logf("Connecting to VPS at %s as user %s...", addr, user)
	client, err := ssh.Dial("tcp", addr, clientConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to dial SSH: %w", err)
	}

	return &SSHRunner{client: client, logger: logger}, nil
}

func (s *SSHRunner) Close() {
	if s.client != nil {
		s.client.Close()
	}
}

func (s *SSHRunner) Run(ctx context.Context, command string) (string, error) {
	session, err := s.client.NewSession()
	if err != nil {
		return "", err
	}
	defer session.Close()

	stdout := newBoundedCapture(maxSSHCommandOutput)
	session.Stdout = stdout
	session.Stderr = io.Discard

	done := make(chan error, 1)
	go func() {
		done <- session.Run(command)
	}()

	select {
	case <-ctx.Done():
		session.Signal(ssh.SIGKILL)
		return "", ctx.Err()
	case err := <-done:
		out := stdout.String()
		if err != nil {
			return out, fmt.Errorf("remote command failed: %w", err)
		}
		return out, nil
	}
}

func (s *SSHRunner) RunScript(ctx context.Context, script string) (string, error) {
	if len(script) == 0 {
		return "", fmt.Errorf("remote script is empty")
	}
	if len(script) > 2<<20 {
		return "", fmt.Errorf("remote script exceeds 2 MiB limit")
	}
	session, err := s.client.NewSession()
	if err != nil {
		return "", err
	}
	defer session.Close()

	stdout := newBoundedCapture(maxSSHCommandOutput)
	session.Stdout = stdout
	session.Stderr = io.Discard
	session.Stdin = strings.NewReader(script)

	done := make(chan error, 1)
	go func() {
		done <- session.Run("bash -se")
	}()

	select {
	case <-ctx.Done():
		_ = session.Signal(ssh.SIGKILL)
		return "", ctx.Err()
	case err := <-done:
		out := stdout.String()
		if err != nil {
			return out, fmt.Errorf("remote script failed: %w", err)
		}
		return out, nil
	}
}

func ProvisionVPS(ctx context.Context, cfg VpsConfig, logger *ProvisionLogger) error {
	// Validate immutable runtime inputs before any remote or Cloudflare mutation.
	if err := cfg.validateRuntimeSupplyChain(); err != nil {
		return fmt.Errorf("invalid VPS runtime supply chain: %w", err)
	}

	if cfg.CFToken != "" && cfg.Domain != "" {
		logger.Logf("DNS check: Pointing domain %s to VPS IP %s on Cloudflare...", cfg.Domain, cfg.IP)
		cf := NewCFClient(cfg.CFToken)
		zoneID, err := cf.GetZoneID(ctx, cfg.Domain)
		if err != nil {
			logger.Logf("Cloudflare DNS warning: failed to resolve zone ID for %s: %v", cfg.Domain, err)
		} else {
			err = cf.UpsertDNSRecord(ctx, zoneID, cfg.Domain, cfg.IP, false)
			if err != nil {
				logger.Logf("Cloudflare DNS warning: failed to upsert DNS A-record for %s: %v", cfg.Domain, err)
			} else {
				logger.Logf("Cloudflare DNS: A-record pointed %s -> %s successfully!", cfg.Domain, cfg.IP)
			}
			err = cf.SetSSLModeStrict(ctx, zoneID)
			if err != nil {
				logger.Logf("Cloudflare SSL warning: failed to set Strict SSL mode: %v", err)
			} else {
				logger.Log("Cloudflare SSL: Strict SSL mode enabled successfully!")
			}
		}
	}

	runner, err := NewSSHRunner(cfg, logger)
	if err != nil {
		return err
	}
	defer runner.Close()

	logger.Log("Connected successfully! Checking if Docker is installed...")
	hasDocker := false
	if _, err := runner.Run(ctx, "command -v docker >/dev/null 2>&1"); err == nil {
		hasDocker = true
		logger.Log("Docker is already installed on the host.")
	}

	if !hasDocker {
		logger.Log("Docker not found. Installing from the host's signed distro repository...")
		if err := installDockerFromTrustedRepo(ctx, runner, logger); err != nil {
			return fmt.Errorf("failed to install Docker: %w", err)
		}
		logger.Log("Docker installed successfully. Starting and enabling service...")
		_, _ = runner.Run(ctx, "systemctl enable --now docker")
	}

	logger.Log("Checking Docker Compose capability...")
	hasCompose := false
	composeCmd := "docker compose"
	if _, err := runner.Run(ctx, "docker compose version >/dev/null 2>&1"); err == nil {
		hasCompose = true
	} else if _, err := runner.Run(ctx, "docker-compose version >/dev/null 2>&1"); err == nil {
		hasCompose = true
		composeCmd = "docker-compose"
	}

	if !hasCompose {
		logger.Log("Docker Compose not found. Installing docker-compose-plugin...")
		_, err = runner.Run(ctx, "apt-get update && apt-get install -y docker-compose-plugin")
		if err != nil {
			logger.Log("Apt failed, trying yum package manager...")
			_, err = runner.Run(ctx, "yum install -y docker-compose-plugin")
		}
		if err != nil {
			return fmt.Errorf("failed to install Docker Compose plugin: %w", err)
		}
		composeCmd = "docker compose"
	}

	postgresPass, err := generateProvisionSecret()
	if err != nil {
		return err
	}
	composeContent := fmt.Sprintf(`services:
  3xui:
    image: %s
    container_name: 3xui_app
    cap_add:
      - NET_ADMIN
      - NET_RAW
    volumes:
      - /opt/3xui/db/:/etc/x-ui/
      - /opt/3xui/cert/:/root/cert/
    environment:
      XRAY_VMESS_AEAD_FORCED: "false"
      XUI_ENABLE_FAIL2BAN: "true"
      XUI_DB_TYPE: "postgres"
      XUI_DB_DSN: "postgres://xui:%s@postgres:5432/xui?sslmode=disable"
    tty: true
    ports:
      - "2053:2053/tcp"
      - "443:443/tcp"
      - "443:443/udp"
    restart: unless-stopped
    depends_on:
      - postgres
      - tor
  tor:
    build:
      context: ./tor
    container_name: 3xui_tor
    restart: unless-stopped
  postgres:
    image: %s
    container_name: 3xui_postgres
    environment:
      POSTGRES_USER: xui
      POSTGRES_PASSWORD: %s
      POSTGRES_DB: xui
    volumes:
      - /opt/3xui/pgdata/:/var/lib/postgresql/data
    restart: unless-stopped
`, cfg.ThreeXUIImage, postgresPass, cfg.PostgresImage, postgresPass)

	dockerfileContent := fmt.Sprintf(`FROM %s
RUN apk add --no-cache tor=%s && mkdir -p /var/lib/tor && chown -R tor /var/lib/tor
COPY torrc /etc/tor/torrc
USER tor
EXPOSE 9050
CMD ["tor", "-f", "/etc/tor/torrc"]`, cfg.AlpineImage, cfg.TorAPKVersion)

	torrcContent := `SocksPort 0.0.0.0:9050
SocksPolicy accept *
Log notice stdout
DataDirectory /var/lib/tor`

	logger.Logf("Using immutable VPS images: 3x-ui=%s postgres=%s alpine=%s", cfg.ThreeXUIImage, cfg.PostgresImage, cfg.AlpineImage)
	logger.Logf("Using explicit Tor package version: %s", cfg.TorAPKVersion)
	logger.Log("Preparing an atomic managed 3x-ui configuration generation...")
	if _, err := runner.Run(ctx, "command -v bash >/dev/null 2>&1 && command -v base64 >/dev/null 2>&1 && command -v mktemp >/dev/null 2>&1 && command -v find >/dev/null 2>&1"); err != nil {
		return fmt.Errorf("remote host lacks required transactional provisioning tools: %w", err)
	}
	layoutScript, err := buildManagedLayoutScript("/opt/3xui", composeCmd, composeContent, dockerfileContent, torrcContent)
	if err != nil {
		return fmt.Errorf("build managed VPS layout transaction: %w", err)
	}
	if _, err := runner.RunScript(ctx, layoutScript); err != nil {
		return fmt.Errorf("publish managed VPS layout transaction: %w", err)
	}

	logger.Log("3x-ui Docker stack started successfully!")
	logger.Log("Waiting for containers to initialize (10 seconds)...")
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(10 * time.Second):
	}

	logger.Log("Verifying running VPS containers and immutable image identities...")
	out, err := runner.Run(ctx, "docker ps --format '{{.Names}} - {{.Status}}'")
	if err != nil {
		return fmt.Errorf("verify running containers: %w", err)
	}
	logger.Logf("Running containers:\n%s", out)

	imageEvidence, err := runner.Run(ctx, "docker inspect --format '{{.Name}} {{.Image}}' 3xui_app 3xui_tor 3xui_postgres")
	if err != nil {
		return fmt.Errorf("capture deployed image IDs: %w", err)
	}
	if err := validateRuntimeImageEvidence(imageEvidence); err != nil {
		return fmt.Errorf("invalid deployed image evidence: %w", err)
	}
	logger.Logf("Deployed image IDs:\n%s", imageEvidence)

	return nil
}
