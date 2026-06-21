package provision

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

type SSHRunner struct {
	client *ssh.Client
	logger *ProvisionLogger
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

	clientConfig := &ssh.ClientConfig{
		User:            user,
		Auth:            auths,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
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

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	session.Stdout = &stdout
	session.Stderr = &stderr

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
			errStr := strings.TrimSpace(stderr.String())
			if errStr == "" {
				errStr = err.Error()
			}
			return out, fmt.Errorf("command failed: %s (stderr: %s)", command, errStr)
		}
		return out, nil
	}
}

func ProvisionVPS(ctx context.Context, cfg VpsConfig, logger *ProvisionLogger) error {
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

			// Hardening: enforce strict SSL Mode on Cloudflare zone (ported from WhiteDNS-Wizard)
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
		logger.Log("Docker not found. Initiating Docker installation...")
		installCmd := "curl -fsSL https://get.docker.com | sh"
		if _, err := runner.Run(ctx, installCmd); err != nil {
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

	logger.Log("Preparing docker compose layout folder `/opt/3xui`...")
	_, _ = runner.Run(ctx, "mkdir -p /opt/3xui/tor")

	// Render configs
	postgresPass := "LumiNetPostgresSecure" + fmt.Sprintf("%d", time.Now().Unix()%10000)
	composeContent := fmt.Sprintf(`services:
  3xui:
    image: ghcr.io/mhsanaei/3x-ui:latest
    container_name: 3xui_app
    cap_add:
      - NET_ADMIN
      - NET_RAW
    volumes:
      - ./db/:/etc/x-ui/
      - ./cert/:/root/cert/
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
    image: postgres:16-alpine
    container_name: 3xui_postgres
    environment:
      POSTGRES_USER: xui
      POSTGRES_PASSWORD: %s
      POSTGRES_DB: xui
    volumes:
      - ./pgdata/:/var/lib/postgresql/data
    restart: unless-stopped
`, postgresPass, postgresPass)

	dockerfileContent := `FROM alpine:latest
RUN apk add --no-cache tor && mkdir -p /var/lib/tor && chown -R tor /var/lib/tor
COPY torrc /etc/tor/torrc
USER tor
EXPOSE 9050
CMD ["tor", "-f", "/etc/tor/torrc"]`

	torrcContent := `SocksPort 0.0.0.0:9050
SocksPolicy accept *
Log notice stdout
DataDirectory /var/lib/tor`

	logger.Log("Uploading docker-compose.yml and Tor configurations...")
	
	// Upload via Heredoc commands
	_, err = runner.Run(ctx, fmt.Sprintf("cat << 'EOF' > /opt/3xui/docker-compose.yml\n%s\nEOF", composeContent))
	if err != nil {
		return fmt.Errorf("failed to upload docker-compose.yml: %w", err)
	}

	_, err = runner.Run(ctx, fmt.Sprintf("cat << 'EOF' > /opt/3xui/tor/Dockerfile\n%s\nEOF", dockerfileContent))
	if err != nil {
		return fmt.Errorf("failed to upload tor/Dockerfile: %w", err)
	}

	_, err = runner.Run(ctx, fmt.Sprintf("cat << 'EOF' > /opt/3xui/tor/torrc\n%s\nEOF", torrcContent))
	if err != nil {
		return fmt.Errorf("failed to upload tor/torrc: %w", err)
	}

	logger.Log("Launching 3x-ui stack via Docker Compose...")
	upCmd := fmt.Sprintf("cd /opt/3xui && %s up -d --build", composeCmd)
	if _, err := runner.Run(ctx, upCmd); err != nil {
		return fmt.Errorf("failed to run docker compose up: %w", err)
	}

	logger.Log("3x-ui Docker stack started successfully!")
	logger.Log("Waiting for containers to initialize (10 seconds)...")
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(10 * time.Second):
	}

	logger.Log("Verifying 3x-ui port listening on VPS...")
	out, err := runner.Run(ctx, "docker ps --format '{{.Names}} - {{.Status}}'")
	if err == nil {
		logger.Logf("Running containers:\n%s", out)
	}

	return nil
}
