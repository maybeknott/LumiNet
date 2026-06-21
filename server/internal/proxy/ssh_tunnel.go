package proxy

import (
	"context"
	"fmt"
	"net"
	"time"

	"golang.org/x/crypto/ssh"
)

// SshTunnelClient represents the client establishing TCP connections over an SSH tunnel.
type SshTunnelClient struct {
	Host        string // e.g. "127.0.0.1:22"
	User        string
	Password    string
	PrivateKey  string // optional SSH private key content
	DialTimeout time.Duration
}

// NewSshTunnelClient instantiates a new SSH tunnel proxy client config.
func NewSshTunnelClient(host, user, password, privateKey string) *SshTunnelClient {
	return &SshTunnelClient{
		Host:        host,
		User:        user,
		Password:    password,
		PrivateKey:  privateKey,
		DialTimeout: 10 * time.Second,
	}
}

// DialTarget dials the remote target through the SSH tunnel using a direct-tcpip channel.
func (c *SshTunnelClient) DialTarget(ctx context.Context, target string) (net.Conn, error) {
	authMethods := []ssh.AuthMethod{}
	if c.PrivateKey != "" {
		signer, err := ssh.ParsePrivateKey([]byte(c.PrivateKey))
		if err != nil {
			return nil, fmt.Errorf("failed to parse private key: %w", err)
		}
		authMethods = append(authMethods, ssh.PublicKeys(signer))
	}
	if c.Password != "" {
		authMethods = append(authMethods, ssh.Password(c.Password))
	}

	config := &ssh.ClientConfig{
		User:            c.User,
		Auth:            authMethods,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         c.DialTimeout,
	}

	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "tcp", c.Host)
	if err != nil {
		return nil, fmt.Errorf("failed to dial SSH server %s: %w", c.Host, err)
	}

	sshConn, chans, reqs, err := ssh.NewClientConn(conn, c.Host, config)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to negotiate SSH client session: %w", err)
	}

	client := ssh.NewClient(sshConn, chans, reqs)

	targetConn, err := client.Dial("tcp", target)
	if err != nil {
		client.Close()
		return nil, fmt.Errorf("failed to dial target %s via SSH tunnel: %w", target, err)
	}

	return &sshConnWrapper{
		Conn:   targetConn,
		client: client,
	}, nil
}

type sshConnWrapper struct {
	net.Conn
	client *ssh.Client
}

func (w *sshConnWrapper) Close() error {
	err1 := w.Conn.Close()
	err2 := w.client.Close()
	if err1 != nil {
		return err1
	}
	return err2
}
