package proxy

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestSSHTunneling(t *testing.T) {
	// Create local echo TCP listener
	echoListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to listen for echo service: %v", err)
	}
	defer echoListener.Close()

	go func() {
		for {
			conn, err := echoListener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}(conn)
		}
	}()

	// Start local mock SSH server
	sshConfig := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			if c.User() == "testuser" && string(pass) == "testpass" {
				return nil, nil
			}
			return nil, fmt.Errorf("auth failed")
		},
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		t.Fatalf("Failed to create signer: %v", err)
	}
	sshConfig.AddHostKey(signer)

	sshListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to listen for mock SSH: %v", err)
	}
	defer sshListener.Close()

	go func() {
		for {
			conn, err := sshListener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				sshConn, chans, reqs, err := ssh.NewServerConn(c, sshConfig)
				if err != nil {
					return
				}
				go ssh.DiscardRequests(reqs)
				for newChan := range chans {
					if newChan.ChannelType() != "direct-tcpip" {
						_ = newChan.Reject(ssh.UnknownChannelType, "unknown channel type")
						continue
					}

					type localForward struct {
						DestAddr string
						DestPort uint32
						OrigAddr string
						OrigPort uint32
					}
					var payload localForward
					if err := ssh.Unmarshal(newChan.ExtraData(), &payload); err != nil {
						_ = newChan.Reject(ssh.ConnectionFailed, "bad payload")
						continue
					}

					channel, requests, err := newChan.Accept()
					if err != nil {
						continue
					}
					go ssh.DiscardRequests(requests)

					dest := fmt.Sprintf("%s:%d", payload.DestAddr, payload.DestPort)
					destConn, err := net.Dial("tcp", dest)
					if err != nil {
						_ = channel.Close()
						continue
					}

					go func() {
						defer channel.Close()
						defer destConn.Close()
						_, _ = io.Copy(channel, destConn)
					}()
					go func() {
						defer channel.Close()
						defer destConn.Close()
						_, _ = io.Copy(destConn, channel)
					}()
				}
				_ = sshConn.Close()
			}(conn)
		}
	}()

	client := NewSshTunnelClient(sshListener.Addr().String(), "testuser", "testpass", "")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := client.DialTarget(ctx, echoListener.Addr().String())
	if err != nil {
		t.Fatalf("Failed to dial target through SSH tunnel: %v", err)
	}
	defer conn.Close()

	payload := []byte("hello ssh tunnel")
	_, err = conn.Write(payload)
	if err != nil {
		t.Fatalf("Failed to write to SSH tunnel: %v", err)
	}

	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("Failed to read from SSH tunnel: %v", err)
	}

	if string(buf[:n]) != string(payload) {
		t.Errorf("Got message %q, want %q", buf[:n], payload)
	}
}
