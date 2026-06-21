package proxy

import (
	"bytes"
	"net"
	"testing"
)

func TestObfuscatedConn_ReadWrite(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer l.Close()

	password := "salamanderSecretKey"

	go func() {
		conn, err := l.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		// Wrap server-side connection in ObfuscatedConn
		paced := NewObfuscatedConn(conn, password)
		buf := make([]byte, 1024)
		n, err := paced.Read(buf)
		if err != nil {
			return
		}
		// Write back modified response
		_, _ = paced.Write(append([]byte("echo: "), buf[:n]...))
	}()

	client, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatalf("failed to dial: %v", err)
	}
	defer client.Close()

	// Wrap client-side connection in ObfuscatedConn
	pacedClient := NewObfuscatedConn(client, password)

	payload := []byte("hello stream obfuscation")
	_, err = pacedClient.Write(payload)
	if err != nil {
		t.Fatalf("failed to write: %v", err)
	}

	buf := make([]byte, 1024)
	n, err := pacedClient.Read(buf)
	if err != nil {
		t.Fatalf("failed to read: %v", err)
	}

	expected := append([]byte("echo: "), payload...)
	if !bytes.Equal(buf[:n], expected) {
		t.Errorf("expected %q, got %q", string(expected), string(buf[:n]))
	}
}

func TestObfuscatedPacketConn_ReadWrite(t *testing.T) {
	pc1, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen packet: %v", err)
	}
	defer pc1.Close()

	pc2, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen packet: %v", err)
	}
	defer pc2.Close()

	password := "salamanderPacketSecretKey"

	obfs1 := NewObfuscatedPacketConn(pc1, password)
	obfs2 := NewObfuscatedPacketConn(pc2, password)

	payload := []byte("hello datagram obfuscation")

	// Write payload from obfs1 to obfs2
	_, err = obfs1.WriteTo(payload, obfs2.LocalAddr())
	if err != nil {
		t.Fatalf("failed to write datagram: %v", err)
	}

	// Read and verify on obfs2
	buf := make([]byte, 2048)
	n, addr, err := obfs2.ReadFrom(buf)
	if err != nil {
		t.Fatalf("failed to read datagram: %v", err)
	}

	if addr.String() != obfs1.LocalAddr().String() {
		t.Errorf("expected sender %s, got %s", obfs1.LocalAddr(), addr)
	}

	if !bytes.Equal(buf[:n], payload) {
		t.Errorf("expected %q, got %q", string(payload), string(buf[:n]))
	}
}

func TestGenerateHysteria2Config_Success(t *testing.T) {
	cfg := Hysteria2Outbound{
		Server:      "my-server.com",
		Port:        443,
		Password:    "my-password",
		Obfuscation: "my-obfs",
		UpMbps:      100,
		DownMbps:    200,
	}

	out, err := GenerateHysteria2Config(cfg)
	if err != nil {
		t.Fatalf("failed to generate config: %v", err)
	}

	if out["type"] != "hysteria2" || out["server"] != "my-server.com" || out["server_port"] != 443 || out["password"] != "my-password" {
		t.Errorf("unexpected output config: %+v", out)
	}

	obfsMap := out["obfs"].(map[string]interface{})
	if obfsMap["type"] != "salamander" || obfsMap["password"] != "my-obfs" {
		t.Errorf("unexpected obfs settings: %+v", obfsMap)
	}

	bandwidthMap := out["bandwidth"].(map[string]interface{})
	if bandwidthMap["up"] != "100 Mbps" || bandwidthMap["down"] != "200 Mbps" {
		t.Errorf("unexpected bandwidth settings: %+v", bandwidthMap)
	}
}
