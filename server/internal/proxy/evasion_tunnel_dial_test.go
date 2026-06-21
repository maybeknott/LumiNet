package proxy

import (
	"io"
	"testing"
)

func TestEvasionTunnelDial_GDrive(t *testing.T) {
	mgr := &EvasionTunnelManager{
		covertMode:          "gdrive",
		covertGdocsFolderId: "folder-gdrive-123",
		// Leave covertGdocsAccessToken empty to use simulator mode
		covertGdocsAccessToken: "",
	}

	conn, err := mgr.dialWithEvasion(
		"example.com",
		443,
		0,
		0,
		false,
		false,
		false,
		0,
		"all",
		0,
		0,
		false,
		"8.8.8.8:53",
		"",
		0,
		false,
		0,
		"",
	)
	if err != nil {
		t.Fatalf("dialWithEvasion failed for gdrive covert mode: %v", err)
	}
	defer conn.Close()

	// Write payload
	n, err := conn.Write([]byte("gdrive test payload"))
	if err != nil {
		t.Fatalf("Failed to write to gdrive connection: %v", err)
	}
	if n != 19 {
		t.Errorf("Expected to write 19 bytes, wrote %d", n)
	}

	// Read from connection (simulator returns io.EOF)
	buf := make([]byte, 10)
	rn, err := conn.Read(buf)
	if err != io.EOF {
		t.Errorf("Expected EOF read on simulator connection, got %v", err)
	}
	if rn != 0 {
		t.Errorf("Expected 0 bytes read, got %d", rn)
	}
}

func TestEvasionTunnelDial_GDocs(t *testing.T) {
	mgr := &EvasionTunnelManager{
		covertMode:             "gdocs",
		covertGdocsFolderId:   "folder-gdocs-456",
		covertGdocsAccessToken: "",
	}

	conn, err := mgr.dialWithEvasion(
		"example.com",
		443,
		0,
		0,
		false,
		false,
		false,
		0,
		"all",
		0,
		0,
		false,
		"8.8.8.8:53",
		"",
		0,
		false,
		0,
		"",
	)
	if err != nil {
		t.Fatalf("dialWithEvasion failed for gdocs covert mode: %v", err)
	}
	defer conn.Close()

	// Write payload
	n, err := conn.Write([]byte("gdocs test payload"))
	if err != nil {
		t.Fatalf("Failed to write to gdocs connection: %v", err)
	}
	if n != 18 {
		t.Errorf("Expected to write 18 bytes, wrote %d", n)
	}

	// Read from connection (simulator returns io.EOF)
	buf := make([]byte, 10)
	rn, err := conn.Read(buf)
	if err != io.EOF {
		t.Errorf("Expected EOF read on simulator connection, got %v", err)
	}
	if rn != 0 {
		t.Errorf("Expected 0 bytes read, got %d", rn)
	}
}
