package proxy

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"strings"
	"testing"

	"golang.org/x/crypto/pbkdf2"
)

func TestFormatRegistry_NPVT(t *testing.T) {
	registry := GetFormatRegistry()

	npvtJSON := `{
		"host": "test-npvt.domain",
		"port": 443,
		"id": "uuid-1234",
		"aid": 0,
		"net": "ws",
		"type": "none",
		"tls": "tls",
		"sni": "sni-target.com",
		"path": "/ws-path",
		"protocol": "vless",
		"remarks": "NPVT Remark"
	}`

	cfg, err := registry.Decode("npvt", []byte(npvtJSON))
	if err != nil {
		t.Fatalf("failed to decode npvt configuration: %v", err)
	}

	if cfg.Address != "test-npvt.domain" || cfg.Port != 443 || cfg.UUID != "uuid-1234" || cfg.Protocol != ProtocolVLESS {
		t.Errorf("decoded config properties do not match: %+v", cfg)
	}

	if cfg.SNI != "sni-target.com" || cfg.Path != "/ws-path" || cfg.Name != "NPVT Remark" {
		t.Errorf("decoded transport/metadata properties do not match: %+v", cfg)
	}
}

func TestFormatRegistry_HC(t *testing.T) {
	registry := GetFormatRegistry()

	hcJSON := `{
		"server": "ssh-hc.domain",
		"port": 22,
		"password": "ssh-password",
		"remarks": "HC Remark"
	}`

	// Test direct JSON
	cfg, err := registry.Decode("hc", []byte(hcJSON))
	if err != nil {
		t.Fatalf("failed to decode hc json: %v", err)
	}
	if cfg.Address != "ssh-hc.domain" || cfg.Port != 22 || cfg.Password != "ssh-password" || cfg.Name != "HC Remark" {
		t.Errorf("decoded hc config does not match: %+v", cfg)
	}

	// Test URL scheme
	b64 := base64.StdEncoding.EncodeToString([]byte(hcJSON))
	urlStr := "hc://" + b64
	cfg2, err := registry.Decode("hc", []byte(urlStr))
	if err != nil {
		t.Fatalf("failed to decode hc url: %v", err)
	}
	if cfg2.Address != "ssh-hc.domain" || cfg2.Port != 22 || cfg2.Password != "ssh-password" {
		t.Errorf("decoded hc url config properties do not match: %+v", cfg2)
	}
}

func TestFormatRegistry_EHI(t *testing.T) {
	registry := GetFormatRegistry()

	// format: host|port|password|remarks
	raw := "ss-ehi.domain|8388|ehi-pass|EHI Remark"
	b64 := base64.StdEncoding.EncodeToString([]byte(raw))
	ehiURI := "ehi://" + b64

	cfg, err := registry.Decode("ehi", []byte(ehiURI))
	if err != nil {
		t.Fatalf("failed to decode ehi: %v", err)
	}

	if cfg.Address != "ss-ehi.domain" || cfg.Port != 8388 || cfg.Password != "ehi-pass" || cfg.Name != "EHI Remark" {
		t.Errorf("decoded ehi config properties do not match: %+v", cfg)
	}
}

func TestFormatRegistry_Opaque(t *testing.T) {
	registry := GetFormatRegistry()

	// Standard VMess URI obfuscated
	vmessURI := "vmess://eyJhZGQiOiJ0ZXN0LXZtZXNzIiwiYWlkIjowLCJob3N0IjoiIiwiaWQiOiIxIiwicGF0aCI6IiIsInBvcnQiOjQ0MywicHMiOiJ0ZXN0IiwicXVlcnkiOiIiLCJzbmkiOiIiLCJ0bHMiOiIiLCJ0eXBlIjoibm9uZSIsInYiOjJ9"

	encrypted := []byte(vmessURI)
	for i := range encrypted {
		encrypted[i] ^= 0x5A
	}
	b64 := base64.StdEncoding.EncodeToString(encrypted)
	opaqueURI := "opaque:" + b64

	cfg, err := registry.Decode("opaque_bundle", []byte(opaqueURI))
	if err != nil {
		t.Fatalf("failed to decode opaque config: %v", err)
	}

	// We expect auto-detected vmess since the decrypted content starts with vmess://
	if cfg.Protocol != ProtocolVMess || cfg.Address != "test-vmess" || cfg.Port != 443 {
		t.Errorf("decoded opaque config properties do not match: %+v", cfg)
	}
}

func TestFormatRegistry_AutoDecode(t *testing.T) {
	registry := GetFormatRegistry()

	npvtJSON := `{
		"host": "auto-npvt.domain",
		"port": 80,
		"id": "uuid-auto",
		"aid": 0,
		"net": "tcp",
		"type": "none",
		"tls": "none",
		"protocol": "vmess",
		"remarks": "Auto Remark"
	}`

	cfg, err := registry.AutoDecode([]byte(npvtJSON))
	if err != nil {
		t.Fatalf("failed to auto-decode npvt payload: %v", err)
	}

	if cfg.Address != "auto-npvt.domain" || cfg.Port != 80 || cfg.UUID != "uuid-auto" || cfg.Protocol != ProtocolVMess {
		t.Errorf("auto-decoded properties do not match: %+v", cfg)
	}
}

func TestFormatRegistry_Nipo(t *testing.T) {
	registry := GetFormatRegistry()

	nipoJSON := `{
		"name": "Nipo Format Reg Node",
		"config": {
			"serverIp": "127.0.0.11",
			"serverPort": "8080",
			"token": "reg-token",
			"protocol": "http",
			"fakeUrls": "google.com",
			"tlsEnable": false
		}
	}`

	b64 := base64.StdEncoding.EncodeToString([]byte(nipoJSON))
	uri := "nipovpn://" + b64

	cfg, err := registry.Decode("nipo", []byte(uri))
	if err != nil {
		t.Fatalf("failed to decode nipo configuration via registry: %v", err)
	}

	if cfg.Protocol != ProtocolNipo || cfg.Address != "127.0.0.11" || cfg.Port != 8080 || cfg.Password != "reg-token" || cfg.Name != "Nipo Format Reg Node" {
		t.Errorf("decoded properties do not match: %+v", cfg)
	}
}

func TestFormatRegistry_NetMod(t *testing.T) {
	registry := GetFormatRegistry()

	plainURI := "vless://uuid-netmod-1234@auto-netmod.domain:443?path=/netmod-ws"
	key := []byte("_netsyna_netmod_")
	
	// Encrypt using helper
	ciphertext := encryptECB([]byte(plainURI), key)
	b64 := base64.StdEncoding.EncodeToString(ciphertext)
	uri := "netmod://" + b64

	cfg, err := registry.Decode("nm", []byte(uri))
	if err != nil {
		t.Fatalf("failed to decode netmod configuration: %v", err)
	}

	if cfg.Protocol != ProtocolVLESS || cfg.Address != "auto-netmod.domain" || cfg.Port != 443 || cfg.UUID != "uuid-netmod-1234" || cfg.Path != "/netmod-ws" {
		t.Errorf("decoded netmod config properties do not match: %+v", cfg)
	}
}

func TestFormatRegistry_SlipNet(t *testing.T) {
	registry := GetFormatRegistry()

	// V28 profile string: Version|Tunnel Type/Mode|Name|Domain|Resolvers|AuthMode|KeepAlive|CC|Port|Host|GSO|...[62]VLESS UUID|...[78]VLESS SNI
	parts := make([]string, 80)
	parts[0] = "28"
	parts[1] = "VLESS"
	parts[2] = "SlipNet Test Node"
	parts[3] = "slipnet.domain"
	parts[8] = "8443"
	parts[62] = "uuid-slipnet-5678"
	parts[64] = "ws"
	parts[65] = "/slipnet-ws"
	parts[78] = "sni-slipnet.com"

	decryptedProfile := strings.Join(parts, "|")
	uri := encryptSlipNet([]byte(decryptedProfile))

	cfg, err := registry.Decode("slipnet", []byte(uri))
	if err != nil {
		t.Fatalf("failed to decode slipnet configuration: %v", err)
	}

	if cfg.Protocol != ProtocolVLESS || cfg.Address != "slipnet.domain" || cfg.Port != 8443 || cfg.UUID != "uuid-slipnet-5678" || cfg.Path != "/slipnet-ws" || cfg.SNI != "sni-slipnet.com" || cfg.Name != "SlipNet Test Node" {
		t.Errorf("decoded slipnet config properties do not match: %+v", cfg)
	}
}

// Helpers for tests
func encryptECB(plaintext []byte, key []byte) []byte {
	blockSize := 16
	padLen := blockSize - (len(plaintext) % blockSize)
	padded := make([]byte, len(plaintext)+padLen)
	copy(padded, plaintext)
	for i := len(plaintext); i < len(padded); i++ {
		padded[i] = byte(padLen)
	}

	block, _ := aes.NewCipher(key)
	ciphertext := make([]byte, len(padded))
	for i := 0; i < len(padded); i += blockSize {
		block.Encrypt(ciphertext[i:i+blockSize], padded[i:i+blockSize])
	}
	return ciphertext
}

func encryptSlipNet(plaintext []byte) string {
	s0, m0 := uint64(0x1c8986f91dd8ec9a), uint64(0x557034dc3ddda3bb)
	s1, m1 := uint64(0xc70a4a42712024ee), uint64(0x6f5577ae58747e8e)
	s2, m2 := uint64(0x924d4af0d8a43e0b), uint64(0xfcd9e79819861e07)
	s3, m3 := uint64(0x4a5573b012f4d08b), uint64(0x998e67c256d955e3)

	key := make([]byte, 32)
	binary.LittleEndian.PutUint64(key[0:8], s0^m0)
	binary.LittleEndian.PutUint64(key[8:16], s1^m1)
	binary.LittleEndian.PutUint64(key[16:24], s2^m2)
	binary.LittleEndian.PutUint64(key[24:32], s3^m3)

	block, _ := aes.NewCipher(key)
	aesgcm, _ := cipher.NewGCM(block)

	iv := []byte("123456789012") // 12 bytes
	ciphertext := aesgcm.Seal(nil, iv, plaintext, nil)

	payload := make([]byte, 1+12+len(ciphertext))
	payload[0] = 0x01
	copy(payload[1:13], iv)
	copy(payload[13:], ciphertext)

	return "slipnet-enc://" + base64.StdEncoding.EncodeToString(payload)
}

func TestFormatRegistry_HCTools(t *testing.T) {
	registry := GetFormatRegistry()

	plainURI := "vless://uuid-hctools-1234@hctools-test.domain:443?path=/hctools-ws"
	
	// Test .tut format
	tutURI := encryptHCTools([]byte(plainURI), []byte("fubvx788b46v"))
	cfg, err := registry.Decode("hctools", []byte(tutURI))
	if err != nil {
		t.Fatalf("failed to decode tut configuration: %v", err)
	}
	if cfg.Protocol != ProtocolVLESS || cfg.Address != "hctools-test.domain" || cfg.UUID != "uuid-hctools-1234" {
		t.Errorf("decoded tut config does not match: %+v", cfg)
	}

	// Test .sks format
	sksURI := encryptHCTools([]byte(plainURI), []byte("dyv35224nossas!!"))
	cfg2, err := registry.Decode("hctools", []byte(sksURI))
	if err != nil {
		t.Fatalf("failed to decode sks configuration: %v", err)
	}
	if cfg2.Protocol != ProtocolVLESS || cfg2.Address != "hctools-test.domain" || cfg2.UUID != "uuid-hctools-1234" {
		t.Errorf("decoded sks config does not match: %+v", cfg2)
	}
}

func encryptHCTools(plaintext []byte, password []byte) string {
	salt := []byte("salt123456789012") // 16 bytes
	iv := []byte("iv1234567890")      // 12 bytes

	key := pbkdf2.Key(password, salt, 1000, 32, sha256.New)

	block, _ := aes.NewCipher(key)
	aesgcm, _ := cipher.NewGCM(block)

	ciphertext := aesgcm.Seal(nil, iv, plaintext, nil)

	// HCTools format: salt.iv.encrypted (base64 encoded strings separated by dot)
	saltB64 := base64.StdEncoding.EncodeToString(salt)
	ivB64 := base64.StdEncoding.EncodeToString(iv)
	cipherB64 := base64.StdEncoding.EncodeToString(ciphertext)

	return fmt.Sprintf("%s.%s.%s", saltB64, ivB64, cipherB64)
}

