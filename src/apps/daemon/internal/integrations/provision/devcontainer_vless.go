package provision

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

const maxDevcontainerPathBytes = 256

var (
	devcontainerUUID      = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$`)
	devcontainerVersion   = regexp.MustCompile(`^v?[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?$`)
	devcontainerBaseImage = regexp.MustCompile(`^debian:bookworm-slim@sha256:[0-9a-fA-F]{64}$`)
	devcontainerSHA256    = regexp.MustCompile(`^[0-9a-fA-F]{64}$`)
)

// VLESSDevcontainerSpec describes a generated, non-executing Xray + XHTTP
// development bundle. The generator emits files only; provisioning and remote
// execution remain owned by the existing provisioning workflow.
type VLESSDevcontainerSpec struct {
	UUID              string `json:"uuid"`
	XrayVersion       string `json:"xray_version"`
	BaseImage         string `json:"base_image"`
	XraySHA256AMD64   string `json:"xray_sha256_amd64"`
	XraySHA256ARM64   string `json:"xray_sha256_arm64"`
	Port              int    `json:"port"`
	Path              string `json:"path"`
	Mode              string `json:"mode"`
}

type GeneratedFile struct {
	Path    string `json:"path"`
	Content string `json:"content"`
}

type VLESSDevcontainerBundle struct {
	Files []GeneratedFile `json:"files"`
	Notes []string        `json:"notes"`
}

func GenerateVLESSDevcontainer(spec VLESSDevcontainerSpec) (VLESSDevcontainerBundle, error) {
	spec.UUID = strings.TrimSpace(spec.UUID)
	spec.XrayVersion = strings.TrimSpace(spec.XrayVersion)
	spec.BaseImage = strings.TrimSpace(spec.BaseImage)
	spec.XraySHA256AMD64 = strings.ToLower(strings.TrimSpace(spec.XraySHA256AMD64))
	spec.XraySHA256ARM64 = strings.ToLower(strings.TrimSpace(spec.XraySHA256ARM64))
	spec.Path = strings.TrimSpace(spec.Path)
	spec.Mode = strings.ToLower(strings.TrimSpace(spec.Mode))
	if !devcontainerUUID.MatchString(spec.UUID) {
		return VLESSDevcontainerBundle{}, fmt.Errorf("uuid must be a canonical RFC 4122 UUID")
	}
	if spec.XrayVersion == "" {
		return VLESSDevcontainerBundle{}, fmt.Errorf("xray_version is required")
	}
	if !devcontainerVersion.MatchString(spec.XrayVersion) {
		return VLESSDevcontainerBundle{}, fmt.Errorf("xray_version must look like v1.2.3")
	}
	if !strings.HasPrefix(spec.XrayVersion, "v") {
		spec.XrayVersion = "v" + spec.XrayVersion
	}
	if !devcontainerBaseImage.MatchString(spec.BaseImage) {
		return VLESSDevcontainerBundle{}, fmt.Errorf("base_image must be debian:bookworm-slim pinned by sha256 digest")
	}
	if !devcontainerSHA256.MatchString(spec.XraySHA256AMD64) || !devcontainerSHA256.MatchString(spec.XraySHA256ARM64) {
		return VLESSDevcontainerBundle{}, fmt.Errorf("xray_sha256_amd64 and xray_sha256_arm64 must each be 64 hexadecimal characters")
	}
	if spec.Port == 0 {
		spec.Port = 443
	}
	if spec.Port < 1 || spec.Port > 65535 {
		return VLESSDevcontainerBundle{}, fmt.Errorf("port must be between 1 and 65535")
	}
	if spec.Path == "" {
		spec.Path = "/xhttp"
	}
	if len(spec.Path) > maxDevcontainerPathBytes || !strings.HasPrefix(spec.Path, "/") || strings.ContainsAny(spec.Path, "\r\n") {
		return VLESSDevcontainerBundle{}, fmt.Errorf("path must start with / and be at most %d bytes", maxDevcontainerPathBytes)
	}
	if spec.Mode == "" {
		spec.Mode = "packet-up"
	}
	switch spec.Mode {
	case "auto", "packet-up", "stream-up", "stream-one":
	default:
		return VLESSDevcontainerBundle{}, fmt.Errorf("unsupported xhttp mode %q", spec.Mode)
	}

	xrayConfig := map[string]any{
		"log": map[string]any{"loglevel": "warning"},
		"inbounds": []any{map[string]any{
			"listen":   "0.0.0.0",
			"port":     spec.Port,
			"protocol": "vless",
			"settings": map[string]any{
				"clients":    []any{map[string]any{"id": spec.UUID}},
				"decryption": "none",
			},
			"streamSettings": map[string]any{
				"method": "xhttp",
				"xhttpSettings": map[string]any{
					"path": spec.Path,
					"mode": spec.Mode,
				},
			},
		}},
		"outbounds": []any{map[string]any{"protocol": "freedom", "tag": "direct"}},
	}
	configJSON, err := json.MarshalIndent(xrayConfig, "", "  ")
	if err != nil {
		return VLESSDevcontainerBundle{}, fmt.Errorf("encode Xray config: %w", err)
	}

	devcontainer := map[string]any{
		"name": "LumiNet VLESS XHTTP",
		"build": map[string]any{
			"dockerfile": "Dockerfile",
			"args": map[string]string{
				"BASE_IMAGE":         spec.BaseImage,
				"XRAY_VERSION":       spec.XrayVersion,
				"XRAY_SHA256_AMD64":  spec.XraySHA256AMD64,
				"XRAY_SHA256_ARM64":  spec.XraySHA256ARM64,
			},
		},
		"forwardPorts": []int{spec.Port},
	}
	devcontainerJSON, err := json.MarshalIndent(devcontainer, "", "  ")
	if err != nil {
		return VLESSDevcontainerBundle{}, fmt.Errorf("encode devcontainer config: %w", err)
	}

	dockerfile := `ARG BASE_IMAGE
FROM ${BASE_IMAGE}
ARG XRAY_VERSION
ARG XRAY_SHA256_AMD64
ARG XRAY_SHA256_ARM64
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl unzip \
    && rm -rf /var/lib/apt/lists/* \
    && arch="$(dpkg --print-architecture)" \
    && case "$arch" in amd64) asset="Xray-linux-64.zip"; expected="$XRAY_SHA256_AMD64" ;; arm64) asset="Xray-linux-arm64-v8a.zip"; expected="$XRAY_SHA256_ARM64" ;; *) echo "unsupported architecture: $arch" >&2; exit 1 ;; esac \
    && curl --fail --show-error --silent --location --proto '=https' --tlsv1.2 "https://github.com/XTLS/Xray-core/releases/download/${XRAY_VERSION}/${asset}" -o /tmp/xray.zip \
    && printf '%s  %s\n' "$expected" /tmp/xray.zip | sha256sum -c - \
    && unzip /tmp/xray.zip xray -d /usr/local/bin \
    && chmod 0755 /usr/local/bin/xray \
    && rm /tmp/xray.zip
COPY xray-config.json /etc/xray/config.json
EXPOSE 443
ENTRYPOINT ["/usr/local/bin/xray", "run", "-config", "/etc/xray/config.json"]
`
	// Preserve a non-443 port in the generated Dockerfile instead of pretending
	// EXPOSE controls runtime behavior.
	if spec.Port != 443 {
		dockerfile = strings.Replace(dockerfile, "EXPOSE 443", fmt.Sprintf("EXPOSE %d", spec.Port), 1)
	}

	return VLESSDevcontainerBundle{
		Files: []GeneratedFile{
			{Path: ".devcontainer/Dockerfile", Content: dockerfile},
			{Path: ".devcontainer/devcontainer.json", Content: string(devcontainerJSON) + "\n"},
			{Path: ".devcontainer/xray-config.json", Content: string(configJSON) + "\n"},
		},
		Notes: []string{
			"Generated bundle only; no remote mutation or deployment was performed.",
			"XHTTP parameters are emitted through Xray streamSettings.method=xhttp and xhttpSettings.",
			"The Debian base image is digest-pinned and both supported Xray archives are SHA-256 verified before extraction.",
		},
	}, nil
}
