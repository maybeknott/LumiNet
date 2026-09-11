// Package cmd implements the CLI interface for LumiNet using cobra.
package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/maybeknott/luminet/contracts/buildinfo"
	"github.com/spf13/cobra"
)

// Version is the current version of LumiNet, set at build time via ldflags.
var Version = buildinfo.Version

var cfgFile string
var logLevel string
var dataDir string

var rootCmd = &cobra.Command{
	Use:           "luminet",
	Version:       Version,
	SilenceUsage:  true,
	SilenceErrors: true,
	Short:         "LumiNet — network diagnostics, proxy testing, and system configuration",
	Long: `LumiNet is a comprehensive network toolbox that provides:
  - ICMP/TCP/DNS/TLS/SNI scanning via a Rust core
  - Proxy protocol parsing and testing (VMess, VLESS, Trojan, SS, Hy2, WG, etc.)
  - 8-phase network diagnostic pipeline
  - System DNS/proxy/DDNS management
  - Network profile auto-switching
  - WebSocket-driven real-time UI`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runServe(cmd, args)
	},
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.luminet/config.json)")
	rootCmd.PersistentFlags().StringVar(&logLevel, "log-level", "info", "log level (debug, info, warn, error)")
	rootCmd.PersistentFlags().StringVar(&dataDir, "data-dir", "", "data directory for database and logs")
}

func initConfig() {
	if dataDir == "" {
		home, err := os.UserHomeDir()
		if err == nil {
			dataDir = filepath.Join(home, ".luminet")
		} else {
			dataDir = ".luminet"
		}
	}

	if cfgFile == "" {
		cfgFile = filepath.Join(dataDir, "config.json")
	}

	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: could not create data directory %s: %v\n", dataDir, err)
	} else if err := os.Chmod(dataDir, 0o700); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: could not secure data directory %s: %v\n", dataDir, err)
	}
	if err := os.Setenv("LUMINET_DATA_DIR", dataDir); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: could not publish data directory to host-network manager: %v\n", err)
	}
}

func resolveDataDir() string {
	if dataDir != "" {
		return dataDir
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ".luminet"
	}
	return filepath.Join(home, ".luminet")
}
