// Package cmd implements the CLI interface for LumiNet using cobra.
package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
)

// Version is the current version of LumiNet, set at build time via ldflags.
var Version = "0.1.0-dev"

// cfgFile holds the path to the configuration file.
var cfgFile string

// logLevel holds the desired log level (debug, info, warn, error).
var logLevel string

// dataDir holds the path to the data directory for SQLite, logs, etc.
var dataDir string

// rootCmd represents the base command when called without any subcommands.
var rootCmd = &cobra.Command{
	Use:     "luminet",
	Version: Version,
	Short:   "LumiNet — network diagnostics, proxy testing, and system configuration",
	Long: `LumiNet is a comprehensive network toolbox that provides:
  - ICMP/TCP/DNS/TLS/SNI scanning via a Rust core
  - Proxy protocol parsing and testing (VMess, VLESS, Trojan, SS, Hy2, WG, etc.)
  - 7-phase network diagnostic pipeline
  - System DNS/proxy/DDNS management
  - Network profile auto-switching
  - WebSocket-driven real-time UI`,
	RunE: func(cmd *cobra.Command, args []string) error {
		// Default to running serve in GUI mode if no subcommands were specified
		guiMode = true
		return runServe(cmd, args)
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
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

// initConfig reads in the config file and ENV variables if set.
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

	// Ensure data directory exists
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: could not create data directory %s: %v\n", dataDir, err)
	}
}

// resolveDataDir returns the resolved data directory path.
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
