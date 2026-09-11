package provision

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestGenerateProvisionSecretIsStrongAndShellSafe(t *testing.T) {
	secret, err := generateProvisionSecret()
	if err != nil {
		t.Fatal(err)
	}
	if len(secret) < 43 {
		t.Fatalf("secret too short: %d", len(secret))
	}
	if strings.ContainsAny(secret, " \t\r\n'\"") {
		t.Fatalf("secret contains shell-sensitive whitespace/quotes: %q", secret)
	}
}

func TestManagedLayoutScriptOrdersOwnershipBeforeRollbackAndUsesAtomicGeneration(t *testing.T) {
	script, err := buildManagedLayoutScript("/opt/3xui", "docker compose", "compose", "dockerfile", "torrc")
	if err != nil {
		t.Fatal(err)
	}
	guard := strings.Index(script, "unmanaged layout")
	trap := strings.Index(script, "trap rollback")
	if guard < 0 || trap < 0 || guard > trap {
		t.Fatalf("ownership guard must precede rollback trap")
	}
	for _, want := range []string{"umask 077", ".luminet-generations", ".stage.XXXXXX", "config >/dev/null", "current.next", "mv -Tf", "set +e", "chmod 600 \"$stage/docker-compose.yml\""} {
		if !strings.Contains(script, want) {
			t.Fatalf("script missing %q", want)
		}
	}
	if strings.Contains(script, "> /opt/3xui/docker-compose.yml") {
		t.Fatal("script overwrites live compose file directly")
	}
}

func TestManagedLayoutScriptRunsAndRollsBackGeneration(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("managed VPS transaction targets Linux hosts and uses GNU/Linux command semantics")
	}
	root := filepath.Join(t.TempDir(), "managed")
	if err := os.MkdirAll(filepath.Join(root, "db"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "db", "state"), []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	bin := t.TempDir()
	docker := filepath.Join(bin, "docker")
	fake := `#!/bin/sh
if [ "$1" != "compose" ]; then exit 2; fi
shift
case " $* " in
  *" config "*) exit 0 ;;
  *" up "*) if [ "${FAIL_UP:-}" = "1" ]; then exit 9; fi; exit 0 ;;
esac
exit 0
`
	if err := os.WriteFile(docker, []byte(fake), 0o700); err != nil {
		t.Fatal(err)
	}
	run := func(compose string, fail bool) error {
		script, err := buildManagedLayoutScript(root, "docker compose", compose, "FROM scratch\n", "SocksPort 9050\n")
		if err != nil {
			return err
		}
		cmd := exec.Command("bash", "-se")
		cmd.Stdin = strings.NewReader(script)
		cmd.Env = append(os.Environ(), "PATH="+bin+":"+os.Getenv("PATH"))
		if fail {
			cmd.Env = append(cmd.Env, "FAIL_UP=1")
		}
		return cmd.Run()
	}
	if err := run("generation-one", false); err != nil {
		t.Fatal(err)
	}
	first, err := os.Readlink(filepath.Join(root, "current"))
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(first, "docker-compose.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("compose mode=%o", info.Mode().Perm())
	}
	if data, _ := os.ReadFile(filepath.Join(root, "db", "state")); string(data) != "keep" {
		t.Fatalf("state dir changed: %q", data)
	}
	if err := run("generation-two", true); err == nil {
		t.Fatal("expected failed launch")
	}
	second, err := os.Readlink(filepath.Join(root, "current"))
	if err != nil {
		t.Fatal(err)
	}
	if second != first {
		t.Fatalf("rollback current=%q want %q", second, first)
	}
	data, err := os.ReadFile(filepath.Join(first, "docker-compose.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "generation-one" {
		t.Fatalf("previous generation changed: %q", data)
	}
}

func TestManagedLayoutScriptRefusesUnmanagedDirectoryBeforeMutation(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("managed VPS transaction targets Linux hosts and uses GNU/Linux command semantics")
	}
	root := filepath.Join(t.TempDir(), "unmanaged")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "foreign.txt"), []byte("mine"), 0o600); err != nil {
		t.Fatal(err)
	}
	script, err := buildManagedLayoutScript(root, "docker compose", "compose", "dockerfile", "torrc")
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("bash", "-se")
	cmd.Stdin = strings.NewReader(script)
	if err := cmd.Run(); err == nil {
		t.Fatal("unmanaged layout accepted")
	}
	if _, err := os.Stat(filepath.Join(root, ".luminet-managed")); !os.IsNotExist(err) {
		t.Fatalf("marker created on refused layout: %v", err)
	}
	if data, _ := os.ReadFile(filepath.Join(root, "foreign.txt")); string(data) != "mine" {
		t.Fatalf("foreign file changed: %q", data)
	}
}
