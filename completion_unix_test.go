//go:build !windows

package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// This file holds the tests that need a POSIX shell or a built bareshare
// binary: bash and zsh integrations are driven in bash and zsh, the binary is
// built without an .exe suffix and found through a PATH of /usr/bin:/bin, and
// the processes run under a HOME-only environment. The grammar and the
// catalogue are covered portably in completion_test.go.

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// realHome is $HOME as the process started, before any test swapped it. The Go
// toolchain keeps its module and build caches under it.
var realHome = os.Getenv("HOME")

// shellPath locates a shell, skipping the test where there is none.
func shellPath(t *testing.T, name string) string {
	t.Helper()
	p, err := exec.LookPath(name)
	if err != nil {
		t.Skipf("%s not on PATH", name)
	}
	return p
}

// syntaxCheck fails the test if the named shell will not parse src.
func syntaxCheck(t *testing.T, shell, src string) {
	t.Helper()
	sh := shellPath(t, shell)
	f := filepath.Join(t.TempDir(), "script")
	if err := os.WriteFile(f, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(sh, "-n", f).CombinedOutput(); err != nil {
		t.Errorf("%s rejected the emitted script: %v\n%s\n--- script ---\n%s", shell, err, out, src)
	}
}

// buildBareshare compiles the module into a temp directory and returns the
// binary's directory, so a shell adapter under test can call the real tool.
func buildBareshare(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go not on PATH")
	}
	dir := t.TempDir()
	cmd := exec.Command("go", "build", "-o", filepath.Join(dir, cmdName), ".")
	// WHY: the surrounding test has pointed HOME at a scratch directory; left
	// alone the toolchain would rebuild a whole read-only module cache inside
	// it, which is slow and then impossible to clean up.
	cmd.Env = append(os.Environ(), "HOME="+realHome)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}
	return dir
}

// fileMarker is the only file in the directory the adapters are driven from,
// so a "files" directive has exactly one right answer.
const fileMarker = "marker-file.txt"

// driveShell writes the integration for shell plus a driver script that fakes
// the shell's completion state, runs it, and returns what the adapter offered.
func driveShell(t *testing.T, shell, binDir, driver string, args []string) []string {
	t.Helper()
	sh := shellPath(t, shell)
	script, err := completion(t, shell)
	if err != nil {
		t.Fatal(err)
	}
	tmp := t.TempDir()
	scriptPath := filepath.Join(tmp, "integration")
	driverPath := filepath.Join(tmp, "driver")
	for p, body := range map[string]string{scriptPath: script, driverPath: driver} {
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	cmd := exec.Command(sh, append([]string{driverPath, scriptPath}, args...)...)
	// WHY: the "files" directive completes the working directory, so the test
	// needs one whose contents it chose.
	cwd := t.TempDir()
	if err := os.WriteFile(filepath.Join(cwd, fileMarker), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	cmd.Dir = cwd
	cmd.Env = []string{
		"PATH=" + binDir + string(os.PathListSeparator) + "/usr/bin:/bin",
		"HOME=" + os.Getenv("HOME"),
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("driving %s over %q: %v\n%s", shell, args, err, stderr.String())
	}
	s := strings.TrimSuffix(string(out), "\n")
	if s == "" {
		return nil
	}
	return strings.Split(s, "\n")
}

// ---------------------------------------------------------------------------
// the emitted scripts, in their real shells
// ---------------------------------------------------------------------------

// TestCompletionScript_ParsesInItsShell: each supported shell accepts the
// integration emitted for it. The content checks live in
// TestCompletionScript_InstallsCompletion.
func TestCompletionScript_ParsesInItsShell(t *testing.T) {
	for _, shell := range supportedShells {
		t.Run(shell, func(t *testing.T) {
			isolatedHome(t)
			out, err := completion(t, shell)
			if err != nil {
				t.Fatal(err)
			}
			syntaxCheck(t, shell, out)
		})
	}
}

// TestCompletion_UnsupportedShellParsesInBash: the complaint written for an
// unsupported shell is itself valid shell code, so `. <(...)` can run it.
func TestCompletion_UnsupportedShellParsesInBash(t *testing.T) {
	for _, tc := range unsupportedShellCases {
		t.Run(tc.name, func(t *testing.T) {
			isolatedHome(t)
			out, err := completion(t, tc.args...)
			if err != errSilent {
				t.Fatalf("error is %v, want errSilent", err)
			}
			syntaxCheck(t, "bash", out)
		})
	}
}

// ---------------------------------------------------------------------------
// the adapters, in their real shells
// ---------------------------------------------------------------------------

// bashDriver sources the integration, fakes readline's completion state from
// the remaining arguments, runs _bareshare and prints COMPREPLY.
const bashDriver = `source "$1"; shift
COMP_CWORD=$1; shift
COMP_WORDS=( "$@" )
_bareshare
if [ ${#COMPREPLY[@]} -gt 0 ]; then printf '%s\n' "${COMPREPLY[@]}"; fi
`

// zshDriver sources the integration and then replaces the pieces of the zsh
// completion system the adapter calls, so what it asked for is observable
// without driving an interactive shell.
const zshDriver = `emulate -L zsh
compdef() { : }
source "$1"; shift
CURRENT=$1; shift
words=( "$@" )
_describe() { print -rl -- ${(P)${@[-1]}} }
_files() { print -r -- '<files>' }
_message() { print -r -- '<message>' }
compset() { print -r -- "<compset $*>" }
# A completion function returns non-zero to mean "no matches"; that is an
# answer, not a driver failure.
_bareshare || true
`

// TestShellAdapters_TranslateEveryDirective drives the emitted bash and zsh
// functions in their real shells against a real bareshare binary. The grammar
// is already covered above; what this proves is that each shell asks the right
// question and turns every directive into the right completion.
func TestShellAdapters_TranslateEveryDirective(t *testing.T) {
	type check func(t *testing.T, got []string)
	exactly := func(want ...string) check {
		return func(t *testing.T, got []string) {
			if strings.Join(got, "\n") != strings.Join(want, "\n") {
				t.Errorf("offered mismatch:\n got: %q\nwant: %q", got, want)
			}
		}
	}
	holds := func(want ...string) check {
		return func(t *testing.T, got []string) {
			for _, w := range want {
				if !containsString(got, w) {
					t.Errorf("offered %q is missing %q", got, w)
				}
			}
		}
	}

	// The same lines for both shells; the cursor index differs only by the
	// shells' own 0- vs 1-based convention.
	cases := []struct {
		name  string
		words []string
		bash  check
		zsh   check
	}{
		{"the mode position offers every mode",
			[]string{"bareshare", ""},
			holds("send", "receive", "completion"),
			holds("send:send a file to a verified peer over QUIC", "receive:listen for an incoming file from a verified peer")},
		{"a partial word is matched by the shell, not by bareshare",
			[]string{"bareshare", "r"},
			exactly("rotate-key", "receive"),
			// zsh's own matcher runs inside the real _describe, which this
			// driver replaces, so it sees the unfiltered list.
			holds("receive:listen for an incoming file from a verified peer")},
		{"the flag position offers the flags not yet given",
			[]string{"bareshare", "send", "--file", "x", "--"},
			exactly("--to", "--peer-key", "--port", "--network"),
			holds("--to:receiver address as host and port")},
		{"the words directive for a flag value",
			[]string{"bareshare", "send", "--network", "udp"},
			exactly("udp4", "udp6", "udp"),
			holds("udp4:IPv4 only (default)")},
		{"the files directive becomes a file completion",
			[]string{"bareshare", "send", "--file", ""},
			exactly(fileMarker),
			exactly("<files>")},
		{"the none directive offers nothing at all",
			[]string{"bareshare", "send", "--to", ""},
			exactly(),
			exactly("<message>")},
		{"the bash split of --network= lands on the bare =",
			[]string{"bareshare", "send", "--network", "="},
			exactly("udp4", "udp6", "udp"),
			nil},
		{"the bash split of --network=VALUE lands on the value",
			[]string{"bareshare", "send", "--network", "=", "udp6"},
			exactly("udp6"),
			nil},
		{"the joined --network=VALUE zsh keeps is split by compset",
			[]string{"bareshare", "send", "--network=ud"},
			nil,
			exactly("<compset -P --network=>", "udp4:IPv4 only (default)", "udp6:IPv6 only", "udp:dual-stack, IPv4 and IPv6")},
	}

	keyDir := isolatedHome(t)
	bin := buildBareshare(t)
	for _, c := range cases {
		for _, shell := range []string{"bash", "zsh"} {
			check, driver, cursor := c.bash, bashDriver, len(c.words)-1
			if shell == "zsh" {
				check, driver, cursor = c.zsh, zshDriver, len(c.words)
			}
			if check == nil {
				continue
			}
			t.Run(shell+": "+c.name, func(t *testing.T) {
				args := append([]string{strconv.Itoa(cursor)}, c.words...)
				check(t, driveShell(t, shell, bin, driver, args))
			})
		}
	}
	if _, err := os.Lstat(keyDir); err == nil {
		t.Errorf("completion created the key directory")
	}
}

// TestZshCompletion_RegistersWithCompsys: the zsh integration must actually
// bind _bareshare to bareshare once the completion system is loaded, and must
// say so when it is not.
func TestZshCompletion_RegistersWithCompsys(t *testing.T) {
	isolatedHome(t)
	bin := buildBareshare(t)
	zsh := shellPath(t, "zsh")

	for _, tc := range []struct {
		name     string
		compinit bool
	}{
		{"sourced after compinit", true},
		{"sourced before compinit", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			script := ""
			if tc.compinit {
				script = "autoload -Uz compinit; compinit -u -D\n"
			}
			script += `. <(command bareshare completion zsh)
(( $+_comps[bareshare] )) && print -r -- "bound:$_comps[bareshare]"
print -r -- "function:$(whence -w _bareshare)"
`
			f := filepath.Join(t.TempDir(), "rc.zsh")
			if err := os.WriteFile(f, []byte(script), 0o600); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command(zsh, "-f", f)
			cmd.Env = []string{
				"PATH=" + bin + string(os.PathListSeparator) + "/usr/bin:/bin",
				"HOME=" + os.Getenv("HOME"),
			}
			var stderr bytes.Buffer
			cmd.Stderr = &stderr
			out, err := cmd.Output()
			if err != nil {
				t.Fatalf("zsh: %v\n%s", err, stderr.String())
			}
			if !strings.Contains(string(out), "function:_bareshare: function") {
				t.Errorf("_bareshare was not defined: %q", out)
			}
			bound := strings.Contains(string(out), "bound:_bareshare")
			if bound != tc.compinit {
				t.Errorf("completion bound = %v, want %v (stdout %q)", bound, tc.compinit, out)
			}
			if !tc.compinit && !strings.Contains(stderr.String(), "compinit") {
				t.Errorf("no hint about compinit on stderr: %q", stderr.String())
			}
		})
	}
}

// TestBashCompletion_RegistersWithReadline: the bash integration, sourced the
// documented way, must bind _bareshare to bareshare.
func TestBashCompletion_RegistersWithReadline(t *testing.T) {
	isolatedHome(t)
	bin := buildBareshare(t)
	bash := shellPath(t, "bash")

	// WHY: eval, the documented form. bash 3.2 reads nothing when it sources
	// a pipe, so `. <(...)` would silently install nothing on macOS.
	script := `eval "$(command bareshare completion bash)"
complete -p bareshare
`
	f := filepath.Join(t.TempDir(), "rc.bash")
	if err := os.WriteFile(f, []byte(script), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bash, f)
	cmd.Env = []string{
		"PATH=" + bin + string(os.PathListSeparator) + "/usr/bin:/bin",
		"HOME=" + os.Getenv("HOME"),
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("bash: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "complete -F _bareshare bareshare") {
		t.Errorf("completion was not registered: %q", out)
	}
}

// TestCompletion_ExitStatusThroughMain: the real binary exits non-zero for an
// unsupported shell, with the complaint on stdout and nothing on stderr, and
// zero for a supported one.
func TestCompletion_ExitStatusThroughMain(t *testing.T) {
	isolatedHome(t)
	bin := buildBareshare(t)
	exe := filepath.Join(bin, cmdName)

	for _, tc := range []struct {
		args       []string
		wantExit   int
		wantStdout string
	}{
		{[]string{"completion", "fish"}, 1, ">&2 echo \"fish not supported\" && false\n"},
		{[]string{"completion"}, 1, ">&2 echo \"no shell specified\" && false\n"},
		{[]string{"--complete"}, 1, ""},
		{[]string{"--complete", "bash", "1", "--", "bareshare", "ver"}, 0, "words\nshow-key\nrotate-key\nsend\nreceive\nversion\ncompletion\nhelp\n"},
	} {
		t.Run(strings.Join(tc.args, " "), func(t *testing.T) {
			cmd := exec.Command(exe, tc.args...)
			var stdout, stderr bytes.Buffer
			cmd.Stdout, cmd.Stderr = &stdout, &stderr
			err := cmd.Run()
			code := 0
			if ee, ok := err.(*exec.ExitError); ok {
				code = ee.ExitCode()
			} else if err != nil {
				t.Fatal(err)
			}
			if code != tc.wantExit {
				t.Errorf("exit = %d, want %d (stderr %q)", code, tc.wantExit, stderr.String())
			}
			if stdout.String() != tc.wantStdout {
				t.Errorf("stdout mismatch:\n got: %q\nwant: %q", stdout.String(), tc.wantStdout)
			}
			if strings.Contains(stderr.String(), "goroutine") {
				t.Errorf("the binary panicked: %s", stderr.String())
			}
			if tc.args[0] == "completion" && stderr.String() != "" {
				t.Errorf("completion wrote to stderr as well as stdout: %q", stderr.String())
			}
		})
	}
}
