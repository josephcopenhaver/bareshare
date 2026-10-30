package main

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"unicode"
)

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// isolatedHome points HOME at a scratch directory and returns the key
// directory bareshare would use inside it, so a test can prove that
// completion never creates or reads it.
func isolatedHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	return filepath.Join(home, "."+cmdName)
}

// completion runs `bareshare completion <args>` and returns stdout.
func completion(t *testing.T, args ...string) (string, error) {
	t.Helper()
	var out bytes.Buffer
	err := writeCompletion(&out, args)
	return out.String(), err
}

// completeLines asks bareshare what fits at word cword of words and returns the
// directive and the candidate lines, exactly as a shell adapter would see them.
func completeLines(t *testing.T, shell string, cword int, words ...string) (string, []string) {
	t.Helper()
	args := append([]string{shell, strconv.Itoa(cword), "--"}, words...)
	var out bytes.Buffer
	if err := writeComplete(&out, args); err != nil {
		t.Fatalf("--complete %v: %v", words, err)
	}
	lines := strings.Split(strings.TrimSuffix(out.String(), "\n"), "\n")
	if len(lines) == 0 || lines[0] == "" {
		t.Fatalf("--complete %v produced no directive: %q", words, out.String())
	}
	return lines[0], lines[1:]
}

func containsString(hay []string, needle string) bool {
	for _, h := range hay {
		if h == needle {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// the catalogue
// ---------------------------------------------------------------------------

// TestCompletionCatalogue_MatchesTheHelpMenu keeps the completion catalogue and
// the help menu from drifting apart: a mode or flag added to one but not the
// other is either undocumented or uncompletable.
func TestCompletionCatalogue_MatchesTheHelpMenu(t *testing.T) {
	t.Parallel()

	menu := usageText()
	modeLine := regexp.MustCompile(`(?m)^  ([a-z-]+) {2,}\S`)
	usageLine := regexp.MustCompile(`(?m)^  ` + regexp.QuoteMeta(cmdName) + ` ([a-z-]+)(.*)$`)
	flagWord := regexp.MustCompile(`--([A-Za-z][A-Za-z-]*)`)

	// Modes, from the "Modes:" section.
	menuModes := map[string]bool{}
	for _, m := range modeLine.FindAllStringSubmatch(menu, -1) {
		menuModes[m[1]] = true
	}
	// Flags per mode, from the "Usage:" lines.
	menuFlags := map[string]map[string]bool{}
	for _, m := range usageLine.FindAllStringSubmatch(menu, -1) {
		flags := map[string]bool{}
		for _, f := range flagWord.FindAllStringSubmatch(m[2], -1) {
			flags[f[1]] = true
		}
		menuFlags[m[1]] = flags
	}
	if len(menuModes) == 0 || len(menuFlags) == 0 {
		t.Fatalf("could not parse the help menu:\n%s", menu)
	}

	catalogue := map[string]bool{}
	for _, m := range completionModes {
		catalogue[m.name] = true
		if !menuModes[m.name] {
			t.Errorf("mode %s can be completed but is not in the help menu", m.name)
		}
		// WHY: zsh's _describe splits a candidate from its description on the
		// first ':', so one in the text would truncate it.
		if m.desc == "" || strings.Contains(m.desc, ":") {
			t.Errorf("mode %s has an empty or colon-bearing description: %q", m.name, m.desc)
		}
		for _, f := range m.flags {
			if f.desc == "" || strings.Contains(f.desc, ":") {
				t.Errorf("flag --%s of %s has an empty or colon-bearing description: %q", f.name, m.name, f.desc)
			}
			if strings.ContainsAny(f.name, " \t=-") && !regexp.MustCompile(`^[a-z][a-z-]*$`).MatchString(f.name) {
				t.Errorf("flag %q of %s is not a plain flag name", f.name, m.name)
			}
			if !menuFlags[m.name][f.name] {
				t.Errorf("--%s of %s can be completed but the usage line does not document it", f.name, m.name)
			}
			for _, c := range f.choices {
				if strings.ContainsAny(c.word, " \t:") || strings.Contains(c.desc, ":") {
					t.Errorf("choice %q of --%s is not shell-safe", c.word, f.name)
				}
			}
		}
		for f := range menuFlags[m.name] {
			if flagFor(m.flags, "--"+f) == nil {
				t.Errorf("--%s is in the usage line of %s but cannot be completed", f, m.name)
			}
		}
	}
	for m := range menuModes {
		if !catalogue[m] {
			t.Errorf("mode %s is in the help menu but cannot be completed", m)
		}
	}
	for m := range menuFlags {
		if !catalogue[m] {
			t.Errorf("mode %s has a usage line but cannot be completed", m)
		}
	}
}

// TestCompletionCatalogue_MatchesTheFlagSets keeps the completion catalogue
// and the flags the modes really parse from drifting apart. The help-menu test
// above catches a flag missing from the documentation; this one catches a flag
// added to a FlagSet but not to the catalogue (or the reverse), and a boolean
// flag the catalogue would wrongly expect a value for.
func TestCompletionCatalogue_MatchesTheFlagSets(t *testing.T) {
	t.Parallel()

	// Every mode with a FlagSet must be in the catalogue with flags, and vice
	// versa, so a new flag-parsing mode cannot be added without completion.
	catalogued := map[string]bool{}
	for _, m := range completionModes {
		if m.flags == nil {
			continue
		}
		catalogued[m.name] = true
		if modeFlagSets[m.name] == nil {
			t.Errorf("mode %s completes flags but has no FlagSet in modeFlagSets", m.name)
		}
	}
	for name := range modeFlagSets {
		if !catalogued[name] {
			t.Errorf("mode %s parses flags but the completion catalogue has none for it", name)
		}
	}

	for name, newFlagSet := range modeFlagSets {
		mode := modeFor(name)
		if mode == nil {
			continue // reported above
		}
		real := map[string]*flag.Flag{}
		newFlagSet().VisitAll(func(f *flag.Flag) { real[f.Name] = f })

		for _, c := range mode.flags {
			f, ok := real[c.name]
			if !ok {
				t.Errorf("%s: --%s can be completed but the mode does not define it", name, c.name)
				continue
			}
			// WHY: the flag package lets a boolean stand alone (`--resume`)
			// but makes every other flag consume the next word. Completion
			// has to make the same call, or it offers a value where the next
			// flag belongs, and the other way round.
			isBool := false
			if b, ok := f.Value.(interface{ IsBoolFlag() bool }); ok {
				isBool = b.IsBoolFlag()
			}
			if isBool != (c.value == argBool) {
				t.Errorf("%s: --%s is boolean=%v in the FlagSet but boolean=%v in the catalogue", name, c.name, isBool, c.value == argBool)
			}
		}
		for fname := range real {
			if flagFor(mode.flags, "--"+fname) == nil {
				t.Errorf("%s: the mode defines --%s but it cannot be completed", name, fname)
			}
		}
	}
}

// TestCompletionCatalogue_NetworkChoicesAreTheValidOnes: the values --network
// offers must be exactly the ones the command accepts.
func TestCompletionCatalogue_NetworkChoicesAreTheValidOnes(t *testing.T) {
	t.Parallel()

	for _, c := range networkChoices {
		if err := validNetwork(c.word); err != nil {
			t.Errorf("--network offers %q, which the command rejects: %v", c.word, err)
		}
	}
	offered := map[string]bool{}
	for _, c := range networkChoices {
		offered[c.word] = true
	}
	for _, n := range []string{"udp4", "udp6", "udp"} {
		if !offered[n] {
			t.Errorf("--network accepts %q but completion does not offer it", n)
		}
	}
}

// ---------------------------------------------------------------------------
// the emitted scripts
// ---------------------------------------------------------------------------

// TestCompletionScript_InstallsCompletion: for each supported shell, the
// emitted integration parses in that shell, defines the completion function,
// registers it the way that shell expects, and touches nothing on disk.
func TestCompletionScript_InstallsCompletion(t *testing.T) {
	tests := []struct {
		shell string
		wants []string
		// comments records whether this shell's integration may carry them.
		// zsh's must not: an interactive zsh is not obliged to treat '#' as a
		// comment inside an eval, and where it does not the lines are parsed
		// as code instead, which can leave _bareshare undefined and tab
		// completion silently dead.
		comments bool
	}{
		{"bash", []string{"complete -F _bareshare bareshare", `--complete bash "$COMP_CWORD"`}, true},
		{"zsh", []string{"compdef _bareshare bareshare", `--complete zsh $(( CURRENT - 1 ))`, "compinit"}, false},
	}
	for _, tc := range tests {
		t.Run(tc.shell, func(t *testing.T) {
			keyDir := isolatedHome(t)
			out, err := completion(t, tc.shell)
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range append([]string{"_" + cmdName + " () {"}, tc.wants...) {
				if !strings.Contains(out, want) {
					t.Errorf("%s integration is missing %q", tc.shell, want)
				}
			}
			// WHY: this is sourced by an interactive shell; an `exit`
			// anywhere in it would close the user's terminal.
			if strings.Contains(out, "exit") {
				t.Errorf("%s integration contains an exit", tc.shell)
			}
			if _, err := os.Lstat(keyDir); err == nil {
				t.Errorf("completion %s created the key directory", tc.shell)
			}
			for i, line := range strings.Split(out, "\n") {
				if !tc.comments && strings.HasPrefix(strings.TrimSpace(line), "#") {
					t.Errorf("%s integration line %d is a comment: %q", tc.shell, i+1, line)
				}
				// WHY: this text is about to be parsed by a shell; a stray
				// multibyte character there is a hazard that buys nothing.
				for _, r := range line {
					if r > unicode.MaxASCII {
						t.Errorf("%s integration line %d is not ASCII: %q", tc.shell, i+1, line)
						break
					}
				}
			}
		})
	}
}

// unsupportedShellCases are the `completion` inputs that must produce a
// source-safe complaint rather than an integration. They are checked in Go
// below and parsed by a real bash in completion_unix_test.go.
var unsupportedShellCases = []struct {
	name string
	args []string
	want string
}{
	{"a real shell with no integration yet", []string{"fish"}, "fish not supported"},
	{"no shell given", nil, "no shell specified"},
	{"another real shell with no integration", []string{"csh"}, "csh not supported"},
	{"a name that is not a shell at all", []string{"frobnicate"}, "unknown shell specified"},
	{"an argument trying to inject shell code", []string{`"; rm -rf ~ #`}, "unknown shell specified"},
	{"a supported shell spelled with the wrong case", []string{"ZSH"}, "unknown shell specified"},
	{"a supported shell followed by an extra word", []string{"bash", "extra"}, "completion takes exactly one shell name"},
}

// TestCompletion_UnsupportedShellIsSourceSafe: every input but a supported
// shell writes its complaint as shell code — so `. <(...)` shows it once and
// leaves $? non-zero — and never emits an `exit`, which would close the
// caller's shell. The name is echoed back only when bareshare recognises it as
// a shell, so a hostile argument cannot smuggle itself into the source.
func TestCompletion_UnsupportedShellIsSourceSafe(t *testing.T) {
	for _, tc := range unsupportedShellCases {
		t.Run(tc.name, func(t *testing.T) {
			keyDir := isolatedHome(t)
			out, err := completion(t, tc.args...)
			if err == nil {
				t.Fatal("expected an error")
			}
			if err != errSilent {
				t.Errorf("error is %v, want errSilent so the message is not printed twice", err)
			}
			if want := fmt.Sprintf(">&2 echo %q && false\n", tc.want); out != want {
				t.Errorf("stdout mismatch:\n got: %q\nwant: %q", out, want)
			}
			if strings.Contains(out, "exit") {
				t.Errorf("an unsupported shell emitted an exit: %q", out)
			}
			if strings.Contains(out, "rm ") || strings.Contains(out, "extra") {
				t.Errorf("the argument reached the emitted shell code: %q", out)
			}
			if _, err := os.Lstat(keyDir); err == nil {
				t.Errorf("completion %q created the key directory", tc.args)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// the grammar, in Go
// ---------------------------------------------------------------------------

// TestComplete_AnswersEachPosition exercises the whole argument grammar through
// the --complete protocol both shell adapters read. It is the shell-independent
// half of the coverage: the adapter tests below only have to prove that each
// directive is translated into the right completion call.
func TestComplete_AnswersEachPosition(t *testing.T) {
	t.Parallel()

	type check func(t *testing.T, cands []string)
	exactly := func(want ...string) check {
		return func(t *testing.T, got []string) {
			if strings.Join(got, "\n") != strings.Join(want, "\n") {
				t.Errorf("candidates mismatch:\n got: %q\nwant: %q", got, want)
			}
		}
	}
	holds := func(want ...string) check {
		return func(t *testing.T, got []string) {
			for _, w := range want {
				if !containsString(got, w) {
					t.Errorf("candidates %q are missing %q", got, w)
				}
			}
		}
	}
	lacks := func(unwanted ...string) check {
		return func(t *testing.T, got []string) {
			for _, u := range unwanted {
				if containsString(got, u) {
					t.Errorf("candidates %q must not offer %q", got, u)
				}
			}
		}
	}
	all := func(fns ...check) check {
		return func(t *testing.T, got []string) {
			for _, fn := range fns {
				fn(t, got)
			}
		}
	}
	none := func(t *testing.T, got []string) {
		if len(got) != 0 {
			t.Errorf("expected no candidates, got %q", got)
		}
	}

	allModes := exactly("show-key", "rotate-key", "send", "receive", "version", "completion", "help")
	sendFlags := exactly("--file", "--to", "--peer-key", "--port", "--network")
	receiveFlags := exactly("--peer-key", "--port", "--out", "--mode", "--key-file", "--resume", "--sender-addr", "--network")
	networks := exactly("udp4", "udp6", "udp")

	tests := []struct {
		name  string
		words []string
		cword int
		want  string
		check check
	}{
		{"the mode position offers every mode", []string{"bareshare", ""}, 1, "words", allModes},
		{"candidates are left unfiltered for the shell to match", []string{"bareshare", "re"}, 1, "words", allModes},
		{"a cursor past the end of the typed words is still the mode position", []string{"bareshare"}, 1, "words", allModes},
		{"show-key takes nothing", []string{"bareshare", "show-key", ""}, 2, "none", none},
		{"rotate-key takes nothing", []string{"bareshare", "rotate-key", ""}, 2, "none", none},
		{"version takes nothing", []string{"bareshare", "version", ""}, 2, "none", none},
		{"help takes nothing", []string{"bareshare", "help", ""}, 2, "none", none},
		{"an unknown mode offers nothing", []string{"bareshare", "frobnicate", ""}, 2, "none", none},
		{"completion offers exactly the shells that are implemented", []string{"bareshare", "completion", ""}, 2, "words", exactly(supportedShells...)},
		{"completion takes only the one shell", []string{"bareshare", "completion", "zsh", ""}, 3, "none", none},
		{"send offers its flags", []string{"bareshare", "send", ""}, 2, "words", sendFlags},
		{"receive offers its flags", []string{"bareshare", "receive", ""}, 2, "words", receiveFlags},
		{"a partly typed flag still offers every flag", []string{"bareshare", "send", "--fi"}, 2, "words", sendFlags},
		{"--file takes a file", []string{"bareshare", "send", "--file", ""}, 3, "files", none},
		{"the one-dash spelling is understood", []string{"bareshare", "send", "-file", ""}, 3, "files", none},
		{"--out takes a file", []string{"bareshare", "receive", "--out", ""}, 3, "files", none},
		{"--key-file takes a file", []string{"bareshare", "receive", "--key-file", ""}, 3, "files", none},
		{"--network offers the valid networks", []string{"bareshare", "send", "--network", ""}, 3, "words", networks},
		{"the COMP_WORDBREAKS split of --network=VALUE is understood", []string{"bareshare", "send", "--network", "=", ""}, 4, "words", networks},
		{"the cursor on the bare = of --network= is understood", []string{"bareshare", "send", "--network", "="}, 3, "words", networks},
		{"the joined --network=VALUE zsh leaves intact is understood", []string{"bareshare", "send", "--network=ud"}, 2, "words", networks},
		{"the joined --file=PATH zsh leaves intact is understood", []string{"bareshare", "send", "--file=./x"}, 2, "files", none},
		{"the joined form of an unknown flag offers nothing", []string{"bareshare", "send", "--bogus=x"}, 2, "none", none},
		{"the joined form of a boolean flag offers nothing", []string{"bareshare", "receive", "--resume=t"}, 2, "none", none},
		{"--to is only known to the user", []string{"bareshare", "send", "--to", ""}, 3, "none", none},
		{"--peer-key is only known to the user", []string{"bareshare", "send", "--peer-key", ""}, 3, "none", none},
		{"--port is only known to the user", []string{"bareshare", "receive", "--port", ""}, 3, "none", none},
		{"--mode is only known to the user", []string{"bareshare", "receive", "--mode", ""}, 3, "none", none},
		{"--sender-addr is only known to the user", []string{"bareshare", "receive", "--sender-addr", ""}, 3, "none", none},
		{"a flag already given is not offered again", []string{"bareshare", "send", "--file", "x", ""}, 4, "words",
			all(exactly("--to", "--peer-key", "--port", "--network"), lacks("--file"))},
		{"a flag given in joined form is not offered again", []string{"bareshare", "send", "--file=x", ""}, 3, "words", lacks("--file")},
		{"a flag given with one dash is not offered again", []string{"bareshare", "send", "-file", "x", ""}, 4, "words", lacks("--file")},
		{"a boolean flag consumes no value", []string{"bareshare", "receive", "--resume", ""}, 3, "words",
			all(holds("--peer-key", "--out"), lacks("--resume"))},
		{"the value after a boolean flag is a flag position, not a value", []string{"bareshare", "receive", "--resume", "--out", ""}, 4, "files", none},
		{"a value that looks like a flag is still the value", []string{"bareshare", "send", "--to", "--peer-key", ""}, 4, "words",
			all(holds("--peer-key"), lacks("--to"))},
		{"an unknown flag is skipped and the real flags still offered", []string{"bareshare", "send", "--bogus", ""}, 3, "words", sendFlags},
		{"after -- everything is positional and nothing is offered", []string{"bareshare", "send", "--", ""}, 3, "none", none},
		{"after a non-flag word nothing is offered", []string{"bareshare", "send", "stray", ""}, 3, "none", none},
		{"a lone - is a non-flag word", []string{"bareshare", "send", "-", ""}, 3, "none", none},
		{"every flag used leaves nothing to offer", []string{"bareshare", "send", "--file", "a", "--to", "b", "--peer-key", "c", "--port", "1", "--network", "udp", ""}, 12, "words", none},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			d, c := completeLines(t, "bash", tc.cword, tc.words...)
			if d != tc.want {
				t.Errorf("directive: got %q, want %q", d, tc.want)
			}
			tc.check(t, c)
		})
	}
}

// TestComplete_DescriptionsOnlyForZsh: bash would offer a description as if it
// were a word, so it must only ever see the words themselves.
func TestComplete_DescriptionsOnlyForZsh(t *testing.T) {
	t.Parallel()

	for _, words := range [][]string{
		{"bareshare", ""},
		{"bareshare", "receive", ""},
		{"bareshare", "receive", "--network", ""},
	} {
		cword := len(words) - 1
		_, bash := completeLines(t, "bash", cword, words...)
		_, zsh := completeLines(t, "zsh", cword, words...)
		if len(bash) != len(zsh) || len(bash) == 0 {
			t.Fatalf("%q: shells were offered different candidates: %d vs %d", words, len(bash), len(zsh))
		}
		for _, c := range bash {
			if strings.Contains(c, "\t") {
				t.Errorf("%q: bash candidate carries a description: %q", words, c)
			}
		}
		for i, c := range zsh {
			word, desc, ok := strings.Cut(c, "\t")
			if !ok || desc == "" {
				t.Errorf("%q: zsh candidate has no description: %q", words, c)
			}
			if word != bash[i] {
				t.Errorf("%q: candidate %d differs between shells: %q vs %q", words, i, word, bash[i])
			}
		}
	}
}

// TestComplete_RejectsAMalformedRequest: the protocol is internal, but a
// mangled request must fail rather than guess.
func TestComplete_RejectsAMalformedRequest(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		args []string
	}{
		{"no arguments at all", nil},
		{"missing the -- separator", []string{"bash", "1", "bareshare"}},
		{"a cursor index that is not a number", []string{"bash", "x", "--", "bareshare"}},
		{"a negative cursor index", []string{"bash", "-1", "--", "bareshare"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var out bytes.Buffer
			err := writeComplete(&out, tc.args)
			if err == nil {
				t.Fatal("expected an error")
			}
			if out.Len() != 0 {
				t.Errorf("stdout not empty: %q", out.String())
			}
		})
	}
}
