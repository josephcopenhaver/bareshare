// Shell completion.
//
// All of the "what can go here?" logic lives in this file, in Go, behind the
// hidden `bareshare --complete <shell> <cword> -- <word>...` protocol. The bash
// and zsh scripts printed by `bareshare completion <shell>` are thin adapters:
// they hand bareshare the words the user has typed and translate the answer
// into their own completion system. That is deliberate — a second copy of the
// argument grammar written in shell would drift from this one, and could only
// be tested through a shell.

package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// completeKind is the answer to "what does the word under the cursor accept?".
// It is the first line of --complete's output; the adapters switch on it.
type completeKind uint8

const _completeKindEncodedValues = "nonewordsfiles"

const (
	completeNone completeKind = iota // "none" - nothing can be offered

	completeWords // "words" - the candidate lines that follow
	completeFiles // "files" - whatever the shell calls a file
)

func (k completeKind) String() string {

	switch k {
	case completeNone:
		return _completeKindEncodedValues[:4]
	case completeWords:
		return _completeKindEncodedValues[4:9]
	case completeFiles:
		return _completeKindEncodedValues[9:]
	}

	panic("completeKind.String: unknown kind")
}

// argKind is what one positional argument, or the value of one flag, accepts.
type argKind uint8

const (
	argNothing argKind = iota // only the user knows it: an address, a fingerprint, a port

	argBool   // a boolean flag; it takes no value word at all
	argFile   // a path
	argChoice // one of the flag's fixed choices
	argShell  // a shell name for the completion command
)

// candidate is one offered word and, for shells that show them, its description.
type candidate struct{ word, desc string }

// flagSpec is one flag of a mode: its name without dashes, the one-line
// description zsh shows beside it, and what its value accepts.
//
// Descriptions must not contain ':' — zsh's _describe uses it to separate a
// completion from its description. TestCompletionCatalogue_MatchesTheHelpMenu
// enforces that, and that this catalogue and the help menu list the same flags.
type flagSpec struct {
	name    string
	desc    string
	value   argKind
	choices []candidate // what argChoice offers
}

// networkChoices are the values --network accepts, as validNetwork checks them.
var networkChoices = []candidate{
	{"udp4", "IPv4 only (default)"},
	{"udp6", "IPv6 only"},
	{"udp", "dual-stack, IPv4 and IPv6"},
}

// completionModes is the catalogue --complete answers from: every mode with its
// description, what its positional arguments accept, and its flags in the
// order the help menu lists them.
var completionModes = []struct {
	name  string
	desc  string     // no ':' (see flagSpec)
	args  []argKind  // what positional arguments 1, 2, ... accept
	flags []flagSpec // the flags the mode parses; nil for a mode without any
}{
	{"show-key", "display your public key fingerprint", nil, nil},
	{"rotate-key", "generate a new key pair, replacing the existing one", nil, nil},
	{"send", "send a file to a verified peer over QUIC", nil, []flagSpec{
		{"file", "path of the file to send", argFile, nil},
		{"to", "receiver address as host and port", argNothing, nil},
		{"peer-key", "expected receiver fingerprint", argNothing, nil},
		{"port", "local UDP port, fixed for bilateral punching", argNothing, nil},
		{"network", "bind network, udp4 udp6 or udp", argChoice, networkChoices},
	}},
	{"receive", "listen for an incoming file from a verified peer", nil, []flagSpec{
		{"peer-key", "expected sender fingerprint", argNothing, nil},
		{"port", "UDP port to listen on", argNothing, nil},
		{"out", "output file path, - for stdout", argFile, nil},
		{"mode", "file permission mode in octal", argNothing, nil},
		{"key-file", "key file path, or . for the user key", argFile, nil},
		{"resume", "resume an interrupted download", argBool, nil},
		{"sender-addr", "sender public address for bilateral hole punching", argNothing, nil},
		{"network", "bind network, udp4 udp6 or udp", argChoice, networkChoices},
	}},
	{"version", "print the version", nil, nil},
	{"completion", "print the tab completion script for bash or zsh", []argKind{argShell}, nil},
	{"help", "print the help menu", nil, nil},
}

// supportedShells are the shells `completion` can actually emit an integration
// for. Order is the order they are offered in.
var supportedShells = []string{"bash", "zsh"}

// knownShells are shell names recognised well enough to be named back to the
// user in the "not supported" message.
//
// WHY: that message is printed as shell code the caller will source, so the
// only caller-derived text it may ever contain is one of these fixed literals.
// Echoing the argument itself would let `bareshare completion '"; rm -rf ~ #'`
// smuggle commands straight into the user's shell.
var knownShells = map[string]struct{}{
	"ash": {}, "bash": {}, "csh": {}, "dash": {}, "elvish": {}, "fish": {},
	"ksh": {}, "ksh93": {}, "mksh": {}, "nu": {}, "nushell": {}, "oil": {},
	"osh": {}, "powershell": {}, "pwsh": {}, "sh": {}, "tcsh": {}, "xonsh": {},
	"yash": {}, "zsh": {},
}

// errSilent marks a failure that has already been reported to the caller and
// needs nothing from main but the non-zero exit status.
var errSilent = errors.New("reported")

// writeCompletion writes the shell integration for the shell named by args to
// w. args is everything after the `completion` word.
//
// An unsupported or missing shell, or an extra argument, still writes shell
// code, because the caller's `eval "$(bareshare completion X)"` swallows stdout:
// emitting the complaint as code is the only way it reaches the terminal
// exactly once and leaves $? non-zero in the calling shell.
// WHY: everything printed for sourcing stays 7-bit ASCII. A stray multibyte
// character in text a shell is about to parse is a hazard that buys nothing.
func writeCompletion(w io.Writer, args []string) error {
	if len(args) == 1 {
		switch args[0] {
		case "bash":
			_, err := io.WriteString(w, bashIntegration)
			return err
		case "zsh":
			// WHY: stripped rather than written without them, so that a
			// comment added to the script later cannot leak into the zsh
			// output, where a sourced-via-eval '#' is not reliably a comment.
			_, err := io.WriteString(w, stripComments(zshIntegration))
			return err
		}
	}
	msg := "no shell specified"
	switch {
	case len(args) > 1:
		msg = "completion takes exactly one shell name"
	case len(args) == 1:
		msg = "unknown shell specified"
		if _, ok := knownShells[args[0]]; ok {
			msg = args[0] + " not supported"
		}
	}
	// WHY: `&& false`, never `&& exit 1`. This line is sourced by the user's
	// interactive shell, where `exit` would close their terminal (or abort the
	// rest of a .bashrc). `false` leaves $? non-zero without either.
	if _, err := fmt.Fprintf(w, ">&2 echo %q && false\n", msg); err != nil {
		return err
	}
	// WHY: errSilent, not errors.New(msg) — the sourced echo above already
	// prints it, and bareshare's own stderr line would show it to the user
	// twice.
	return errSilent
}

// writeComplete answers one completion request. args is
// `<shell> <cword> -- <word>...`: the words the user has typed and the index of
// the one under the cursor. Output is the completeKind on the first line
// followed by the candidates, one per line, as `word` or `word\tdescription`.
//
// Candidates are NOT filtered against the word under the cursor: both shells
// match the prefix themselves, and zsh's matching is the user's to configure.
func writeComplete(w io.Writer, args []string) error {
	if len(args) < 3 || args[2] != "--" {
		return fmt.Errorf("usage: %s --complete <shell> <cword> -- <word>...", cmdName)
	}
	shell, words := args[0], args[3:]
	cword, err := strconv.Atoi(args[1])
	if err != nil || cword < 0 {
		return fmt.Errorf("invalid cursor word index %q", args[1])
	}
	// WHY: a shell that drops an empty trailing word still means "the cursor is
	// on a word that is not there yet".
	for len(words) <= cword {
		words = append(words, "")
	}

	kind, cands := completeAt(words, cword)
	var out bytes.Buffer
	out.WriteString(kind.String())
	out.WriteByte('\n')
	for _, c := range cands {
		out.WriteString(c.word)
		// Only zsh renders descriptions; bash would offer them as words.
		if c.desc != "" && shell == "zsh" {
			out.WriteByte('\t')
			out.WriteString(c.desc)
		}
		out.WriteByte('\n')
	}
	_, err = w.Write(out.Bytes())
	return err
}

// completeAt decides what the word at index cword of words accepts. words is
// the whole command line as the shell split it, words[0] being the tool itself.
func completeAt(words []string, cword int) (completeKind, []candidate) {
	// WHY: bash splits words on COMP_WORDBREAKS, so `--network=udp4` arrives as
	// the three words `--network`, `=`, `udp4`. Dropping the bare `=` restores
	// the plain `--network udp4` shape this parser expects; zsh, which does not
	// split, is unaffected.
	typed := make([]string, 0, cword)
	for _, w := range words[:cword] {
		if w != "=" {
			typed = append(typed, w)
		}
	}

	// The first word after the tool is the mode.
	if len(typed) <= 1 {
		return completeWords, modeCandidates()
	}
	mode := modeFor(typed[1])
	if mode == nil {
		return completeNone, nil
	}
	if mode.flags != nil {
		return completeFlag(mode.flags, typed[2:], words[cword])
	}

	pos := len(typed) - 2 // 0 is the first argument after the mode
	if pos >= len(mode.args) {
		return completeNone, nil
	}
	switch mode.args[pos] {
	case argFile:
		return completeFiles, nil
	case argShell:
		cands := make([]candidate, 0, len(supportedShells))
		for _, s := range supportedShells {
			cands = append(cands, candidate{s, ""})
		}
		return completeWords, cands
	}
	return completeNone, nil
}

// completeFlag decides what the cursor word accepts inside a mode that parses
// flags the way the standard flag package does: `-name value`, `--name value`,
// `-name=value`, `--name=value`, a boolean flag never consuming a value, and
// parsing stopping at `--` or at the first word that is not a flag.
//
// typed is the words after the mode, before the cursor; cur is the word under
// the cursor (which bash has split at `=` but zsh keeps whole).
func completeFlag(flags []flagSpec, typed []string, cur string) (completeKind, []candidate) {
	// A `--name=` joined with its value under the cursor, as zsh presents it:
	// the value is what is being completed.
	if name, _, joined := strings.Cut(cur, "="); joined && strings.HasPrefix(name, "-") {
		if f := flagFor(flags, name); f != nil && f.value != argBool {
			return completeValue(f)
		}
		return completeNone, nil
	}

	used := map[string]bool{}
	var pending *flagSpec // the flag whose value the next word is
	for _, w := range typed {
		if pending != nil {
			pending = nil
			continue
		}
		// The flag package stops at `--` and at the first non-flag word; from
		// there on every word is positional, and bareshare takes none.
		if w == "--" || w == "-" || !strings.HasPrefix(w, "-") {
			return completeNone, nil
		}
		name, _, joined := strings.Cut(w, "=")
		f := flagFor(flags, name)
		if f == nil {
			// WHY: an unknown flag makes the invocation fail, but offering the
			// real flags is still the most useful thing a tab press can do.
			continue
		}
		used[f.name] = true
		if !joined && f.value != argBool {
			pending = f
		}
	}
	if pending != nil {
		return completeValue(pending)
	}

	var cands []candidate
	for i := range flags {
		if !used[flags[i].name] {
			cands = append(cands, candidate{"--" + flags[i].name, flags[i].desc})
		}
	}
	return completeWords, cands
}

// completeValue is what the value of flag f accepts.
func completeValue(f *flagSpec) (completeKind, []candidate) {
	switch f.value {
	case argFile:
		return completeFiles, nil
	case argChoice:
		return completeWords, f.choices
	}
	// argNothing, or the explicit value of a boolean: only the user knows it.
	return completeNone, nil
}

// modeSpec is one row of completionModes, as modeFor returns it.
type modeSpec struct {
	name  string
	desc  string
	args  []argKind
	flags []flagSpec
}

func modeFor(name string) *modeSpec {
	for _, m := range completionModes {
		if m.name == name {
			return &modeSpec{m.name, m.desc, m.args, m.flags}
		}
	}
	return nil
}

// flagFor finds the flag that word names, accepting the one- and two-dash
// spellings the flag package does. A word with three or more dashes, or no
// name after them, is not a flag.
func flagFor(flags []flagSpec, word string) *flagSpec {
	name := strings.TrimPrefix(word, "-")
	name = strings.TrimPrefix(name, "-")
	if name == "" || strings.HasPrefix(name, "-") {
		return nil
	}
	for i := range flags {
		if flags[i].name == name {
			return &flags[i]
		}
	}
	return nil
}

// modeCandidates is every mode, in catalogue order.
func modeCandidates() []candidate {
	out := make([]candidate, 0, len(completionModes))
	for _, m := range completionModes {
		out = append(out, candidate{m.name, m.desc})
	}
	return out
}

// stripComments removes whole-line shell comments and collapses the runs of
// blank lines they leave behind. A '#' that is part of the shell code is never
// touched, because only a line whose first non-blank character is '#' is a
// comment.
func stripComments(src string) string {
	var out strings.Builder
	blank := true // WHY: seeded true so leading blank lines go too
	for _, line := range strings.Split(src, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		if trimmed == "" {
			if blank {
				continue
			}
			blank = true
		} else {
			blank = false
		}
		out.WriteString(line)
		out.WriteByte('\n')
	}
	return strings.TrimRight(out.String(), "\n") + "\n"
}

// bashIntegration asks bareshare what fits at the cursor and feeds the answer
// to readline. Written for bash 3.2, the newest bash Apple ships, and assuming
// nothing from the bash-completion package beyond using it where it is loaded.
const bashIntegration = `# ` + cmdName + ` tab completion. Install with:
#
#     eval "$(` + cmdName + ` completion bash)"    # in ~/.bashrc
#
# eval rather than ". <(...)": bash 3.2, which macOS ships, reads nothing when
# it sources a pipe, so the process-substitution form silently installs
# nothing there.

_` + cmdName + `_filedir () {
    if declare -F _filedir >/dev/null 2>&1; then
        _filedir
        return
    fi
    COMPREPLY=( $(compgen -f -- "$cur") )
    # compopt is bash 4+; on bash 3.2 the error is discarded and the
    # completions are merely shown with their full path.
    compopt -o filenames 2>/dev/null || true
}

_` + cmdName + ` () {
    local cur reply directive cands
    COMPREPLY=()
    cur=${COMP_WORDS[COMP_CWORD]}
    # bash splits words on COMP_WORDBREAKS, so the cursor can land on the bare
    # "=" of "--network=udp4"; that is a prefix of nothing, not a word to match.
    if [ "$cur" = "=" ]; then
        cur=""
    fi

    # stderr is dropped so a failure can never scribble over the prompt.
    reply=$(command ` + cmdName + ` --complete bash "$COMP_CWORD" -- "${COMP_WORDS[@]}" 2>/dev/null) || return
    directive=${reply%%$'\n'*}
    cands=${reply#*$'\n'}
    if [ "$cands" = "$reply" ]; then
        cands=""
    fi

    case $directive in
        words) COMPREPLY=( $(compgen -W "$cands" -- "$cur") );;
        files) _` + cmdName + `_filedir;;
    esac
}

complete -F _` + cmdName + ` ` + cmdName + `
`

// zshIntegration is the same question asked from zsh, answered through the zsh
// completion system so candidates keep their descriptions and the user's own
// matcher and menu settings apply.
const zshIntegration = `# ` + cmdName + ` tab completion. Install with:
#
#     . <(` + cmdName + ` completion zsh)     # in ~/.zshrc, after compinit

_` + cmdName + ` () {
    local cur directive
    local -a reply cands

    cur=${words[CURRENT]}
    # stderr is dropped so a failure can never scribble over the prompt.
    # CURRENT is 1-based, cword is not.
    reply=( ${(f)"$(command ` + cmdName + ` --complete zsh $(( CURRENT - 1 )) -- "${words[@]}" 2>/dev/null)"} )
    (( $#reply )) || return 1
    directive=$reply[1]
    cands=( ${reply[2,-1]//$'\t'/:} )

    # zsh keeps "--network=udp4" as one word; set the "--network=" part aside
    # so only the value is matched and completed.
    if [[ $cur == -*=* ]]; then
        compset -P "${cur%%=*}="
    fi

    case $directive in
        words) _describe -t ` + cmdName + ` ` + cmdName + ` cands ;;
        files) _files ;;
        # WHY: a plain "return 1" here would leave zsh to report a bare "no
        # matches"; saying so out loud distinguishes "` + cmdName + ` has nothing to
        # offer at this position" from "your prefix matched nothing".
        none)  _message -e ` + cmdName + ` "no completion here" ; return 1 ;;
        *)     return 1 ;;
    esac
}

if (( $+functions[compdef] )); then
    compdef _` + cmdName + ` ` + cmdName + `
else
    >&2 echo "` + cmdName + `: completion needs compinit; source this after compinit in ~/.zshrc"
fi
`
