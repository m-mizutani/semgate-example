package detector

import (
	"fmt"
	"strings"

	"github.com/m-mizutani/semgate-example/pkg/domain/model"
	"mvdan.cc/sh/v3/syntax"
)

// Command models a diagnostics endpoint that builds a shell command line by
// concatenating user input into "ping -c 3 <host>". It parses the resulting
// command line with a real POSIX shell parser and fires when the input turns
// the single intended ping into anything more: an extra command, a pipeline, a
// command substitution, or a redirection. It NEVER executes the command.
type Command struct {
	template string // command template with a single %s for the host
}

// NewCommand builds the command-injection detector.
func NewCommand() *Command {
	return &Command{template: "ping -c 3 %s"}
}

// Inspect evaluates the host value spliced into the command template.
func (d *Command) Inspect(host string) model.Verdict {
	cmdline := fmt.Sprintf(d.template, host)

	parser := syntax.NewParser()
	file, err := parser.Parse(strings.NewReader(cmdline), "")
	if err != nil {
		// A parse failure (e.g. an unmatched quote) is malformed input, not an
		// injected command: a shell would not execute an extra command from it.
		// Command injection fires only when a real extra command appears, so
		// treat this as benign.
		return model.NotFired()
	}

	var (
		callExprs int
		extras    []string
	)
	syntax.Walk(file, func(node syntax.Node) bool {
		switch n := node.(type) {
		case *syntax.CallExpr:
			// A CallExpr with args is one simple command invocation.
			if len(n.Args) > 0 {
				callExprs++
			}
		case *syntax.BinaryCmd:
			// "&&", "||", "|", "|&" between commands.
			extras = append(extras, n.Op.String())
		case *syntax.CmdSubst:
			extras = append(extras, "$(...)")
		case *syntax.Stmt:
			// A statement terminated by "&" (background) or ";" chains commands.
			if n.Background {
				extras = append(extras, "&")
			}
		case *syntax.Redirect:
			extras = append(extras, "redirect")
		}
		return true
	})

	// The intended command line is exactly one call: "ping -c 3 <host>". Anything
	// beyond that — a second call, an operator, a substitution — is injection.
	if callExprs > 1 || len(extras) > 0 {
		detail := fmt.Sprintf("parsed into %d commands", callExprs)
		if len(extras) > 0 {
			detail += " with " + strings.Join(dedupe(extras), ", ")
		}
		return model.Fire(model.CategoryCommandInjection, "cmd_extra_command", detail)
	}

	return model.NotFired()
}

func dedupe(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}
