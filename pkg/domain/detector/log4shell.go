package detector

import (
	"fmt"
	"strings"

	"github.com/m-mizutani/semgate-example/pkg/domain/model"
)

// Log4Shell models a value that gets logged by a vulnerable Log4j-style logger.
// It expands the ${...} lookup grammar, resolving the nested substitution and
// obfuscation attackers use (${lower:j}, ${::-j}, ${upper:x}), and fires only
// when a lookup node's key resolves exactly to "jndi". It NEVER performs the
// JNDI/LDAP lookup. A bare "jndi:" appearing as plain text (not as a ${...}
// lookup key) does not fire.
type Log4Shell struct{}

// NewLog4Shell builds the Log4Shell detector.
func NewLog4Shell() *Log4Shell { return &Log4Shell{} }

// maxExpandPasses bounds the de-obfuscation loop so a crafted input cannot spin
// it forever.
const maxExpandPasses = 128

// Inspect evaluates a logged value for a jndi lookup after de-obfuscation.
func (d *Log4Shell) Inspect(value string) model.Verdict {
	s := value
	for i := 0; i < maxExpandPasses; i++ {
		open := strings.LastIndex(s, "${")
		if open < 0 {
			return model.NotFired()
		}
		rel := strings.Index(s[open:], "}")
		if rel < 0 {
			return model.NotFired() // unbalanced: not a resolvable lookup
		}
		close := open + rel
		inner := s[open+2 : close]

		if lookupKey(inner) == "jndi" {
			return model.Fire(model.CategoryLog4Shell, "log4shell_jndi_lookup",
				fmt.Sprintf("value resolves to a jndi lookup: ${%s}", inner))
		}

		// Resolve this innermost lookup and continue expanding the rest.
		s = s[:open] + resolveLookup(inner) + s[close+1:]
	}
	return model.NotFired()
}

// lookupKey returns the lowercased lookup name of a ${...} body: the part before
// the first ':'. For "jndi:ldap://x" it is "jndi"; for "env:jndi:ldap" it is
// "env" (an env lookup, not a jndi lookup).
func lookupKey(inner string) string {
	key := inner
	if idx := strings.Index(inner, ":"); idx >= 0 {
		key = inner[:idx]
	}
	return strings.ToLower(strings.TrimSpace(key))
}

// resolveLookup de-obfuscates one innermost lookup body. Transform and default
// forms are resolved; any other form is dropped to empty text, since an unknown
// lookup (env, sys, …) does not resolve to its own name.
func resolveLookup(inner string) string {
	lower := strings.ToLower(inner)
	switch {
	case strings.HasPrefix(lower, "lower:"):
		return strings.ToLower(inner[len("lower:"):])
	case strings.HasPrefix(lower, "upper:"):
		return strings.ToUpper(inner[len("upper:"):])
	case strings.Contains(inner, ":-"):
		// ${key:-default} resolves to the default when the key is unset.
		idx := strings.Index(inner, ":-")
		return inner[idx+2:]
	default:
		return ""
	}
}
