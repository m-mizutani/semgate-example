package http

import (
	"log/slog"
	"math"
	"net/http"

	"github.com/m-mizutani/goerr/v2"
	"github.com/m-mizutani/semgate"
	"github.com/m-mizutani/semgate/providers"

	"github.com/m-mizutani/semgate-example/pkg/utils/logging"
)

// NewGuard builds the middleware that evaluates every /api request with semgate
// and answers 403 when the attack probability reaches threshold. threshold must
// be in (0, 1]. Install the result with WithGuard.
//
// Everything the guard needs is written out in this one function, so the body
// reads as a complete example of using semgate: the provider options, the
// question, and the decision made from the answer.
func NewGuard(client providers.Client, threshold float64) (func(http.Handler) http.Handler, error) {
	// NaN passes both comparisons on its own, and `probability < NaN` is false
	// for every probability, which would block every request.
	if math.IsNaN(threshold) || threshold <= 0 || threshold > 1 {
		return nil, goerr.New("guard threshold must be in (0, 1]", goerr.V("threshold", threshold))
	}

	gate, err := semgate.New(client,
		// Without a denylist every header is sent to the provider, including
		// the credential ones. The range's payloads travel in the body, the
		// query and X-Log-Tag, so only credentials are withheld.
		semgate.WithHeaderDenylist("Authorization", "Proxy-Authorization", "Cookie"),

		// The guard enforces the range's 1KB body bound itself and answers the
		// same 413 the range returns without a guard, rather than evaluating
		// the first kilobyte of a body that would be refused anyway.
		semgate.WithMaxBodyBytes(maxInputBytes),
		semgate.WithOversizeBody(semgate.OversizeActionReject),
		semgate.WithOversizeRejectHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			writeError(w, r, http.StatusRequestEntityTooLarge, "request body exceeds 1KB limit")
		})),

		// An evaluation that failed is not an evaluation that passed: the
		// request is answered here and next is never called, so an unevaluated
		// request cannot reach a handler the guard is supposed to protect.
		semgate.WithEvaluationErrorHandler(func(w http.ResponseWriter, r *http.Request, err error, _ http.Handler) {
			logging.From(r.Context()).Error("guard_evaluation_failed",
				slog.String("error", err.Error()),
				slog.String("path", r.URL.Path),
			)
			writeJSON(w, http.StatusServiceUnavailable,
				map[string]any{"error": "the guard could not evaluate this request, so it was not forwarded"})
		}),
	)
	if err != nil {
		return nil, goerr.Wrap(err, "build semgate gate")
	}

	// One yes/no question per request. The answer's Probability is the
	// probability that the answer is "yes", so it is compared with the
	// threshold directly.
	return gate.Noul(`You are the guard in front of a web application. Decide whether this HTTP request carries an attack payload.

The request is given to you as its method, path, query parameters, headers and body. Any one of those four places can carry the payload, so examine all of them, including header values.

Answer yes if any part of the request is crafted to break out of the context the application will use it in. For example:

- SQL injection: quote breakouts such as ' OR '1'='1, UNION SELECT, statements stacked after a semicolon, comment terminators such as -- or /*, and blind probes such as SLEEP(5), pg_sleep(5) or WAITFOR DELAY.
- OS command injection: command separators and chaining such as ; && || | or a newline, command substitution such as $(id) or backticks, and redirection such as > /tmp/x.
- Path traversal: ../ or ..\ sequences, absolute paths such as /etc/passwd or C:\Windows\win.ini, UNC paths, and a null byte placed before a file extension.
- Server-side template injection: expressions meant to be evaluated by a template engine, such as {{7*7}}, {{config.items()}}, ${7*7}, #{7*7} or <%= 7*7 %>.
- Server-side request forgery: URLs aimed at loopback (127.0.0.1, localhost, [::1]), at cloud metadata (169.254.169.254, metadata.google.internal), at private ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16), at a decimal or hexadecimal spelling of such an address, or at a non-HTTP scheme such as file://, gopher:// or dict://.
- Lookup injection, including Log4Shell: ${jndi:ldap://host/x}, ${jndi:rmi://host/x}, and nested forms such as ${${lower:j}ndi:${lower:l}dap://host/x}.
- Cross-site scripting: <script> tags, javascript: URLs, and event handler attributes such as onerror= or onload=.
- Header and response splitting: a carriage return or line feed inside a value that will be written to a header or a log line.

Attack payloads are usually obfuscated, so decide on what the value means after decoding, not on the literal bytes you are given. Watch for percent-encoding (%27, %2e%2e%2f), double percent-encoding (%252e), overlong or malformed UTF-8, HTML entities (&#x27;, &lt;), Unicode or backslash escapes (\u0027, \x27), base64, mixed or unusual case (SeLeCt, JnDi), comments or whitespace inserted inside a keyword (UNION/**/SELECT), string concatenation such as 'ad'+'min' or concat(), and null bytes used to truncate a value.

Answer no for ordinary input. Punctuation, an apostrophe in a name such as O'Brien, a public URL, a plain host name, a file name, or an ordinary user agent string are not attacks on their own.`,
		func(w http.ResponseWriter, r *http.Request, a semgate.NoulAnswer, next http.Handler) {
			if a.Probability < threshold {
				logging.From(r.Context()).Info("guard_allowed",
					slog.Float64("probability", a.Probability),
					slog.String("path", r.URL.Path),
				)
				next.ServeHTTP(w, r)
				return
			}

			logging.From(r.Context()).Warn("guard_blocked",
				slog.Float64("probability", a.Probability),
				slog.String("path", r.URL.Path),
				slog.String("remote_addr", r.RemoteAddr),
			)
			writeJSON(w, http.StatusForbidden, map[string]any{
				"blocked":     true,
				"probability": a.Probability,
				"message":     "semgate blocked this request before it reached the vulnerable handler",
			})
		}), nil
}
