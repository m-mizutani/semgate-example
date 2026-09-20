package http

import (
	"log/slog"
	"math"
	"net/http"

	"github.com/m-mizutani/goerr/v2"
	"github.com/m-mizutani/semgate"
	"github.com/m-mizutani/semgate-example/pkg/domain/model"
	"github.com/m-mizutani/semgate-example/pkg/utils/logging"
	"github.com/m-mizutani/semgate/providers"
)

// CategoryBenign is the Choice option returned when the request carries no
// attack payload. A Choice question always selects one option, so the benign
// case needs an option of its own.
const CategoryBenign = "benign"

// attackOptions describes, for the model, each injection family the range
// simulates. The option names are the same strings the range reports in the
// envelope's category field, so a blocked request and a fired request name the
// same family.
var attackOptions = map[string]string{
	string(model.CategorySQLi):             "SQL injection: the input manipulates an SQL query, for example by closing a quote, adding a tautology, a UNION SELECT, or a stacked statement.",
	string(model.CategoryCommandInjection): "OS command injection: the input appends or chains a shell command, for example with ';', '&&', '|', backticks, or $(...).",
	string(model.CategoryPathTraversal):    "Path traversal: the input escapes the intended directory, for example with '../', an absolute path, or encoded separators.",
	string(model.CategorySSTI):             "Server-side template injection: the input carries a template expression meant to be evaluated, for example {{7*7}} or <%= ... %>.",
	string(model.CategorySSRF):             "Server-side request forgery: the input points the server at a loopback, link-local, private, or non-HTTP target.",
	string(model.CategoryLog4Shell):        "Log4Shell: the input carries a Log4j lookup that resolves to JNDI, for example ${jndi:ldap://host/x}, including obfuscated spellings.",
	CategoryBenign:                         "None of the above: ordinary input that carries no attack payload.",
}

const attackInstructions = "Does this HTTP request carry a web application attack payload in its body, query string, or headers? " +
	"Consider SQL injection, OS command injection, path traversal, server-side template injection, " +
	"server-side request forgery, and Log4Shell (JNDI lookup) payloads."

const categoryInstructions = "Which kind of attack payload does this HTTP request carry?"

// blockResponse is the body of a blocked request. It is a different shape from
// envelope on purpose: the SPA tells a blocked request from an exploited one by
// this field set, not by the status code alone.
type blockResponse struct {
	Blocked     bool    `json:"blocked"`
	Category    string  `json:"category"`
	Probability float64 `json:"probability"`
	Confidence  float64 `json:"confidence"`
	Message     string  `json:"message"`
}

// NewGuard builds the middleware that evaluates every /api request with
// semgate and answers 403 when the attack probability reaches threshold.
// threshold must be in (0, 1]. Install the result with WithGuard.
func NewGuard(client providers.Client, threshold float64) (func(http.Handler) http.Handler, error) {
	// NaN passes both comparisons below on its own, and `probability < NaN` is
	// false for every probability, which would block every request.
	if math.IsNaN(threshold) || threshold <= 0 || threshold > 1 {
		return nil, goerr.New("guard threshold must be in (0, 1]", goerr.V("threshold", threshold))
	}

	gate, err := semgate.New(client,
		// The range's payloads travel in the body, the query, and X-Log-Tag, so
		// only the credential headers are withheld.
		semgate.WithHeaderDenylist("Authorization", "Proxy-Authorization", "Cookie"),
		// The guard enforces the range's 1KB body bound itself, rather than
		// evaluating the first kilobyte of a body that would be refused anyway.
		semgate.WithMaxBodyBytes(maxInputBytes),
		semgate.WithOversizeBody(semgate.OversizeActionReject),
		semgate.WithOversizeRejectHandler(http.HandlerFunc(rejectOversizeBody)),
		semgate.WithEvaluationErrorHandler(evaluationFailed),
	)
	if err != nil {
		return nil, goerr.Wrap(err, "build semgate gate")
	}

	attack := semgate.Noul(attackInstructions)
	category := semgate.Choice(categoryInstructions, attackOptions)

	return gate.Ask([]semgate.Question{attack, category},
		func(w http.ResponseWriter, r *http.Request, ans *semgate.Answers, next http.Handler) {
			probability := attack.Answer(ans).Probability
			verdict := category.Answer(ans)

			if probability < threshold {
				logging.From(r.Context()).Info("guard_allowed",
					slog.Float64("probability", probability),
					slog.String("category", verdict.Choice),
					slog.Float64("confidence", verdict.Confidence),
				)
				next.ServeHTTP(w, r)
				return
			}

			logging.From(r.Context()).Warn("guard_blocked",
				slog.String("path", r.URL.Path),
				slog.Float64("probability", probability),
				slog.String("category", verdict.Choice),
				slog.Float64("confidence", verdict.Confidence),
				slog.String("remote_addr", r.RemoteAddr),
			)
			writeJSON(w, http.StatusForbidden, blockResponse{
				Blocked:     true,
				Category:    verdict.Choice,
				Probability: probability,
				Confidence:  verdict.Confidence,
				Message:     "semgate blocked this request before it reached the vulnerable handler",
			})
		}), nil
}

// rejectOversizeBody answers a body above maxInputBytes with the same 413 the
// range returns without a guard, so the bound reads the same either way.
func rejectOversizeBody(w http.ResponseWriter, r *http.Request) {
	writeError(w, r, http.StatusRequestEntityTooLarge, "request body exceeds 1KB limit")
}

// evaluationFailed answers a request whose evaluation did not produce a usable
// answer. It does not call next: an unevaluated request must not reach a
// handler that a guard is supposed to protect.
func evaluationFailed(w http.ResponseWriter, r *http.Request, err error, _ http.Handler) {
	logging.From(r.Context()).Error("guard_evaluation_failed",
		slog.String("error", err.Error()),
		slog.String("path", r.URL.Path),
	)
	writeJSON(w, http.StatusServiceUnavailable,
		map[string]any{"error": "the guard could not evaluate this request, so it was not forwarded"})
}
