package detector_test

import (
	"testing"

	"github.com/m-mizutani/gt"
	"github.com/m-mizutani/semgate-example/pkg/domain/detector"
	"github.com/m-mizutani/semgate-example/pkg/domain/model"
)

func TestSSRF_Inspect(t *testing.T) {
	d := detector.NewSSRF()

	testCases := map[string]struct {
		url       string
		wantFired bool
		wantRule  string
	}{
		"public https":   {url: "https://example.com/page", wantFired: false},
		"public http":    {url: "http://www.example.org", wantFired: false},
		"metadata":       {url: "http://169.254.169.254/latest/meta-data/", wantFired: true, wantRule: "ssrf_metadata"},
		"loopback ipv4":  {url: "http://127.0.0.1:8080/admin", wantFired: true, wantRule: "ssrf_loopback"},
		"localhost name": {url: "http://localhost/internal", wantFired: true, wantRule: "ssrf_localhost"},
		"private range":  {url: "http://10.0.0.5/", wantFired: true, wantRule: "ssrf_private"},
		"private 192":    {url: "http://192.168.1.1/", wantFired: true, wantRule: "ssrf_private"},
		"file scheme":    {url: "file:///etc/passwd", wantFired: true, wantRule: "ssrf_forbidden_scheme"},
		"gopher scheme":  {url: "gopher://127.0.0.1:6379/_INFO", wantFired: true, wantRule: "ssrf_forbidden_scheme"},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			v := d.Inspect(tc.url)
			wantFired(t, v.Fired, tc.wantFired)
			if tc.wantFired {
				gt.Value(t, v.Category).Equal(model.CategorySSRF)
				gt.String(t, v.RuleID).Equal(tc.wantRule)
			}
		})
	}
}
