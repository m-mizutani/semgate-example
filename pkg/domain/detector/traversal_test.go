package detector_test

import (
	"testing"

	"github.com/m-mizutani/gt"
	"github.com/m-mizutani/semgate-example/pkg/domain/detector"
	"github.com/m-mizutani/semgate-example/pkg/domain/model"
)

func TestTraversal_Inspect(t *testing.T) {
	d := detector.NewTraversal()

	testCases := map[string]struct {
		path      string
		wantFired bool
	}{
		"benign filename":      {path: "report.txt", wantFired: false},
		"benign nested":        {path: "docs/2026/report.txt", wantFired: false},
		"dotdot escape":        {path: "../../../etc/passwd", wantFired: true},
		"url encoded":          {path: "%2e%2e%2f%2e%2e%2fetc%2fpasswd", wantFired: true},
		"double encoded":       {path: "%252e%252e%252fetc%252fpasswd", wantFired: true},
		"absolute sensitive":   {path: "/etc/passwd", wantFired: true},
		"windows absolute":     {path: "c:\\windows\\win.ini", wantFired: true},
		"null byte truncation": {path: "report.txt%00.png", wantFired: true},
		"backslash traversal":  {path: "..\\..\\etc\\passwd", wantFired: true},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			v := d.Inspect(tc.path)
			wantFired(t, v.Fired, tc.wantFired)
			if tc.wantFired {
				gt.Value(t, v.Category).Equal(model.CategoryPathTraversal)
				gt.String(t, v.Detail).IsNotEmpty()
			}
		})
	}
}
