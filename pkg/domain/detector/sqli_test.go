package detector_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/m-mizutani/gt"
	"github.com/m-mizutani/semgate-example/pkg/domain/detector"
	"github.com/m-mizutani/semgate-example/pkg/domain/model"
)

func TestSQLi_Inspect(t *testing.T) {
	d, err := detector.NewSQLi()
	gt.NoError(t, err)
	t.Cleanup(func() { _ = d.Close() })
	ctx := context.Background()

	testCases := map[string]struct {
		username  string
		password  string
		wantFired bool
		wantRule  string
	}{
		"benign wrong login": {username: "alice", password: "wrong", wantFired: false},
		"benign valid login": {username: "alice", password: "alice-pw-EXAMPLE", wantFired: false},
		"tautology bypass":   {username: "admin' OR '1'='1", password: "x", wantFired: true, wantRule: "sqli_result_altered"},
		"comment truncation": {username: "admin'--", password: "irrelevant", wantFired: true, wantRule: "sqli_result_altered"},
		"union select":       {username: "zzz' UNION SELECT 1, 'x'--", password: "x", wantFired: true, wantRule: "sqli_result_altered"},
		"broken syntax":      {username: "O'Brien", password: "x", wantFired: true, wantRule: "sqli_broken_syntax"},
		"stacked statement":  {username: "x'; DROP TABLE users;--", password: "x", wantFired: true, wantRule: "sqli_stacked_statements"},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			v := d.Inspect(ctx, tc.username, tc.password)
			wantFired(t, v.Fired, tc.wantFired)
			if tc.wantFired {
				gt.Value(t, v.Category).Equal(model.CategorySQLi)
				gt.String(t, v.RuleID).Equal(tc.wantRule)
				gt.String(t, v.Detail).IsNotEmpty()
			}
		})
	}
}

// TestSQLi_HardeningNoSideEffects confirms that attacker SQL routed through the
// real Inspect path fires without any side effect: stacked ATTACH/write/PRAGMA
// statements are never executed, so no file is created and the fake table is
// unchanged.
func TestSQLi_HardeningNoSideEffects(t *testing.T) {
	dir := t.TempDir()
	probe := filepath.Join(dir, "attach_probe.db")
	ctx := context.Background()

	d, err := detector.NewSQLi()
	gt.NoError(t, err)
	t.Cleanup(func() { _ = d.Close() })

	attacks := []string{
		"x'; ATTACH DATABASE '" + probe + "' AS p;--",
		"x'; PRAGMA query_only=OFF;--",
		"x'; UPDATE users SET username='pwned';--",
		"x'; DROP TABLE users;--",
	}
	for _, payload := range attacks {
		v := d.Inspect(ctx, payload, "x")
		gt.Bool(t, v.Fired).True() // stacked injection is detected...
		gt.Value(t, v.Category).Equal(model.CategorySQLi)
	}

	// ...but nothing was executed: no attached file, and the table is intact.
	_, statErr := os.Stat(probe)
	gt.Bool(t, os.IsNotExist(statErr)).True()

	// The seeded rows are still there and unchanged (a valid credential matches).
	valid := d.Inspect(ctx, "admin", "admin-pw-EXAMPLE")
	gt.Bool(t, valid.Fired).False()
}
