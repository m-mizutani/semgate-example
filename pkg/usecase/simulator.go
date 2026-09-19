// Package usecase orchestrates each simulated endpoint: it hands the input to
// the matching detector and, based on the verdict, builds either a synthetic
// "leaked" payload (fired) or a benign response.
package usecase

import (
	"context"

	"github.com/m-mizutani/goerr/v2"
	"github.com/m-mizutani/semgate-example/pkg/domain/detector"
	"github.com/m-mizutani/semgate-example/pkg/domain/model"
)

// Simulator holds one detector per attack family and turns a verdict into an
// endpoint response.
type Simulator struct {
	sqli      *detector.SQLi
	command   *detector.Command
	traversal *detector.Traversal
	ssti      *detector.SSTI
	ssrf      *detector.SSRF
	log4shell *detector.Log4Shell
}

// NewSimulator constructs the simulator and its detectors. It returns an error
// if the SQLi detector's in-memory database cannot be initialised.
func NewSimulator() (*Simulator, error) {
	sqli, err := detector.NewSQLi()
	if err != nil {
		return nil, goerr.Wrap(err, "init sqli detector")
	}
	return &Simulator{
		sqli:      sqli,
		command:   detector.NewCommand(),
		traversal: detector.NewTraversal(),
		ssti:      detector.NewSSTI(),
		ssrf:      detector.NewSSRF(),
		log4shell: detector.NewLog4Shell(),
	}, nil
}

// Close releases resources held by the simulator (the SQLi in-memory database).
func (s *Simulator) Close() error {
	return s.sqli.Close()
}

// LeakedUser is one row of the synthetic users table returned on a fired login.
type LeakedUser struct {
	ID           int
	Username     string
	PasswordHash string
	Email        string
}

// LoginResult is the outcome of the SQLi login endpoint.
type LoginResult struct {
	Verdict       model.Verdict
	Authenticated bool
	Users         []LeakedUser
}

// PingResult is the outcome of the command-injection ping endpoint.
type PingResult struct {
	Verdict model.Verdict
	Output  string
}

// FileResult is the outcome of the path-traversal files endpoint.
type FileResult struct {
	Verdict model.Verdict
	Path    string
	Found   bool
	Content string
}

// GreetResult is the outcome of the SSTI greet endpoint.
type GreetResult struct {
	Verdict  model.Verdict
	Rendered string
}

// FetchResult is the outcome of the SSRF fetch endpoint.
type FetchResult struct {
	Verdict model.Verdict
	Target  string
	Body    string
}

// TrackResult is the outcome of the Log4Shell track endpoint.
type TrackResult struct {
	Verdict model.Verdict
	Logged  string
}

// Login evaluates a login attempt for SQL injection.
func (s *Simulator) Login(ctx context.Context, username, password string) LoginResult {
	v := s.sqli.Inspect(ctx, username, password)
	if v.Fired {
		return LoginResult{Verdict: v, Authenticated: true, Users: leakedUsers()}
	}
	return LoginResult{Verdict: v, Authenticated: false}
}

// Ping evaluates a diagnostics request for OS command injection.
func (s *Simulator) Ping(_ context.Context, host string) PingResult {
	v := s.command.Inspect(host)
	if v.Fired {
		return PingResult{Verdict: v, Output: commandOutput(host)}
	}
	return PingResult{Verdict: v, Output: benignPing(host)}
}

// ReadFile evaluates a document request for path traversal.
func (s *Simulator) ReadFile(_ context.Context, reqPath string) FileResult {
	v := s.traversal.Inspect(reqPath)
	if v.Fired {
		return FileResult{Verdict: v, Path: reqPath, Found: true, Content: leakedFile(reqPath)}
	}
	content, found := benignFile(reqPath)
	return FileResult{Verdict: v, Path: reqPath, Found: found, Content: content}
}

// Greet evaluates a greeting request for template injection.
func (s *Simulator) Greet(_ context.Context, name string) GreetResult {
	v := s.ssti.Inspect(name)
	if v.Fired {
		return GreetResult{Verdict: v, Rendered: renderedSSTI(v)}
	}
	return GreetResult{Verdict: v, Rendered: "Hello, " + name + "!"}
}

// Fetch evaluates a URL-preview request for SSRF.
func (s *Simulator) Fetch(_ context.Context, rawURL string) FetchResult {
	v := s.ssrf.Inspect(rawURL)
	if v.Fired {
		return FetchResult{Verdict: v, Target: rawURL, Body: leakedMetadata(v)}
	}
	return FetchResult{Verdict: v, Target: rawURL, Body: benignFetch(rawURL)}
}

// Track evaluates a logged header value for a Log4Shell lookup.
func (s *Simulator) Track(_ context.Context, logTag string) TrackResult {
	v := s.log4shell.Inspect(logTag)
	if v.Fired {
		return TrackResult{Verdict: v, Logged: jndiFired(v)}
	}
	return TrackResult{Verdict: v, Logged: "recorded tag: " + logTag}
}
