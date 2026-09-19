package model

// Category identifies one family of injection the range simulates.
type Category string

const (
	CategorySQLi             Category = "sqli"
	CategoryCommandInjection Category = "command_injection"
	CategoryPathTraversal    Category = "path_traversal"
	CategorySSTI             Category = "ssti"
	CategorySSRF             Category = "ssrf"
	CategoryLog4Shell        Category = "log4shell"
)

// Verdict is the outcome of evaluating one input against one vulnerable sink.
// The range decides Fired by parsing/evaluating the input inside a model of the
// sink, never by performing the real side effect.
type Verdict struct {
	Fired    bool     // true if the input actually exploits the modeled sink
	Category Category // the family that fired ("" when not fired)
	RuleID   string   // stable id of the mechanism that fired ("" when not fired)
	Detail   string   // human-readable evidence of the verdict ("" when not fired)
}

// notFired is the shared zero verdict for a benign input.
func NotFired() Verdict { return Verdict{} }

// Fire builds a fired verdict for the given category.
func Fire(category Category, ruleID, detail string) Verdict {
	return Verdict{Fired: true, Category: category, RuleID: ruleID, Detail: detail}
}
