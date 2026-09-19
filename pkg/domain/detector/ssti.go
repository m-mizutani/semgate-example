package detector

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/m-mizutani/semgate-example/pkg/domain/model"
)

// SSTI models a greeting endpoint that renders "Hello, <name>!" through a
// template engine. It detects template delimiters in the input and evaluates
// the inner expression with a SAFE arithmetic-only evaluator. It fires when the
// expression actually evaluates to a value different from its literal text
// (i.e. the engine would have computed something), which is what {{7*7}} -> 49
// demonstrates. A full template engine is deliberately not used: its evaluation
// surface on attacker input is far too broad.
type SSTI struct {
	delims [][2]string
}

// NewSSTI builds the template-injection detector.
func NewSSTI() *SSTI {
	return &SSTI{delims: [][2]string{
		{"{{", "}}"},
		{"${", "}"},
		{"<%", "%>"},
		{"#{", "}"},
	}}
}

// Inspect evaluates the name value for an evaluated template expression. It
// scans every delimited expression in the input (not just the first of each
// kind) and fires as soon as one evaluates to a value different from its literal
// text.
func (d *SSTI) Inspect(name string) model.Verdict {
	for _, delim := range d.delims {
		open, close := delim[0], delim[1]
		search := name
		for {
			start := strings.Index(search, open)
			if start < 0 {
				break
			}
			rest := search[start+len(open):]
			end := strings.Index(rest, close)
			if end < 0 {
				break
			}
			expr := strings.TrimSpace(rest[:end])
			// ERB-style output tags open with "=" (<%= expr %>); drop it so the
			// expression underneath is evaluated.
			expr = strings.TrimSpace(strings.TrimPrefix(expr, "="))

			if value, ok := evalArithmetic(expr); ok {
				rendered := strconv.Itoa(value)
				// A result different from the literal text means the engine
				// computed something — the expression was interpreted, not printed.
				if rendered != expr {
					return model.Fire(model.CategorySSTI, "ssti_expression_evaluated",
						fmt.Sprintf("template expression %q evaluated to %s", expr, rendered))
				}
			}

			// Continue after this expression's closing delimiter.
			search = rest[end+len(close):]
		}
	}
	return model.NotFired()
}

// evalArithmetic evaluates an integer arithmetic expression (+, -, *, /, and
// parentheses). It returns ok=false when the text is not a pure arithmetic
// expression, so a plain name like "Alice" is never treated as a fire.
func evalArithmetic(expr string) (int, bool) {
	p := &exprParser{src: expr}
	value, ok := p.parseExpr()
	if !ok {
		return 0, false
	}
	p.skipSpaces()
	if p.pos != len(p.src) {
		return 0, false // trailing junk: not a pure arithmetic expression
	}
	return value, true
}

type exprParser struct {
	src string
	pos int
}

func (p *exprParser) skipSpaces() {
	for p.pos < len(p.src) && p.src[p.pos] == ' ' {
		p.pos++
	}
}

// parseExpr handles + and - (lowest precedence).
func (p *exprParser) parseExpr() (int, bool) {
	value, ok := p.parseTerm()
	if !ok {
		return 0, false
	}
	for {
		p.skipSpaces()
		if p.pos >= len(p.src) {
			return value, true
		}
		op := p.src[p.pos]
		if op != '+' && op != '-' {
			return value, true
		}
		p.pos++
		rhs, ok := p.parseTerm()
		if !ok {
			return 0, false
		}
		if op == '+' {
			value += rhs
		} else {
			value -= rhs
		}
	}
}

// parseTerm handles * and / (higher precedence).
func (p *exprParser) parseTerm() (int, bool) {
	value, ok := p.parseFactor()
	if !ok {
		return 0, false
	}
	for {
		p.skipSpaces()
		if p.pos >= len(p.src) {
			return value, true
		}
		op := p.src[p.pos]
		if op != '*' && op != '/' {
			return value, true
		}
		p.pos++
		rhs, ok := p.parseFactor()
		if !ok {
			return 0, false
		}
		if op == '*' {
			value *= rhs
		} else {
			if rhs == 0 {
				return 0, false
			}
			value /= rhs
		}
	}
}

// parseFactor handles integers and parenthesised sub-expressions.
func (p *exprParser) parseFactor() (int, bool) {
	p.skipSpaces()
	if p.pos >= len(p.src) {
		return 0, false
	}
	if p.src[p.pos] == '(' {
		p.pos++
		value, ok := p.parseExpr()
		if !ok {
			return 0, false
		}
		p.skipSpaces()
		if p.pos >= len(p.src) || p.src[p.pos] != ')' {
			return 0, false
		}
		p.pos++
		return value, true
	}
	start := p.pos
	for p.pos < len(p.src) && p.src[p.pos] >= '0' && p.src[p.pos] <= '9' {
		p.pos++
	}
	if p.pos == start {
		return 0, false
	}
	n, err := strconv.Atoi(p.src[start:p.pos])
	if err != nil {
		return 0, false
	}
	return n, true
}
