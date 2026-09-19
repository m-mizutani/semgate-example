package detector

// sqlStatementClass is the result of scanning a SQL string for stacked
// statements without executing it.
type sqlStatementClass int

const (
	sqlSingle    sqlStatementClass = iota // exactly one statement
	sqlStacked                            // a top-level ';' is followed by more SQL
	sqlMalformed                          // an unterminated string or block comment
)

// classifyStatements scans SQL the way SQLite tokenises it — respecting single-
// quoted strings (with ” escaping), double-quoted identifiers, line comments
// (-- … EOL) and block comments (/* … */) — and reports whether the text is a
// single statement, a stacked set, or malformed. It never executes anything.
func classifyStatements(sql string) sqlStatementClass {
	n := len(sql)
	i := 0
	sawSeparator := false // a top-level ';' has been seen

	for i < n {
		c := sql[i]
		switch {
		case c == '\'' || c == '"':
			quote := c
			i++
			closed := false
			for i < n {
				if sql[i] == quote {
					// A doubled quote is an escaped quote, not the end.
					if i+1 < n && sql[i+1] == quote {
						i += 2
						continue
					}
					i++
					closed = true
					break
				}
				i++
			}
			if !closed {
				return sqlMalformed
			}
		case c == '-' && i+1 < n && sql[i+1] == '-':
			// Line comment to end of line.
			i += 2
			for i < n && sql[i] != '\n' {
				i++
			}
		case c == '/' && i+1 < n && sql[i+1] == '*':
			// Block comment.
			i += 2
			closed := false
			for i+1 < n {
				if sql[i] == '*' && sql[i+1] == '/' {
					i += 2
					closed = true
					break
				}
				i++
			}
			if !closed {
				return sqlMalformed
			}
		case c == ';':
			sawSeparator = true
			i++
		default:
			// Any non-space content after a top-level ';' is a second statement.
			if sawSeparator && !isSQLSpace(c) {
				return sqlStacked
			}
			i++
		}
	}
	return sqlSingle
}

func isSQLSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == '\v'
}
