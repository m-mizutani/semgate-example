package detector

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/m-mizutani/goerr/v2"
	"github.com/m-mizutani/semgate-example/pkg/domain/model"
	sqlite "modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"
)

// loginQueryTemplate is the vulnerable query: user input is concatenated raw
// into the string literals, exactly as a vulnerable app would build it.
const loginQueryTemplate = "SELECT id, username FROM users WHERE username = '%s' AND password = '%s'"

// loginQuerySafe is the same query built safely with bound parameters. Its row
// count is the ground truth the concatenated query is compared against.
const loginQuerySafe = "SELECT id, username FROM users WHERE username = ? AND password = ?"

// inspectTimeout bounds a single evaluation so a crafted query (a recursive CTE,
// a huge randomblob) cannot run forever while the connection mutex is held.
const inspectTimeout = 2 * time.Second

// SQLi models a login endpoint whose query is built by string concatenation. It
// decides whether the input exploits the query by:
//
//   - Splitting the concatenated SQL into statements. The template is a single
//     SELECT, so a well-formed benign input stays one statement. More than one
//     statement means the input closed the literal and appended its own
//     statement (stacked injection): that fires WITHOUT being executed, so
//     "; PRAGMA query_only=OFF", "; ATTACH ...", "; DROP ..." never run.
//   - Running the single remaining statement (always a read-only SELECT)
//     against a hardened in-memory SQLite (pure Go, modernc.org/sqlite) and
//     comparing its row count with the same query run safely with bound
//     parameters. More rows than the safe query means authentication bypass or
//     UNION exfiltration; a SQL error means the input broke the grammar.
//
// Hardening: one dedicated in-memory connection, read-only (query_only), with
// ATTACH disabled and length / VDBE-op / expression-depth limits, plus a
// per-inspection deadline. Only a single SELECT ever reaches SQLite, so running
// attacker SQL can, at worst, read the fake table.
type SQLi struct {
	db   *sql.DB
	conn *sql.Conn
	mu   sync.Mutex // the single connection is not safe for concurrent use
}

// NewSQLi opens, seeds, and hardens the in-memory SQLite used for SQLi checks.
func NewSQLi() (*SQLi, error) {
	ctx := context.Background()

	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		return nil, goerr.Wrap(err, "open in-memory sqlite")
	}

	conn, err := db.Conn(ctx)
	if err != nil {
		_ = db.Close()
		return nil, goerr.Wrap(err, "acquire sqlite connection")
	}

	if err := seedAndHarden(ctx, conn); err != nil {
		_ = conn.Close()
		_ = db.Close()
		return nil, err
	}

	return &SQLi{db: db, conn: conn}, nil
}

// Close releases the connection and the in-memory database.
func (d *SQLi) Close() error {
	_ = d.conn.Close()
	return d.db.Close()
}

// connLimits are the SQLite limits applied to the connection. Small caps keep a
// single crafted SELECT from exhausting memory or CPU.
var connLimits = []struct {
	id  int
	val int
}{
	{sqlite3.SQLITE_LIMIT_ATTACHED, 0},         // no ATTACH at all
	{sqlite3.SQLITE_LIMIT_LENGTH, 1 << 16},     // cap string/blob length (e.g. randomblob)
	{sqlite3.SQLITE_LIMIT_SQL_LENGTH, 1 << 12}, // cap SQL text (input is already ≤1KB)
	{sqlite3.SQLITE_LIMIT_VDBE_OP, 100_000},    // cap executed VM ops (recursive CTE, etc.)
	{sqlite3.SQLITE_LIMIT_EXPR_DEPTH, 100},     // cap expression nesting
}

// seedAndHarden creates and seeds the fake users table, then locks the
// connection down: read-only, no ATTACH, bounded resource limits.
func seedAndHarden(ctx context.Context, conn *sql.Conn) error {
	seed := []string{
		`CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, email TEXT)`,
		// Synthetic rows: obviously fake credentials, no real secrets.
		`INSERT INTO users (id, username, password, email) VALUES
			(1, 'admin', 'admin-pw-EXAMPLE', 'admin@example.com'),
			(2, 'alice', 'alice-pw-EXAMPLE', 'alice@example.com'),
			(3, 'bob',   'bob-pw-EXAMPLE',   'bob@example.com')`,
	}
	for _, stmt := range seed {
		if _, err := conn.ExecContext(ctx, stmt); err != nil {
			return goerr.Wrap(err, "seed sqlite", goerr.V("stmt", stmt))
		}
	}

	for _, lim := range connLimits {
		if _, err := sqlite.Limit(conn, lim.id, lim.val); err != nil {
			return goerr.Wrap(err, "set sqlite limit", goerr.V("limit_id", lim.id))
		}
	}

	// Defence in depth: read-only even though only single SELECTs are executed.
	if _, err := conn.ExecContext(ctx, "PRAGMA query_only = ON"); err != nil {
		return goerr.Wrap(err, "enable query_only")
	}
	return nil
}

// Inspect evaluates the username/password spliced into the vulnerable query.
func (d *SQLi) Inspect(ctx context.Context, username, password string) model.Verdict {
	concatenated := fmt.Sprintf(loginQueryTemplate, username, password)

	// A stacked or malformed statement never reaches SQLite.
	switch classifyStatements(concatenated) {
	case sqlStacked:
		return model.Fire(model.CategorySQLi, "sqli_stacked_statements",
			"input appended a second SQL statement (stacked query)")
	case sqlMalformed:
		return model.Fire(model.CategorySQLi, "sqli_broken_syntax",
			"input broke the SQL grammar (unterminated string or comment)")
	}

	ctx, cancel := context.WithTimeout(ctx, inspectTimeout)
	defer cancel()

	d.mu.Lock()
	defer d.mu.Unlock()

	safeCount, err := d.countRows(ctx, loginQuerySafe, username, password)
	if err != nil {
		// The safe (baseline) query must always succeed; if it does not, this is
		// an infrastructure fault, not a fired input.
		return model.NotFired()
	}

	rawCount, err := d.countRows(ctx, concatenated)
	if err != nil {
		// The template alone is valid SQL, so an error means the input altered the
		// statement's structure (or hit a resource limit).
		return model.Fire(model.CategorySQLi, "sqli_broken_syntax",
			fmt.Sprintf("input broke the SQL grammar: %s", sqliteErrText(err)))
	}

	if rawCount > safeCount {
		return model.Fire(model.CategorySQLi, "sqli_result_altered",
			fmt.Sprintf("concatenated query returned %d rows vs %d for the safe query", rawCount, safeCount))
	}

	return model.NotFired()
}

// countRows runs a query on the dedicated connection and counts returned rows.
// The caller holds d.mu.
func (d *SQLi) countRows(ctx context.Context, query string, args ...any) (int, error) {
	rows, err := d.conn.QueryContext(ctx, query, args...)
	if err != nil {
		return 0, err
	}
	defer func() { _ = rows.Close() }()

	count := 0
	for rows.Next() {
		count++
	}
	if err := rows.Err(); err != nil {
		return 0, err
	}
	return count, nil
}

func sqliteErrText(err error) string {
	var serr *sqlite.Error
	if errors.As(err, &serr) {
		return serr.Error()
	}
	return err.Error()
}
