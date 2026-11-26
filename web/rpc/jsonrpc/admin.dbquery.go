package jsonrpc

import (
	"context"
	"database/sql"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/komari-monitor/komari/database/auditlog"
	"github.com/komari-monitor/komari/database/dbcore"
	"github.com/komari-monitor/komari/internal/metricstore"
	"github.com/komari-monitor/komari/pkg/metric"
	"github.com/komari-monitor/komari/pkg/rpc"
)

const (
	databaseTargetMain    = "main"
	databaseTargetMetrics = "metrics"
	defaultDBQueryLimit   = 1000
	maxDBQueryLimit       = 10000
)

type databaseQueryParams struct {
	Database *string `json:"database"`
	SQL      string  `json:"sql"`
	Args     []any   `json:"args"`
	Limit    *int    `json:"limit"`
}

type databaseExecParams struct {
	Database *string `json:"database"`
	SQL      string  `json:"sql"`
	Args     []any   `json:"args"`
}

type databaseTablesParams struct {
	Database *string `json:"database"`
}

type databaseQueryResponse struct {
	Database  string   `json:"database"`
	Driver    string   `json:"driver"`
	Columns   []string `json:"columns"`
	Rows      [][]any  `json:"rows"`
	RowCount  int      `json:"row_count"`
	Truncated bool     `json:"truncated"`
}

type databaseExecResponse struct {
	Database     string `json:"database"`
	Driver       string `json:"driver"`
	RowsAffected int64  `json:"rows_affected"`
	LastInsertID *int64 `json:"last_insert_id"`
}

type databaseTablesResponse struct {
	Database string   `json:"database"`
	Driver   string   `json:"driver"`
	Tables   []string `json:"tables"`
}

func init() {
	RegisterWithGroupAndMeta("dbQuery", rpc.RoleAdmin, adminDBQuery, &rpc.MethodMeta{
		Name:    "admin:dbQuery",
		Summary: "Execute a SQL query against the main or metrics database",
		Params: []rpc.ParamMeta{
			{Name: "database", Type: "main | metrics", Description: "Database target (default main)"},
			{Name: "sql", Type: "string", Required: true, Description: "SQL query to execute"},
			{Name: "args", Type: "any[]", Description: "Positional SQL parameters"},
			{Name: "limit", Type: "number", Description: "Maximum rows to return (default 1000, max 10000)"},
		},
		Returns: "{ database: string, driver: string, columns: string[], rows: any[][], row_count: number, truncated: boolean }",
	})
	RegisterWithGroupAndMeta("dbExec", rpc.RoleAdmin, adminDBExec, &rpc.MethodMeta{
		Name:    "admin:dbExec",
		Summary: "Execute a SQL statement against the main or metrics database",
		Params: []rpc.ParamMeta{
			{Name: "database", Type: "main | metrics", Description: "Database target (default main)"},
			{Name: "sql", Type: "string", Required: true, Description: "SQL statement to execute"},
			{Name: "args", Type: "any[]", Description: "Positional SQL parameters"},
		},
		Returns: "{ database: string, driver: string, rows_affected: number, last_insert_id: number | null }",
	})
	RegisterWithGroupAndMeta("dbTables", rpc.RoleAdmin, adminDBTables, &rpc.MethodMeta{
		Name:    "admin:dbTables",
		Summary: "List tables in the main or metrics database",
		Params: []rpc.ParamMeta{
			{Name: "database", Type: "main | metrics", Description: "Database target (default main)"},
		},
		Returns: "{ database: string, driver: string, tables: string[] }",
	})
}

func adminDBQuery(ctx context.Context, req *rpc.JsonRpcRequest) (any, *rpc.JsonRpcError) {
	params, target, statement, limit, rpcErr := parseDatabaseQueryParams(req)
	if rpcErr != nil {
		return nil, rpcErr
	}

	response, err := queryDatabase(ctx, target, statement, params.Args, limit)
	if err != nil {
		return nil, rpc.MakeError(rpc.InternalError, "Failed to execute database query: "+err.Error(), nil)
	}
	return response, nil
}

func adminDBExec(ctx context.Context, req *rpc.JsonRpcRequest) (any, *rpc.JsonRpcError) {
	var params databaseExecParams
	if err := req.BindParams(&params); err != nil {
		return nil, rpc.MakeError(rpc.InvalidParams, "Invalid request body: "+err.Error(), nil)
	}
	target, rpcErr := parseDatabaseTarget(params.Database)
	if rpcErr != nil {
		return nil, rpcErr
	}
	statement := strings.TrimSpace(params.SQL)
	if statement == "" {
		return nil, rpc.MakeError(rpc.InvalidParams, "sql is required", nil)
	}

	actor, ip := auditActor(ctx)
	sqlPreview := "SQL: " + auditlog.Truncate(redactSQLStringLiterals(statement), 2000)
	argsNote := ""
	if len(params.Args) > 0 {
		argsNote = fmt.Sprintf(", args=%d", len(params.Args))
	}

	result, driver, err := executeDatabase(ctx, target, statement, params.Args)
	if err != nil {
		summary := fmt.Sprintf("Failed to execute database SQL: target=%s%s", target, argsNote)
		auditlog.Log(ip, actor, auditlog.JoinLines(summary, "Error: "+err.Error(), sqlPreview), "error")
		return nil, rpc.MakeError(rpc.InternalError, "Failed to execute database statement: "+err.Error(), nil)
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		summary := fmt.Sprintf("Execute database SQL: target=%s, driver=%s%s (rows_affected unavailable: %v)", target, driver, argsNote, err)
		auditlog.Log(ip, actor, auditlog.JoinLines(summary, sqlPreview), "warn")
		return nil, rpc.MakeError(rpc.InternalError, "Failed to read affected row count: "+err.Error(), nil)
	}

	summary := fmt.Sprintf("Execute database SQL: target=%s, driver=%s, rows_affected=%d%s", target, driver, rowsAffected, argsNote)
	auditlog.Log(ip, actor, auditlog.JoinLines(summary, sqlPreview), "warn")

	var lastInsertID *int64
	if id, err := result.LastInsertId(); err == nil {
		lastInsertID = &id
	}
	return databaseExecResponse{
		Database:     target,
		Driver:       string(driver),
		RowsAffected: rowsAffected,
		LastInsertID: lastInsertID,
	}, nil
}

func adminDBTables(ctx context.Context, req *rpc.JsonRpcRequest) (any, *rpc.JsonRpcError) {
	var params databaseTablesParams
	if err := req.BindParams(&params); err != nil {
		return nil, rpc.MakeError(rpc.InvalidParams, "Invalid request body: "+err.Error(), nil)
	}
	target, rpcErr := parseDatabaseTarget(params.Database)
	if rpcErr != nil {
		return nil, rpcErr
	}

	response, err := listDatabaseTables(ctx, target)
	if err != nil {
		return nil, rpc.MakeError(rpc.InternalError, "Failed to list database tables: "+err.Error(), nil)
	}
	return response, nil
}

func parseDatabaseQueryParams(req *rpc.JsonRpcRequest) (databaseQueryParams, string, string, int, *rpc.JsonRpcError) {
	var params databaseQueryParams
	if err := req.BindParams(&params); err != nil {
		return databaseQueryParams{}, "", "", 0, rpc.MakeError(rpc.InvalidParams, "Invalid request body: "+err.Error(), nil)
	}
	target, rpcErr := parseDatabaseTarget(params.Database)
	if rpcErr != nil {
		return databaseQueryParams{}, "", "", 0, rpcErr
	}
	statement := strings.TrimSpace(params.SQL)
	if statement == "" {
		return databaseQueryParams{}, "", "", 0, rpc.MakeError(rpc.InvalidParams, "sql is required", nil)
	}
	limit := defaultDBQueryLimit
	if params.Limit != nil {
		limit = *params.Limit
		if limit < 1 || limit > maxDBQueryLimit {
			return databaseQueryParams{}, "", "", 0, rpc.MakeError(rpc.InvalidParams, fmt.Sprintf("limit must be between 1 and %d", maxDBQueryLimit), nil)
		}
	}
	return params, target, statement, limit, nil
}

func parseDatabaseTarget(value *string) (string, *rpc.JsonRpcError) {
	if value == nil {
		return databaseTargetMain, nil
	}
	target := strings.TrimSpace(*value)
	if target != databaseTargetMain && target != databaseTargetMetrics {
		return "", rpc.MakeError(rpc.InvalidParams, "database must be main or metrics", nil)
	}
	return target, nil
}

func queryDatabase(ctx context.Context, target, statement string, args []any, limit int) (databaseQueryResponse, error) {
	rows, driver, release, err := openDatabaseRows(ctx, target, statement, args...)
	if err != nil {
		return databaseQueryResponse{}, err
	}
	defer func() {
		_ = rows.Close()
		release()
	}()

	columns, resultRows, truncated, err := collectDatabaseRows(rows, limit)
	if err != nil {
		return databaseQueryResponse{}, err
	}
	return databaseQueryResponse{
		Database:  target,
		Driver:    string(driver),
		Columns:   columns,
		Rows:      resultRows,
		RowCount:  len(resultRows),
		Truncated: truncated,
	}, nil
}

func executeDatabase(ctx context.Context, target, statement string, args []any) (sql.Result, metric.Driver, error) {
	switch target {
	case databaseTargetMain:
		db, err := dbcore.GetDBInstance().DB()
		if err != nil {
			return nil, "", err
		}
		result, err := db.ExecContext(ctx, statement, args...)
		return result, metric.DriverSQLite, err
	case databaseTargetMetrics:
		return metricstore.ExecContext(ctx, statement, args...)
	default:
		return nil, "", fmt.Errorf("unsupported database target: %s", target)
	}
}

func listDatabaseTables(ctx context.Context, target string) (databaseTablesResponse, error) {
	var (
		rows         *sql.Rows
		actualDriver metric.Driver
		release      func()
		err          error
	)
	switch target {
	case databaseTargetMain:
		statement, err := tableListSQL(metric.DriverSQLite)
		if err != nil {
			return databaseTablesResponse{}, err
		}
		rows, actualDriver, release, err = openDatabaseRows(ctx, target, statement)
	case databaseTargetMetrics:
		rows, actualDriver, release, err = metricstore.QueryForDriver(ctx, tableListSQL)
	default:
		return databaseTablesResponse{}, fmt.Errorf("unsupported database target: %s", target)
	}
	if err != nil {
		return databaseTablesResponse{}, err
	}
	defer func() {
		_ = rows.Close()
		release()
	}()

	tables := make([]string, 0)
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return databaseTablesResponse{}, err
		}
		tables = append(tables, name)
	}
	if err := rows.Err(); err != nil {
		return databaseTablesResponse{}, err
	}
	sort.Strings(tables)
	return databaseTablesResponse{Database: target, Driver: string(actualDriver), Tables: tables}, nil
}

func openDatabaseRows(ctx context.Context, target, statement string, args ...any) (*sql.Rows, metric.Driver, func(), error) {
	switch target {
	case databaseTargetMain:
		db, err := dbcore.GetDBInstance().DB()
		if err != nil {
			return nil, "", nil, err
		}
		rows, err := db.QueryContext(ctx, statement, args...)
		return rows, metric.DriverSQLite, func() {}, err
	case databaseTargetMetrics:
		return metricstore.QueryContext(ctx, statement, args...)
	default:
		return nil, "", nil, fmt.Errorf("unsupported database target: %s", target)
	}
}

func collectDatabaseRows(rows *sql.Rows, limit int) ([]string, [][]any, bool, error) {
	columns, err := rows.Columns()
	if err != nil {
		return nil, nil, false, err
	}
	resultRows := make([][]any, 0, limit)
	values := make([]any, len(columns))
	scans := make([]any, len(columns))
	for i := range scans {
		scans[i] = &values[i]
	}

	for rows.Next() {
		if len(resultRows) == limit {
			return columns, resultRows, true, nil
		}
		if err := rows.Scan(scans...); err != nil {
			return nil, nil, false, err
		}
		row := make([]any, len(values))
		for i, value := range values {
			row[i] = normalizeDatabaseValue(value)
		}
		resultRows = append(resultRows, row)
	}
	if err := rows.Err(); err != nil {
		return nil, nil, false, err
	}
	return columns, resultRows, false, nil
}

// redactSQLStringLiterals is a fail-closed lexical scanner for SQL audit
// previews. It redacts single-quoted and double-quoted literals while
// honoring SQL comments, quote doubling, and backslash escapes. Comments are
// retained only as redacted placeholders because an apostrophe inside a
// comment must never flip quote parity. Dialect-ambiguous constructs — a
// MySQL '#' line comment, an odd backslash run before a quote, a nested or
// executable block comment, a non-positional dollar construct (dollar
// quotes, '$' identifiers, Tcl-style bind parameters), a MySQL '--' without
// trailing whitespace, a bare carriage return inside a line comment, or a
// backtick/bracket identifier carrying quote-like content — downgrade the
// whole statement preview rather than risking plaintext credential
// disclosure.
func redactSQLStringLiterals(statement string) string {
	var out strings.Builder
	out.Grow(len(statement))
	for i := 0; i < len(statement); {
		ch := statement[i]
		switch {
		case ch == '-' && i+1 < len(statement) && statement[i+1] == '-':
			newline, next, ok := scanSQLLineCommentEnd(statement, i+2)
			if !ok {
				return "[REDACTED]"
			}
			out.WriteString("--[REDACTED]")
			if newline {
				out.WriteByte('\n')
			}
			i = next
		case ch == '/' && i+1 < len(statement) && statement[i+1] == '*':
			next, ok := scanSQLBlockComment(statement, i)
			if !ok {
				return "[REDACTED]"
			}
			out.WriteString("/*[REDACTED]*/")
			i = next
		case ch == '\'' || ch == '"':
			next, ok := scanSQLQuotedLiteral(statement, i, ch)
			if !ok {
				return "[REDACTED]"
			}
			out.WriteByte(ch)
			out.WriteString("[REDACTED]")
			out.WriteByte(ch)
			i = next
		case ch == '#':
			// MySQL '#' line comments are not distinguished from PostgreSQL
			// bitwise operators by a dialect-agnostic scanner, and an apostrophe
			// inside such a comment flips quote parity. Fail closed globally.
			return "[REDACTED]"
		case ch == '`':
			next, ok := scanSQLBacktickIdentifier(statement, i)
			if !ok {
				return "[REDACTED]"
			}
			out.WriteString(statement[i:next])
			i = next
		case ch == '[':
			next, ok := scanSQLBracketIdentifier(statement, i)
			if !ok {
				return "[REDACTED]"
			}
			out.WriteString(statement[i:next])
			i = next
		case ch == '0' && scanSQLBinaryOrHexLiteralEnd(statement, i) > 0:
			// MySQL unquoted binary and hexadecimal literals (0b..., 0x...) are
			// byte-string value carriers and must be redacted like quoted
			// literals.
			end := scanSQLBinaryOrHexLiteralEnd(statement, i)
			out.WriteString(statement[i : i+2])
			out.WriteString("[REDACTED]")
			i = end
		case ch == '$':
			written, next, ok := scanSQLDollarConstruct(statement, i)
			if !ok {
				return "[REDACTED]"
			}
			out.WriteString(written)
			i = next
		case ch == ':' || ch == '@':
			// Tcl-style SQLite bind parameters (:x, @x) fold a following
			// parenthesized suffix into the variable token, hiding string
			// openers from other dialects.
			if hasUnsafeSQLiteVarParen(statement, i) {
				return "[REDACTED]"
			}
			out.WriteByte(ch)
			i++
		default:
			out.WriteByte(ch)
			i++
		}
	}
	return out.String()
}

// scanSQLLineCommentEnd scans from the byte just after a "--" opener to the
// end of the line comment. MySQL only treats "--" as a comment when followed
// by whitespace or EOF — otherwise "--'" is two unary minus operators and a
// string literal — so a non-whitespace byte here fails closed. A bare '\r'
// (not part of a CRLF pair) terminates the comment in PostgreSQL but not in
// SQLite/MySQL, so it likewise fails closed. Returns whether a newline
// terminator was consumed (the newline is consumed here and re-emitted by
// the caller), the byte index just after the comment, and whether scanning
// is safe.
func scanSQLLineCommentEnd(statement string, start int) (bool, int, bool) {
	if start < len(statement) && !isSQLSpace(statement[start]) {
		return false, 0, false
	}
	i := start
	for i < len(statement) && statement[i] != '\n' {
		if statement[i] == '\r' && (i+1 >= len(statement) || statement[i+1] != '\n') {
			return false, 0, false
		}
		i++
	}
	if i < len(statement) {
		return true, i + 1, true
	}
	return false, i, true
}

func isSQLSpace(ch byte) bool {
	return ch == ' ' || ch == '\t' || ch == '\n' || ch == '\r' || ch == '\v' || ch == '\f'
}

// scanSQLDollarConstruct handles PostgreSQL positional parameters ($1, ...)
// starting at start. Dollar-quoted literals ($$...$$, $tag$...$tag$) invert
// lexical meaning across dialects — '$' is also a plain identifier byte or a
// Tcl-style bind parameter opener in SQLite and MySQL — so every
// non-positional dollar construct fails closed rather than guessing.
// Positional parameters pass through as the bare '$' after the Tcl-variable
// parenthesis check.
func scanSQLDollarConstruct(statement string, start int) (string, int, bool) {
	if start+1 < len(statement) && statement[start+1] >= '0' && statement[start+1] <= '9' {
		if hasUnsafeSQLiteVarParen(statement, start) {
			return "", 0, false
		}
		return "$", start + 1, true
	}
	return "", 0, false
}

// hasUnsafeSQLiteVarParen reports whether a Tcl-style SQLite bind parameter
// starting at start (a ':', '@', or positional '$' prefix) is followed by a
// parenthesized suffix whose interior cannot be scanned safely across
// dialects. SQLite folds :x(...), @x(...) and $1(...) into a single variable
// token, so an apostrophe inside the parentheses is not a string opener
// there but is one elsewhere — any ambiguous byte inside the parentheses
// must fail closed. The scan region ends at the first ')', whitespace byte,
// or EOF; only EOF without a closing ')' counts as unterminated. Type casts
// such as $1::varchar(32) are skipped past the parentheses and remain
// visible.
func hasUnsafeSQLiteVarParen(statement string, start int) bool {
	i := start + 1
	n := 0
	for i < len(statement) {
		if isSQLiteIdChar(statement[i]) {
			n++
			i++
			continue
		}
		if statement[i] == ':' && i+1 < len(statement) && statement[i+1] == ':' {
			i += 2
			continue
		}
		break
	}
	if n == 0 || i >= len(statement) || statement[i] != '(' {
		return false
	}
	for j := i + 1; j < len(statement); j++ {
		switch statement[j] {
		case ')':
			return false
		case '\'', '"', '`', '\\', '#', '$', '[':
			return true
		case '-':
			if j+1 < len(statement) && statement[j+1] == '-' {
				return true
			}
		case '/':
			if j+1 < len(statement) && statement[j+1] == '*' {
				return true
			}
		default:
			if isSQLSpace(statement[j]) {
				return false
			}
		}
	}
	return true
}

func isSQLiteIdChar(ch byte) bool {
	return ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' || ch == '_' || ch == '$' || ch >= 0x80
}

// scanSQLBacktickIdentifier scans a MySQL/SQLite backtick-quoted identifier
// starting at start. Doubled backticks are escapes inside the identifier. In
// PostgreSQL a backtick is an operator character rather than an identifier
// delimiter, so when the interior carries a quote, backslash, comment
// opener, or other ambiguous byte the scanner cannot tell identifier from
// operator text across dialects and must fail closed. An unterminated
// identifier is likewise fail closed.
func scanSQLBacktickIdentifier(statement string, start int) (int, bool) {
	for i := start + 1; i < len(statement); i++ {
		switch statement[i] {
		case '`':
			if i+1 < len(statement) && statement[i+1] == '`' {
				i++
				continue
			}
			return i + 1, true
		case '\'', '"', '\\', '#', '$', '[':
			return 0, false
		case '-':
			if i+1 < len(statement) && statement[i+1] == '-' {
				return 0, false
			}
		case '/':
			if i+1 < len(statement) && statement[i+1] == '*' {
				return 0, false
			}
		}
	}
	return 0, false
}

// scanSQLBracketIdentifier scans a bracketed token starting at start. In
// SQLite [name] is a quoted identifier, while in PostgreSQL arr[...] is an
// array subscript whose content can be an arbitrary expression. When the
// interior carries any quote, backslash, comment opener, or other ambiguous
// byte, the scanner cannot tell identifier from expression across dialects
// and must fail closed.
func scanSQLBracketIdentifier(statement string, start int) (int, bool) {
	for i := start + 1; i < len(statement); i++ {
		switch statement[i] {
		case ']':
			return i + 1, true
		case '\'', '"', '`', '\\', '#', '$':
			return 0, false
		case '-':
			if i+1 < len(statement) && statement[i+1] == '-' {
				return 0, false
			}
		case '/':
			if i+1 < len(statement) && statement[i+1] == '*' {
				return 0, false
			}
		}
	}
	return 0, false
}

// scanSQLBinaryOrHexLiteralEnd reports the byte index just after a MySQL
// unquoted binary (0b/0B followed by one or more binary digits) or
// hexadecimal (0x/0X followed by one or more hex digits) literal starting at
// start, or 0 when the bytes at start do not form one. The caller passes the
// index of the leading '0' byte.
func scanSQLBinaryOrHexLiteralEnd(statement string, start int) int {
	if start+2 >= len(statement) {
		return 0
	}
	if statement[start] != '0' {
		return 0
	}
	var validDigit func(byte) bool
	switch statement[start+1] {
	case 'x', 'X':
		validDigit = isHexDigit
	case 'b', 'B':
		validDigit = isBinaryDigit
	default:
		return 0
	}
	// Require a non-identifier byte before the literal so identifiers like
	// x0xff or names ending in a digit are never misinterpreted.
	if start > 0 {
		prev := statement[start-1]
		if prev == '_' || prev >= '0' && prev <= '9' || prev >= 'a' && prev <= 'z' || prev >= 'A' && prev <= 'Z' {
			return 0
		}
	}
	end := start + 2
	for end < len(statement) && validDigit(statement[end]) {
		end++
	}
	if end == start+2 {
		return 0
	}
	return end
}

func isHexDigit(ch byte) bool {
	return ch >= '0' && ch <= '9' || ch >= 'a' && ch <= 'f' || ch >= 'A' && ch <= 'F'
}

func isBinaryDigit(ch byte) bool {
	return ch == '0' || ch == '1'
}

// isExecutableBlockCommentStart reports whether the bytes just after a "/*"
// opener at start mark a conditionally executable comment: MySQL /*! ... */
// conditional comments and /*+ ... */ optimizer hints, MariaDB /*M! ... */
// (optionally versioned /*M!NNNNNN ... */), and TiDB /*T! ... */. Their
// interiors execute as normal SQL in the respective dialect, so a string
// literal inside can carry */ without closing the comment — a
// dialect-agnostic scanner must fail closed on them. Ordinary comments such
// as "/* MariaDB note */" or "/* TODO! */" are unaffected because the '!'
// must sit in the third position immediately after an 'M'/'m'/'T'/'t'.
func isExecutableBlockCommentStart(statement string, start int) bool {
	if start+2 >= len(statement) {
		return false
	}
	ch := statement[start+2]
	if ch == '!' || ch == '+' {
		return true
	}
	return start+3 < len(statement) && statement[start+3] == '!' &&
		(ch == 'M' || ch == 'm' || ch == 'T' || ch == 't')
}

// scanSQLBlockComment returns the byte index just after a block comment.
// PostgreSQL nests block comments while SQLite and MySQL close at the first
// closing delimiter, and MySQL executes the interior of /*! ... */
// conditional comments and honors /*+ ... */ optimizer hints — a
// dialect-agnostic scanner cannot tell comment text from executable SQL
// across these dialects, so any nested or executable opening fails closed.
func scanSQLBlockComment(statement string, start int) (int, bool) {
	if isExecutableBlockCommentStart(statement, start) {
		return 0, false
	}
	for i := start + 2; i < len(statement); i++ {
		if i+1 < len(statement) && statement[i] == '/' && statement[i+1] == '*' {
			return 0, false
		}
		if i+1 < len(statement) && statement[i] == '*' && statement[i+1] == '/' {
			return i + 2, true
		}
	}
	return 0, false
}

// scanSQLQuotedLiteral returns the byte index just after a quoted literal
// starting at start. SQL quote doubling keeps the scanner inside the literal.
// Backslash runs are dialect-ambiguous: MySQL treats a backslash as an escape
// while SQLite/PostgreSQL treat it as a plain byte, so an odd-length backslash
// run immediately before the closing quote flips quote parity between dialects
// and must fail closed rather than guessing. Even-length runs and backslashes
// before non-quote bytes are lexically identical across dialects and safe.
func scanSQLQuotedLiteral(statement string, start int, quote byte) (int, bool) {
	for i := start + 1; i < len(statement); i++ {
		switch statement[i] {
		case '\\':
			// Count the consecutive backslash run starting at i.
			n := 0
			for i+n < len(statement) && statement[i+n] == '\\' {
				n++
			}
			if i+n >= len(statement) {
				// Dangling backslashes at EOF: the literal never closes in some
				// dialects, so this is unterminated/ambiguous.
				return 0, false
			}
			if n%2 == 1 && statement[i+n] == quote {
				// MySQL: the quote is escaped, the literal continues;
				// SQLite/PostgreSQL: the quote closes the literal. The two
				// dialect trees are inverted, so fail closed.
				return 0, false
			}
			// Even-length runs are self-escaping in every dialect, and runs
			// followed by a non-quote byte escape nothing relevant. Skip the
			// whole run and keep scanning.
			i += n - 1
		case quote:
			if i+1 < len(statement) && statement[i+1] == quote {
				i++
				continue
			}
			return i + 1, true
		}
	}
	return 0, false
}

func normalizeDatabaseValue(value any) any {
	switch value := value.(type) {
	case []byte:
		return string(value)
	case time.Time:
		return value.Format(time.RFC3339Nano)
	default:
		return value
	}
}

func tableListSQL(driver metric.Driver) (string, error) {
	switch driver {
	case metric.DriverSQLite:
		return "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'", nil
	case metric.DriverMySQL:
		return "SELECT table_name FROM information_schema.tables WHERE table_schema = DATABASE() AND table_type = 'BASE TABLE'", nil
	case metric.DriverPostgreSQL:
		return "SELECT tablename FROM pg_catalog.pg_tables WHERE schemaname = current_schema()", nil
	default:
		return "", fmt.Errorf("unsupported database driver: %s", driver)
	}
}
