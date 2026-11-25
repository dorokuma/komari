package jsonrpc

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/komari-monitor/komari/database/dbcore"
	"github.com/komari-monitor/komari/database/models"
	"github.com/komari-monitor/komari/pkg/rpc"
	"github.com/komari-monitor/komari/utils/messageSender"
	"github.com/komari-monitor/komari/utils/messageSender/webhook"
)

func testAuditContext(ip, userUUID string) context.Context {
	return rpc.NewContextWithMeta(context.Background(), &rpc.ContextMeta{
		RemoteIP: ip,
		UserUUID: userUUID,
	})
}

func latestAuditLog(t *testing.T) models.Log {
	t.Helper()
	var entry models.Log
	if err := dbcore.GetDBInstance().Order("id desc").First(&entry).Error; err != nil {
		t.Fatalf("load latest audit log: %v", err)
	}
	return entry
}

func TestClientLifecycleAuditLogsIncludeNameAndChanges(t *testing.T) {
	db := dbcore.GetDBInstance()
	ctx := testAuditContext("192.0.2.10", "actor-admin-1")

	res, rpcErr := adminAddClient(ctx, &rpc.JsonRpcRequest{
		Version: rpc.RPC_VERSION,
		Method:  "admin:addClient",
		Params:  map[string]any{"name": "SG-Node-01"},
	})
	if rpcErr != nil {
		t.Fatalf("adminAddClient failed: %v", rpcErr)
	}
	createdUUID := res.(map[string]any)["uuid"].(string)
	t.Cleanup(func() {
		db.Where("uuid = ?", createdUUID).Delete(&models.Client{})
	})

	createLog := latestAuditLog(t)
	wantCreate := "Create client: SG-Node-01(" + createdUUID + ")"
	if createLog.Message != wantCreate {
		t.Fatalf("create log = %q, want %q", createLog.Message, wantCreate)
	}

	if _, rpcErr := adminEditClient(ctx, &rpc.JsonRpcRequest{
		Version: rpc.RPC_VERSION,
		Method:  "admin:editClient",
		Params: map[string]any{
			"uuid":   createdUUID,
			"name":   "SG-Node-Renamed",
			"group":  "production",
			"region": "SG",
		},
	}); rpcErr != nil {
		t.Fatalf("adminEditClient failed: %v", rpcErr)
	}
	editLog := latestAuditLog(t)
	for _, want := range []string{
		"Edit client: SG-Node-Renamed(" + createdUUID + ")",
		`name: "SG-Node-01" -> "SG-Node-Renamed"`,
		`group: "" -> "production"`,
		`region: "" -> "SG"`,
	} {
		if !strings.Contains(editLog.Message, want) {
			t.Fatalf("edit log missing %q:\n%s", want, editLog.Message)
		}
	}

	if _, rpcErr := adminOrderClients(ctx, &rpc.JsonRpcRequest{
		Version: rpc.RPC_VERSION,
		Method:  "admin:orderClients",
		Params:  map[string]any{createdUUID: 7},
	}); rpcErr != nil {
		t.Fatalf("adminOrderClients failed: %v", rpcErr)
	}
	orderLog := latestAuditLog(t)
	if !strings.Contains(orderLog.Message, "SG-Node-Renamed("+createdUUID+")=7") {
		t.Fatalf("order log missing client weight:\n%s", orderLog.Message)
	}

	if _, rpcErr := adminRemoveClient(ctx, &rpc.JsonRpcRequest{
		Version: rpc.RPC_VERSION,
		Method:  "admin:removeClient",
		Params:  map[string]any{"uuid": createdUUID},
	}); rpcErr != nil {
		t.Fatalf("adminRemoveClient failed: %v", rpcErr)
	}
	deleteLog := latestAuditLog(t)
	for _, want := range []string{
		"Delete client: SG-Node-Renamed(" + createdUUID + ")",
		"group=production",
		"region=SG",
	} {
		if !strings.Contains(deleteLog.Message, want) {
			t.Fatalf("delete log missing %q:\n%s", want, deleteLog.Message)
		}
	}
}

func TestSettingsAndDBExecAuditLogsRetainContextAndRedactSecrets(t *testing.T) {
	ctx := testAuditContext("192.0.2.11", "actor-admin-2")

	// The test database is shared across -count repetitions, so include a
	// per-process nonce: a second run must still produce effective changes
	// instead of degenerating into a "(no effective changes)" no-op update.
	nonce := fmt.Sprintf("%d", time.Now().UnixNano())
	apiKey := "secret-api-key-123456-" + nonce
	sitename := "Komari Audit Test " + nonce
	if _, rpcErr := adminEditSettings(ctx, &rpc.JsonRpcRequest{
		Version: rpc.RPC_VERSION,
		Method:  "admin:editSettings",
		Params: map[string]any{
			"sitename": sitename,
			"api_key":  apiKey,
		},
	}); rpcErr != nil {
		t.Fatalf("adminEditSettings failed: %v", rpcErr)
	}
	settingsLog := latestAuditLog(t)
	if strings.Contains(settingsLog.Message, apiKey) {
		t.Fatalf("settings audit log leaked api_key:\n%s", settingsLog.Message)
	}
	for _, want := range []string{
		"Update settings:",
		"api_key: [REDACTED] (updated)",
		`"` + sitename + `"`,
	} {
		if !strings.Contains(settingsLog.Message, want) {
			t.Fatalf("settings audit log missing %q:\n%s", want, settingsLog.Message)
		}
	}

	if _, rpcErr := adminDBExec(ctx, &rpc.JsonRpcRequest{
		Version: rpc.RPC_VERSION,
		Method:  "admin:dbExec",
		Params: map[string]any{
			"database": "main",
			"sql":      "UPDATE clients SET weight = weight WHERE uuid = ?",
			"args":     []any{"non-existent-uuid"},
		},
	}); rpcErr != nil {
		t.Fatalf("adminDBExec failed: %v", rpcErr)
	}
	sqlLog := latestAuditLog(t)
	for _, want := range []string{
		"Execute database SQL: target=main, driver=sqlite, rows_affected=0, args=1",
		"SQL: UPDATE clients SET weight = weight WHERE uuid = ?",
	} {
		if !strings.Contains(sqlLog.Message, want) {
			t.Fatalf("dbExec audit log missing %q:\n%s", want, sqlLog.Message)
		}
	}
	if strings.Contains(sqlLog.Message, "non-existent-uuid") {
		t.Fatalf("dbExec audit log should not record raw positional args:\n%s", sqlLog.Message)
	}
}

// TestRedactSQLStringLiteralsFailClosed pins the audit redaction lexer against
// quote-parity attacks: comments, escapes, double-quoted literals, PostgreSQL
// dollar quotes, and unterminated input must never expose embedded credentials.
func TestRedactSQLStringLiteralsFailClosed(t *testing.T) {
	cases := []struct {
		name      string
		sql       string
		want      string
		forbidden []string
	}{
		{
			name:      "line comment apostrophe does not flip parity",
			sql:       "-- don't break prod\nUPDATE clients SET token='super-secret-token' WHERE uuid='u1'",
			want:      "--[REDACTED]\nUPDATE clients SET token='[REDACTED]' WHERE uuid='[REDACTED]'",
			forbidden: []string{"super-secret-token", "u1"},
		},
		{
			name:      "block comment apostrophe does not flip parity",
			sql:       "/* user's token */ UPDATE clients SET token='block-secret'",
			want:      "/*[REDACTED]*/ UPDATE clients SET token='[REDACTED]'",
			forbidden: []string{"user", "block-secret"},
		},
		{
			name:      "double quoted literal redacted",
			sql:       `UPDATE clients SET token="double-secret" WHERE uuid='u1'`,
			forbidden: []string{"double-secret", "u1"},
		},
		{
			name:      "mysql backslash escape keeps following literal redacted",
			sql:       `UPDATE t SET note='a\'b', token='backslash-secret'`,
			forbidden: []string{"backslash-secret"},
		},
		{
			name:      "postgres dollar quoted literal redacted",
			sql:       `UPDATE t SET token=$$dollar-secret$$, note=$tag$tag-secret$tag$`,
			forbidden: []string{"dollar-secret", "tag-secret"},
		},
		{
			name:      "nested block comment does not reopen parity",
			sql:       "/* outer /* inner */ still comment */ UPDATE t SET token='nested-secret'",
			forbidden: []string{"nested-secret"},
		},
		{
			name: "postgres positional parameters remain visible",
			sql:  "UPDATE clients SET token=$1 WHERE uuid=$2",
			want: "UPDATE clients SET token=$1 WHERE uuid=$2",
		},
		{
			name:      "ambiguous dollar input is globally fail closed",
			sql:       "UPDATE t SET note=$unterminated_tag secret='x'",
			want:      "[REDACTED]",
			forbidden: []string{"secret", "UPDATE"},
		},
		{
			name:      "unterminated quote is globally fail closed",
			sql:       "UPDATE clients SET token='unclosed-secret",
			want:      "[REDACTED]",
			forbidden: []string{"unclosed-secret", "UPDATE"},
		},
		{
			name:      "unterminated block comment is globally fail closed",
			sql:       "UPDATE clients /* unclosed comment SET token='secret'",
			want:      "[REDACTED]",
			forbidden: []string{"secret", "UPDATE"},
		},
		{
			// SQLite/PostgreSQL treat a backslash as a plain byte, so 'C:\' is a
			// closed literal; MySQL treats the backslash as an escape. The odd
			// backslash run before the quote is dialect-ambiguous and must fail
			// closed instead of flipping quote parity.
			name:      "sqlite backslash-ending literal with line comment is fail closed",
			sql:       `UPDATE clients SET remark='C:\', token='super-secret-token' -- don't`,
			want:      "[REDACTED]",
			forbidden: []string{"super-secret-token", "UPDATE"},
		},
		{
			name:      "sqlite double-quoted backslash-ending literal is fail closed",
			sql:       `UPDATE clients SET remark="C:\", token="super-secret-token" -- a"b`,
			want:      "[REDACTED]",
			forbidden: []string{"super-secret-token", "UPDATE"},
		},
		{
			name:      "mysql hash comment apostrophe cannot flip parity",
			sql:       "# don't break prod\nUPDATE t SET token='super-secret-token' # isn't logged",
			want:      "[REDACTED]",
			forbidden: []string{"super-secret-token", "UPDATE"},
		},
		{
			// A backtick carrying quote-like content is a PostgreSQL operator,
			// not an identifier delimiter, so it must fail closed globally.
			name:      "backtick identifier apostrophe is fail closed",
			sql:       "UPDATE t SET `don't`=1, token='super-secret-token', `can't`=2",
			want:      "[REDACTED]",
			forbidden: []string{"super-secret-token", "UPDATE"},
		},
		{
			name: "plain backtick identifiers pass through",
			sql:  "UPDATE `clients` SET token='t1'",
			want: "UPDATE `clients` SET token='[REDACTED]'",
		},
		{
			name: "doubled backtick escape passes through",
			sql:  "UPDATE `a``b` SET token='t1'",
			want: "UPDATE `a``b` SET token='[REDACTED]'",
		},
		{
			name:      "postgres backtick operator parity inversion is fail closed",
			sql:       "UPDATE t SET x = y ` '`', token='super-secret-token' -- '",
			want:      "[REDACTED]",
			forbidden: []string{"super-secret-token", "UPDATE"},
		},
		{
			name:      "bracket identifier containing quote is fail closed",
			sql:       "UPDATE t SET [don't]=1, token='super-secret-token'",
			want:      "[REDACTED]",
			forbidden: []string{"super-secret-token", "UPDATE"},
		},
		{
			name:      "mysql hex literal is redacted",
			sql:       "UPDATE t SET token=0x73757065722d7365637265742d746f6b656e WHERE id=1",
			want:      "UPDATE t SET token=0x[REDACTED] WHERE id=1",
			forbidden: []string{"736563726574"},
		},
		{
			name:      "even backslash run before quote closes normally",
			sql:       `UPDATE t SET path='C:\\', token='even-secret'`,
			want:      "UPDATE t SET path='[REDACTED]', token='[REDACTED]'",
			forbidden: []string{"even-secret", "C:\\"},
		},
		{
			name:      "backslash before non-quote byte keeps structure",
			sql:       `UPDATE t SET path='C:\Users\admin', token='path-secret'`,
			want:      "UPDATE t SET path='[REDACTED]', token='[REDACTED]'",
			forbidden: []string{"path-secret", "C:\\Users"},
		},
		{
			name:      "non-nested block comment parity inversion is fail closed",
			sql:       "/* /* */ UPDATE clients SET a='*/', token='super-secret-token' -- '",
			want:      "[REDACTED]",
			forbidden: []string{"super-secret-token", "UPDATE"},
		},
		{
			name:      "mysql executable comment is fail closed",
			sql:       "/*!50000 UPDATE t SET a='*/', token='super-secret-token' */ -- '",
			want:      "[REDACTED]",
			forbidden: []string{"super-secret-token", "UPDATE"},
		},
		{
			name:      "mysql optimizer hint comment is fail closed",
			sql:       "/*+ MAX_EXECUTION_TIME(1000) */ UPDATE t SET token='super-secret-token'",
			want:      "[REDACTED]",
			forbidden: []string{"super-secret-token", "UPDATE"},
		},
		{
			name:      "dollar identifier suffix parity inversion is fail closed",
			sql:       "UPDATE t SET a$$='$$', token='super-secret-token' -- '",
			want:      "[REDACTED]",
			forbidden: []string{"super-secret-token", "UPDATE"},
		},
		{
			name:      "mysql bare dollar identifier is fail closed",
			sql:       "UPDATE t SET $$='$$', token='super-secret-token' -- '",
			want:      "[REDACTED]",
			forbidden: []string{"super-secret-token", "UPDATE"},
		},
		{
			name:      "sqlite dollar bind parameter is fail closed",
			sql:       "UPDATE t SET a=$x$, b='$x$', token='super-secret-token' -- '",
			want:      "[REDACTED]",
			forbidden: []string{"super-secret-token", "UPDATE"},
		},
		{
			name:      "mysql dashdash without whitespace is fail closed",
			sql:       "UPDATE t SET x=--'\n', token='super-secret-token', y='--'",
			want:      "[REDACTED]",
			forbidden: []string{"super-secret-token", "UPDATE"},
		},
		{
			name:      "postgres bare carriage return ends line comment and is fail closed",
			sql:       "-- hi\rUPDATE t SET a='\n', token='super-secret-token' -- '",
			want:      "[REDACTED]",
			forbidden: []string{"super-secret-token", "UPDATE"},
		},
		{
			name:      "sqlite tcl variable colon prefix parity inversion is fail closed",
			sql:       "UPDATE clients SET a=:x('), token='super-secret-token' -- '",
			want:      "[REDACTED]",
			forbidden: []string{"super-secret-token", "UPDATE"},
		},
		{
			name:      "sqlite tcl variable at prefix is fail closed",
			sql:       "UPDATE clients SET a=@x('), token='super-secret-token' -- '",
			want:      "[REDACTED]",
			forbidden: []string{"super-secret-token", "UPDATE"},
		},
		{
			name:      "sqlite tcl variable dollar positional is fail closed",
			sql:       "UPDATE clients SET a=$1('), token='super-secret-token' -- '",
			want:      "[REDACTED]",
			forbidden: []string{"super-secret-token", "UPDATE"},
		},
		{
			// An unterminated Tcl-variable parenthesis swallows the rest of the
			// statement in SQLite but nothing elsewhere, so it fails closed even
			// when the interior carries no ambiguous byte.
			name:      "sqlite tcl variable unterminated paren is fail closed",
			sql:       "UPDATE clients SET a=:x(v1,token='super-secret-token'",
			want:      "[REDACTED]",
			forbidden: []string{"super-secret-token", "UPDATE"},
		},
		{
			name:      "postgres dollar quote parity inversion is fail closed",
			sql:       "UPDATE t SET a=$tag$'$$'$tag$, token='super-secret-token'",
			want:      "[REDACTED]",
			forbidden: []string{"super-secret-token", "UPDATE"},
		},
		{
			name: "crlf line comment passes through",
			sql:  "-- comment\r\nUPDATE t SET token='t1'",
			want: "--[REDACTED]\nUPDATE t SET token='[REDACTED]'",
		},
		{
			name: "dashdash eof comment passes through",
			sql:  "UPDATE t SET token='t1' -- tail",
			want: "UPDATE t SET token='[REDACTED]' --[REDACTED]",
		},
		{
			name:      "postgres cast with width passes through",
			sql:       "UPDATE clients SET token=$1::varchar(32) WHERE uuid=$2",
			want:      "UPDATE clients SET token=$1::varchar(32) WHERE uuid=$2",
			forbidden: []string{"[REDACTED]"},
		},
		{
			name:      "postgres cast with precision passes through",
			sql:       "UPDATE clients SET token=$1::numeric(10, 2) WHERE uuid=$2",
			want:      "UPDATE clients SET token=$1::numeric(10, 2) WHERE uuid=$2",
			forbidden: []string{"[REDACTED]"},
		},
		{
			name: "sqlite tcl variable with clean paren passes through",
			sql:  "UPDATE clients SET token=:x(32)",
			want: "UPDATE clients SET token=:x(32)",
		},
		{
			name:      "mysql binary literal is redacted",
			sql:       "UPDATE t SET token=0b011010110110010101111001 WHERE id=1",
			want:      "UPDATE t SET token=0b[REDACTED] WHERE id=1",
			forbidden: []string{"01101011"},
		},
		{
			name: "binary digit sequence not literal passes through",
			sql:  "UPDATE t SET token='x' WHERE b0b11=1",
			want: "UPDATE t SET token='[REDACTED]' WHERE b0b11=1",
		},
		{
			name:      "bracket identifier containing backtick is fail closed",
			sql:       "UPDATE t SET [a`b]=1, token='super-secret-token'",
			want:      "[REDACTED]",
			forbidden: []string{"super-secret-token", "UPDATE"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := redactSQLStringLiterals(tc.sql)
			if tc.want != "" && got != tc.want {
				t.Fatalf("redacted SQL = %q, want %q", got, tc.want)
			}
			for _, secret := range tc.forbidden {
				if strings.Contains(got, secret) {
					t.Fatalf("redacted SQL leaked %q:\n%s", secret, got)
				}
			}
		})
	}
}

func TestWebhookChannelAuditRedactsBodyAndHeadersOnce(t *testing.T) {
	if !messageSender.NotificationChannelRegistered("webhook") {
		if err := webhook.Register(); err != nil {
			t.Fatalf("register webhook channel: %v", err)
		}
	}
	db := dbcore.GetDBInstance()
	t.Cleanup(func() {
		db.Where("name = ?", "webhook").Delete(&models.MessageSenderProvider{})
	})

	ctx := testAuditContext("192.0.2.13", "actor-admin-webhook")
	bodyPayload := strings.Repeat("x", 55)
	headerPayload := "Bearer header-secret-value"
	if _, rpcErr := adminSetNotificationChannelConfiguration(ctx, &rpc.JsonRpcRequest{
		Version: rpc.RPC_VERSION,
		Method:  "admin:setNotificationChannelConfiguration",
		Params: map[string]any{
			"id": "webhook",
			"data": map[string]any{
				"url":     "https://example.invalid/hook",
				"body":    bodyPayload,
				"headers": headerPayload,
			},
		},
	}); rpcErr != nil {
		t.Fatalf("set webhook string config: %v", rpcErr)
	}
	stringLog := latestAuditLog(t)
	if !strings.Contains(stringLog.Message, "body=[BODY, 55 chars]") || !strings.Contains(stringLog.Message, "headers=[BODY, 26 chars]") {
		t.Fatalf("webhook audit did not preserve true body/header lengths once:\n%s", stringLog.Message)
	}
	if strings.Contains(stringLog.Message, "[BODY, 16 chars]") || strings.Contains(stringLog.Message, bodyPayload) || strings.Contains(stringLog.Message, headerPayload) {
		t.Fatalf("webhook audit double-wrapped or leaked secrets:\n%s", stringLog.Message)
	}

	if _, rpcErr := adminSetNotificationChannelConfiguration(ctx, &rpc.JsonRpcRequest{
		Version: rpc.RPC_VERSION,
		Method:  "admin:setNotificationChannelConfiguration",
		Params: map[string]any{
			"id": "webhook",
			"data": map[string]any{
				"url":     "https://example.invalid/hook",
				"body":    map[string]any{"token": "object-body-secret"},
				"headers": map[string]any{"Authorization": "object-header-secret"},
			},
		},
	}); rpcErr != nil {
		t.Fatalf("set webhook object config: %v", rpcErr)
	}
	objectLog := latestAuditLog(t)
	if !strings.Contains(objectLog.Message, "body=[REDACTED]") || !strings.Contains(objectLog.Message, "headers=[REDACTED]") {
		t.Fatalf("webhook audit did not redact object body/headers:\n%s", objectLog.Message)
	}
	if strings.Contains(objectLog.Message, "object-body-secret") || strings.Contains(objectLog.Message, "object-header-secret") {
		t.Fatalf("webhook audit leaked object secrets:\n%s", objectLog.Message)
	}

	// A non-string script payload must fail closed instead of serializing
	// embedded tokens into the audit log.
	if _, rpcErr := adminSetNotificationChannelConfiguration(ctx, &rpc.JsonRpcRequest{
		Version: rpc.RPC_VERSION,
		Method:  "admin:setNotificationChannelConfiguration",
		Params: map[string]any{
			"id": "webhook",
			"data": map[string]any{
				"url":    "https://example.invalid/hook",
				"script": map[string]any{"token": "script-object-secret"},
			},
		},
	}); rpcErr != nil {
		t.Fatalf("set webhook object script config: %v", rpcErr)
	}
	scriptLog := latestAuditLog(t)
	if !strings.Contains(scriptLog.Message, "script=[REDACTED]") {
		t.Fatalf("webhook audit did not redact object script:\n%s", scriptLog.Message)
	}
	if strings.Contains(scriptLog.Message, "script-object-secret") {
		t.Fatalf("webhook audit leaked object script secret:\n%s", scriptLog.Message)
	}
}

func TestPingAndOfflineNotificationAuditLogsResolveClientNames(t *testing.T) {
	db := dbcore.GetDBInstance()
	ctx := testAuditContext("192.0.2.12", "actor-admin-3")

	const nodeUUID = "audit-ping-node-1"
	t.Cleanup(func() {
		db.Where("uuid = ?", nodeUUID).Delete(&models.Client{})
		db.Where("client = ?", nodeUUID).Delete(&models.OfflineNotification{})
	})
	db.Where("uuid = ?", nodeUUID).Delete(&models.Client{})
	if err := db.Create(&models.Client{
		UUID:  nodeUUID,
		Token: "tok-" + nodeUUID,
		Name:  "JP-Osaka",
	}).Error; err != nil {
		t.Fatalf("seed client: %v", err)
	}

	res, rpcErr := adminAddPingTask(ctx, &rpc.JsonRpcRequest{
		Version: rpc.RPC_VERSION,
		Method:  "admin:addPingTask",
		Params: map[string]any{
			"name":     "Cloudflare DNS",
			"target":   "1.1.1.1",
			"type":     "icmp",
			"interval": 60,
			"clients":  []string{nodeUUID},
		},
	})
	if rpcErr != nil {
		t.Fatalf("adminAddPingTask failed: %v", rpcErr)
	}
	taskID := res.(map[string]any)["task_id"].(uint)
	t.Cleanup(func() {
		db.Where("id = ?", taskID).Delete(&models.PingTask{})
	})

	addPingLog := latestAuditLog(t)
	for _, want := range []string{
		"Create ping task:",
		"Cloudflare DNS",
		"target=1.1.1.1",
		"JP-Osaka(" + nodeUUID + ")",
	} {
		if !strings.Contains(addPingLog.Message, want) {
			t.Fatalf("addPingTask log missing %q:\n%s", want, addPingLog.Message)
		}
	}

	if _, rpcErr := adminEditPingTask(ctx, &rpc.JsonRpcRequest{
		Version: rpc.RPC_VERSION,
		Method:  "admin:editPingTask",
		Params: map[string]any{
			"tasks": []map[string]any{
				{
					"id":       taskID,
					"name":     "Cloudflare DNS Updated",
					"target":   "1.0.0.1",
					"type":     "icmp",
					"interval": 30,
					"clients":  []string{nodeUUID},
				},
			},
		},
	}); rpcErr != nil {
		t.Fatalf("adminEditPingTask failed: %v", rpcErr)
	}
	editPingLog := latestAuditLog(t)
	for _, want := range []string{
		"Edit ping tasks: count=1",
		"Cloudflare DNS Updated",
		"target=1.0.0.1",
		"JP-Osaka(" + nodeUUID + ")",
	} {
		if !strings.Contains(editPingLog.Message, want) {
			t.Fatalf("editPingTask log missing %q:\n%s", want, editPingLog.Message)
		}
	}

	if _, rpcErr := adminEditOfflineNotification(ctx, &rpc.JsonRpcRequest{
		Version: rpc.RPC_VERSION,
		Method:  "admin:editOfflineNotification",
		Params: []map[string]any{
			{"client": nodeUUID, "enable": true, "grace_period": 180},
		},
	}); rpcErr != nil {
		t.Fatalf("adminEditOfflineNotification failed: %v", rpcErr)
	}
	offlineLog := latestAuditLog(t)
	if !strings.Contains(offlineLog.Message, "JP-Osaka("+nodeUUID+") (enabled=true, grace=180s)") {
		t.Fatalf("editOfflineNotification log missing details:\n%s", offlineLog.Message)
	}

	if _, rpcErr := adminDisableOfflineNotification(ctx, &rpc.JsonRpcRequest{
		Version: rpc.RPC_VERSION,
		Method:  "admin:disableOfflineNotification",
		Params:  []string{nodeUUID},
	}); rpcErr != nil {
		t.Fatalf("adminDisableOfflineNotification failed: %v", rpcErr)
	}
	disableLog := latestAuditLog(t)
	if !strings.Contains(disableLog.Message, "Disable offline notifications: JP-Osaka("+nodeUUID+")") {
		t.Fatalf("disableOfflineNotification log missing client label:\n%s", disableLog.Message)
	}
}
