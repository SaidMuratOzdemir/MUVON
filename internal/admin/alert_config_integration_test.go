package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"muvon/internal/alerting"
	"muvon/internal/alertrules"
	"muvon/internal/logger"
	"muvon/internal/secret"
	"muvon/internal/testpg"
)

type alertAPI struct {
	t      *testing.T
	dbs    testpg.DBs
	box    *secret.Box
	srv    *Server
	mux    *http.ServeMux
	sender *recordingSender
}

type recordingSender struct {
	fail     error
	channels []alertrules.Channel
}

func (s *recordingSender) Send(_ context.Context, ch alertrules.Channel, _ alerting.Message) error {
	s.channels = append(s.channels, ch)
	return s.fail
}

func newAlertAPI(t *testing.T) *alertAPI {
	t.Helper()
	dbs := testpg.Open(t)
	box, err := secret.NewBox("test-key")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err := dbs.Muvon.SyncBuiltinAlertRules(ctx, alertrules.BuiltinRules()); err != nil {
		t.Fatal(err)
	}
	if _, err := dbs.Muvon.Pool.Exec(ctx, `
		INSERT INTO muvon.deploy_projects (slug, name) VALUES ('shop', 'Shop');
		INSERT INTO muvon.deploy_components (project_id, slug, name, image_repo, internal_port)
		SELECT id, 'worker', 'Worker', 'registry.example.com/shop', 8000 FROM muvon.deploy_projects WHERE slug = 'shop';`); err != nil {
		t.Fatalf("seed project: %v", err)
	}
	sender := &recordingSender{}
	srv := &Server{db: dbs.Muvon, secretBox: box, testAlertSenders: map[string]alerting.Sender{
		alertrules.ChannelSlack: sender, alertrules.ChannelEmail: sender,
	}}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/alerts/{id}", srv.handleGetAlert)
	mux.HandleFunc("GET /api/alert-channels", srv.handleListAlertChannels)
	mux.HandleFunc("POST /api/alert-channels", srv.handleCreateAlertChannel)
	mux.HandleFunc("PUT /api/alert-channels/{id}", srv.handleUpdateAlertChannel)
	mux.HandleFunc("DELETE /api/alert-channels/{id}", srv.handleDeleteAlertChannel)
	mux.HandleFunc("POST /api/alert-channels/{id}/test", srv.handleTestAlertChannel)
	mux.HandleFunc("GET /api/alert-rules", srv.handleListAlertRules)
	mux.HandleFunc("POST /api/alert-rules", srv.handleCreateAlertRule)
	mux.HandleFunc("PUT /api/alert-rules/{id}", srv.handleUpdateAlertRule)
	mux.HandleFunc("DELETE /api/alert-rules/{id}", srv.handleDeleteAlertRule)
	mux.HandleFunc("POST /api/alert-rules/{id}/test", srv.handleTestAlertRule)
	mux.HandleFunc("GET /api/alert-projects", srv.handleListAlertProjects)
	mux.HandleFunc("PUT /api/alert-projects/{slug}", srv.handleSetAlertProjectChannels)
	mux.HandleFunc("GET /api/alert-events", srv.handleListProjectEvents)
	return &alertAPI{t: t, dbs: dbs, box: box, srv: srv, mux: mux, sender: sender}
}

func (a *alertAPI) call(method, path string, body any) (int, map[string]any, []byte) {
	a.t.Helper()
	var buf bytes.Buffer
	if body != nil {
		if s, ok := body.(string); ok {
			buf.WriteString(s)
		} else if err := json.NewEncoder(&buf).Encode(body); err != nil {
			a.t.Fatal(err)
		}
	}
	req := httptest.NewRequest(method, path, &buf)
	req = req.WithContext(context.WithValue(req.Context(), usernameKey, "tester"))
	rr := httptest.NewRecorder()
	a.mux.ServeHTTP(rr, req)
	var obj map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &obj)
	return rr.Code, obj, rr.Body.Bytes()
}

func (a *alertAPI) createSlack(name string) string {
	a.t.Helper()
	code, obj, raw := a.call("POST", "/api/alert-channels", map[string]any{
		"name": name, "kind": "slack", "slack_webhook": "https://hooks.example.com/services/T/B/secret",
		"digest_timezone": "Europe/Istanbul",
	})
	if code != http.StatusCreated {
		a.t.Fatalf("create channel: %d %s", code, raw)
	}
	return obj["id"].(string)
}

func TestAlertChannelAPIKeepsWebhookSecret(t *testing.T) {
	a := newAlertAPI(t)
	ctx := context.Background()
	id := a.createSlack("ops")

	_, list, raw := a.call("GET", "/api/alert-channels", nil)
	_ = list
	if strings.Contains(string(raw), "secret") || strings.Contains(string(raw), "hooks.example.com/services") {
		t.Fatalf("webhook leaked in list: %s", raw)
	}
	var channels []map[string]any
	_ = json.Unmarshal(raw, &channels)
	if len(channels) != 1 || channels[0]["has_webhook"] != true || channels[0]["webhook_host"] != "hooks.example.com" {
		t.Fatalf("channel view = %s", raw)
	}
	var stored string
	_ = a.dbs.Muvon.Pool.QueryRow(ctx, `SELECT slack_webhook FROM muvon.alert_channels WHERE id = $1::uuid`, id).Scan(&stored)
	if !secret.IsEncrypted(stored) {
		t.Fatal("webhook stored in plaintext")
	}

	// Editing without the webhook keeps it.
	if code, _, raw := a.call("PUT", "/api/alert-channels/"+id, map[string]any{"name": "ops-renamed", "enabled": true}); code != http.StatusOK {
		t.Fatalf("update: %d %s", code, raw)
	}
	var after string
	_ = a.dbs.Muvon.Pool.QueryRow(ctx, `SELECT slack_webhook FROM muvon.alert_channels WHERE id = $1::uuid`, id).Scan(&after)
	if after != stored {
		t.Fatal("an update without a webhook replaced the stored one")
	}

	if code, obj, _ := a.call("PUT", "/api/alert-channels/"+id, map[string]any{"name": "x", "kind": "email", "email_to": []string{"a@example.com"}}); code != http.StatusBadRequest || obj["field"] != "kind" {
		t.Fatalf("kind change = %d %v", code, obj)
	}
	a.createSlack("second")
	if code, _, _ := a.call("PUT", "/api/alert-channels/"+id, map[string]any{"name": "second"}); code != http.StatusConflict {
		t.Fatalf("duplicate name = %d, want 409", code)
	}
	if code, obj, _ := a.call("POST", "/api/alert-channels", map[string]any{"name": "mail", "kind": "email", "email_to": []string{"not-an-address"}}); code != http.StatusBadRequest || obj["field"] != "email_to" {
		t.Fatalf("bad recipient = %d %v", code, obj)
	}

	// The test sends with the decrypted webhook and reports failures as such.
	if code, _, raw := a.call("POST", "/api/alert-channels/"+id+"/test", nil); code != http.StatusOK {
		t.Fatalf("channel test: %d %s", code, raw)
	}
	if got := a.sender.channels[0].SlackWebhook; got != "https://hooks.example.com/services/T/B/secret" {
		t.Fatalf("sender got webhook %q", got)
	}
	a.sender.fail = errors.New("slack: status 404: no_service")
	if code, obj, _ := a.call("POST", "/api/alert-channels/"+id+"/test", nil); code != http.StatusBadGateway || !strings.Contains(obj["error"].(string), "no_service") {
		t.Fatalf("failing channel test = %d %v", code, obj)
	}
}

func validRuleBody(channelIDs ...string) map[string]any {
	return map[string]any{
		"name":      "Payment blocked",
		"project":   "shop",
		"component": "worker",
		"match": map[string]any{"any": []any{
			map[string]any{"events": []string{"PAYMENT_BLOCKED"}, "fields": []any{}},
		}},
		"tiers":          []any{map[string]any{"severity": "critical", "trigger": map[string]any{"type": "each"}}},
		"notify_fields":  []string{"order_id"},
		"delivery":       "instant",
		"remind_minutes": 240,
		"channel_ids":    channelIDs,
	}
}

func TestAlertRuleAPI(t *testing.T) {
	a := newAlertAPI(t)
	ctx := context.Background()

	for _, tc := range []struct {
		name   string
		mutate func(map[string]any)
		field  string
	}{
		{"unknown project", func(b map[string]any) { b["project"] = "ghost" }, "project"},
		{"unknown component", func(b map[string]any) { b["component"] = "ghost" }, "component"},
		{"unknown channel", func(b map[string]any) { b["channel_ids"] = []string{"0192a000-0000-7000-8000-000000000009"} }, "channel_ids"},
		{"bad tier order", func(b map[string]any) {
			b["tiers"] = []any{
				map[string]any{"severity": "critical", "trigger": map[string]any{"type": "each"}},
				map[string]any{"severity": "warning", "trigger": map[string]any{"type": "each"}},
			}
		}, "tiers[1].severity"},
	} {
		body := validRuleBody()
		tc.mutate(body)
		if code, obj, _ := a.call("POST", "/api/alert-rules", body); code != http.StatusBadRequest || obj["field"] != tc.field {
			t.Errorf("%s: %d %v, want 400 on %s", tc.name, code, obj, tc.field)
		}
	}
	if code, _, _ := a.call("POST", "/api/alert-rules", `{"name":"x","projekt":"shop"}`); code != http.StatusBadRequest {
		t.Errorf("unknown JSON field accepted with %d", code)
	}

	code, created, raw := a.call("POST", "/api/alert-rules", validRuleBody())
	if code != http.StatusCreated || created["project"] != "shop" || created["enabled"] != true {
		t.Fatalf("create: %d %s", code, raw)
	}
	ruleID := created["id"].(string)

	// Testing a rule that notifies nowhere is refused.
	if code, _, _ := a.call("POST", "/api/alert-rules/"+ruleID+"/test", nil); code != http.StatusBadRequest {
		t.Fatalf("test without channels = %d, want 400", code)
	}

	channelID := a.createSlack("shop-ops")
	if code, _, raw := a.call("PUT", "/api/alert-projects/shop", map[string]any{"channel_ids": []string{channelID}}); code != http.StatusOK {
		t.Fatalf("project channels: %d %s", code, raw)
	}
	_, _, raw = a.call("GET", "/api/alert-projects", nil)
	if !strings.Contains(string(raw), channelID) {
		t.Fatalf("project defaults not listed: %s", raw)
	}

	code, test, raw := a.call("POST", "/api/alert-rules/"+ruleID+"/test", nil)
	if code != http.StatusAccepted {
		t.Fatalf("rule test: %d %s", code, raw)
	}
	alertID := test["alert_id"].(string)
	code, detail, raw := a.call("GET", "/api/alerts/"+alertID, nil)
	if code != http.StatusOK || detail["is_test"] != true {
		t.Fatalf("test alert: %d %s", code, raw)
	}
	deliveries := detail["deliveries"].([]any)
	if len(deliveries) != 1 || deliveries[0].(map[string]any)["kind"] != "test" || deliveries[0].(map[string]any)["status"] != "pending" {
		t.Fatalf("test deliveries = %v", deliveries)
	}

	// Builtin rules: routing changes, identity does not, deletion is refused.
	var builtinID string
	_ = a.dbs.Muvon.Pool.QueryRow(ctx, `SELECT id::text FROM muvon.alert_rules WHERE builtin_key = 'auth_brute_force'`).Scan(&builtinID)
	code, updated, raw := a.call("PUT", "/api/alert-rules/"+builtinID, map[string]any{
		"name": "renamed", "enabled": true, "delivery": "digest", "remind_minutes": 0, "channel_ids": []string{channelID},
	})
	if code != http.StatusOK || updated["delivery"] != "digest" || updated["name"] == "renamed" {
		t.Fatalf("builtin update: %d %s", code, raw)
	}
	if code, _, _ := a.call("DELETE", "/api/alert-rules/"+builtinID, nil); code != http.StatusConflict {
		t.Fatalf("builtin delete = %d, want 409", code)
	}
	if code, _, _ := a.call("DELETE", "/api/alert-rules/"+ruleID, nil); code != http.StatusOK {
		t.Fatalf("event rule delete = %d", code)
	}

	// Deleting a channel removes its routes.
	if code, _, _ := a.call("DELETE", "/api/alert-channels/"+channelID, nil); code != http.StatusOK {
		t.Fatalf("channel delete = %d", code)
	}
	var routes int
	_ = a.dbs.Muvon.Pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM muvon.alert_rule_channels) + (SELECT count(*) FROM muvon.project_alert_channels)`).Scan(&routes)
	if routes != 0 {
		t.Fatalf("routes left after channel delete: %d", routes)
	}
}

func TestProjectEventDiscovery(t *testing.T) {
	a := newAlertAPI(t)
	p := logger.NewContainerPipeline(a.dbs.Dialog.Pool, 100, 1, 100, 10*time.Millisecond)
	defer p.Stop()
	entry := func(line string) logger.ContainerEntry {
		return logger.ContainerEntry{ContainerID: "c1", ContainerName: "shop-worker", Project: "shop", Component: "worker",
			Stream: "stdout", Line: line, Timestamp: time.Now()}
	}
	if err := p.SendBatch(context.Background(), []logger.ContainerEntry{
		entry(`{"event.name":"PAYMENT_BLOCKED","order_id":"1","reason":"card"}`),
		entry(`{"event.name":"PAYMENT_BLOCKED","order_id":"2"}`),
		entry(`{"event.name":"JOB_STUCK","job_id":"9"}`),
		entry(`{"level":"info","msg":"no event here"}`),
		entry(`plain text`),
	}); err != nil {
		t.Fatal(err)
	}

	code, _, raw := a.call("GET", "/api/alert-events?project=shop", nil)
	if code != http.StatusOK {
		t.Fatalf("events: %d %s", code, raw)
	}
	var events []map[string]any
	_ = json.Unmarshal(raw, &events)
	if len(events) != 2 || events[0]["name"] != "PAYMENT_BLOCKED" || events[0]["count"].(float64) != 2 {
		t.Fatalf("events = %s", raw)
	}
	fields := events[0]["fields"].([]any)
	if len(fields) != 2 || fields[0] != "order_id" || fields[1] != "reason" {
		t.Fatalf("fields = %v, want order_id and reason", fields)
	}
}
