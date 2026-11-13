package cli_test

import (
	"encoding/json"
	"net/http"
	"os"
	"reflect"
	"regexp"
	"slices"
	"testing"

	"github.com/OJILab-dev/idp/cmd/idpctl/internal/cli"
)

var idempotencyKeyShape = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)

const emptyPage = `{"items":[],"next_cursor":null,"prev_cursor":null}`

type operationCase struct {
	args       []string
	method     string
	path       string
	query      map[string][]string
	body       string // JSON; empty means no body
	idempotent bool   // whether the request must carry an Idempotency-Key
	status     int
	response   string
}

// operationCases covers every non-secret operation with arguments shaped like
// idpctl.md's examples and responses shaped like the spec's success schemas.
var operationCases = map[string]operationCase{
	"users_list": {
		args:   []string{"users_list", "--limit", "20", "--cursor", "eyJkIjoibmV4dCJ9"},
		method: http.MethodGet, path: "/v1/users",
		query:  map[string][]string{"limit": {"20"}, "cursor": {"eyJkIjoibmV4dCJ9"}},
		status: 200,
		response: `{"items":[{"user_id":"` + userID + `","name":"Alice","enablement":"enabled","created_at":1700000000,"passkey_count":2}],` +
			`"next_cursor":"eyJkIjoibmV4dCJ9","prev_cursor":null}`,
	},
	"user_create": {
		args:   []string{"user_create", "Alice"},
		method: http.MethodPost, path: "/v1/users",
		body: `{"name":"Alice"}`, idempotent: true,
		status: 201, response: `{"user_id":"` + userID + `"}`,
	},
	"user_get": {
		args:   []string{"user_get", userID},
		method: http.MethodGet, path: "/v1/users/" + userID,
		status: 200,
		response: `{"user_id":"` + userID + `","name":"Alice","enablement":"enabled","created_at":1700000000,"passkeys":[` +
			`{"credential_id":"Y3JlZA","created_at":1700000000,"last_used_at":null,"created_via":"enroll","backup_eligible":true,"backup_state":true}]}`,
	},
	"user_rename": {
		args:   []string{"user_rename", userID, "Alice Smith"},
		method: http.MethodPut, path: "/v1/users/" + userID + "/name",
		body:   `{"name":"Alice Smith"}`,
		status: 200, response: `{"user_id":"` + userID + `","name":"Alice Smith"}`,
	},
	"user_disable": {
		args:   []string{"user_disable", userID},
		method: http.MethodPost, path: "/v1/users/" + userID + "/enablement-events",
		body: `{"enablement":"disabled"}`, idempotent: true,
		status: 201, response: `{"id":"` + userID + `","enablement":"disabled","occurred_at":1700000000}`,
	},
	"user_enable": {
		args:   []string{"user_enable", userID},
		method: http.MethodPost, path: "/v1/users/" + userID + "/enablement-events",
		body: `{"enablement":"enabled"}`, idempotent: true,
		status: 201, response: `{"id":"` + userID + `","enablement":"enabled","occurred_at":1700000000}`,
	},
	"passkey_revoke": {
		args:   []string{"passkey_revoke", userID, "Y3JlZA"},
		method: http.MethodDelete, path: "/v1/users/" + userID + "/passkeys/Y3JlZA",
		status: 200, response: `{"user_id":"` + userID + `","credential_id":"Y3JlZA"}`,
	},
	"session_revoke": {
		args:   []string{"session_revoke", userID},
		method: http.MethodDelete, path: "/v1/users/" + userID + "/sessions",
		status: 200, response: `{"user_id":"` + userID + `","sessions_deleted":3}`,
	},
	"group_create": {
		args:   []string{"group_create", "family"},
		method: http.MethodPost, path: "/v1/groups",
		body: `{"name":"family"}`, idempotent: true,
		status: 201, response: `{"group_id":"` + groupID + `"}`,
	},
	"group_rename": {
		args:   []string{"group_rename", groupID, "relatives"},
		method: http.MethodPut, path: "/v1/groups/" + groupID + "/name",
		body:   `{"name":"relatives"}`,
		status: 200, response: `{"group_id":"` + groupID + `","name":"relatives"}`,
	},
	"group_disable": {
		args:   []string{"group_disable", groupID},
		method: http.MethodPost, path: "/v1/groups/" + groupID + "/enablement-events",
		body: `{"enablement":"disabled"}`, idempotent: true,
		status: 201, response: `{"id":"` + groupID + `","enablement":"disabled","occurred_at":1700000000}`,
	},
	"group_enable": {
		args:   []string{"group_enable", groupID},
		method: http.MethodPost, path: "/v1/groups/" + groupID + "/enablement-events",
		body: `{"enablement":"enabled"}`, idempotent: true,
		status: 201, response: `{"id":"` + groupID + `","enablement":"enabled","occurred_at":1700000000}`,
	},
	"group_member_add": {
		args:   []string{"group_member_add", groupID, userID},
		method: http.MethodPut, path: "/v1/groups/" + groupID + "/members/" + userID,
		status:   200,
		response: `{"group_id":"` + groupID + `","user_id":"` + userID + `","newly_enabled":[{"user_id":"` + userID + `","client_id":"grafana"}]}`,
	},
	"group_member_remove": {
		args:   []string{"group_member_remove", groupID, userID},
		method: http.MethodDelete, path: "/v1/groups/" + groupID + "/members/" + userID,
		status: 200, response: `{"group_id":"` + groupID + `","user_id":"` + userID + `"}`,
	},
	"groups_list": {
		args:   []string{"groups_list"},
		method: http.MethodGet, path: "/v1/groups",
		query:  map[string][]string{},
		status: 200,
		response: `{"items":[{"group_id":"` + groupID + `","name":"family","enablement":"enabled","created_at":1700000000,"members":["` + userID + `"],"clients":["grafana"]}],` +
			`"next_cursor":null,"prev_cursor":null}`,
	},
	"clients_list": {
		args:   []string{"clients_list", "--id-token-alg", "RS256"},
		method: http.MethodGet, path: "/v1/clients",
		query:  map[string][]string{"id_token_alg": {"RS256"}},
		status: 200,
		response: `{"items":[{"client_id":"grafana","name":"Grafana","client_type":"confidential","enablement":"enabled",` +
			`"redirect_uris":["https://grafana.example/login/generic_oauth"],"id_token_alg":"RS256","created_at":1700000000}],"next_cursor":null,"prev_cursor":null}`,
	},
	"client_create": {
		args:   []string{"client_create", "cli", "Command line", "--public", "--redirect-uri", "http://127.0.0.1/callback"},
		method: http.MethodPost, path: "/v1/clients",
		body:       `{"client_id":"cli","name":"Command line","client_type":"public","redirect_uris":["http://127.0.0.1/callback"]}`,
		idempotent: true,
		status:     201, response: `{"client_id":"cli","client_type":"public"}`,
	},
	"client_rename": {
		args:   []string{"client_rename", "grafana", "Grafana dashboards"},
		method: http.MethodPut, path: "/v1/clients/grafana/name",
		body:   `{"name":"Grafana dashboards"}`,
		status: 200, response: `{"client_id":"grafana","name":"Grafana dashboards"}`,
	},
	"client_set_redirects": {
		args:   []string{"client_set_redirects", "grafana", "https://a.example/cb", "https://b.example/cb"},
		method: http.MethodPut, path: "/v1/clients/grafana/redirect-uris",
		body:   `{"redirect_uris":["https://a.example/cb","https://b.example/cb"]}`,
		status: 200, response: `{"client_id":"grafana","redirect_uris":["https://a.example/cb","https://b.example/cb"]}`,
	},
	"client_set_post_logout_redirects": {
		args:   []string{"client_set_post_logout_redirects", "grafana", "https://a.example/bye", "https://b.example/bye"},
		method: http.MethodPut, path: "/v1/clients/grafana/post-logout-redirect-uris",
		body:   `{"post_logout_redirect_uris":["https://a.example/bye","https://b.example/bye"]}`,
		status: 200, response: `{"client_id":"grafana","post_logout_redirect_uris":["https://a.example/bye","https://b.example/bye"]}`,
	},
	// Without URIs the list is cleared, which stops post-logout redirects: the body carries [], never null.
	"client_set_post_logout_redirects_clear": {
		args:   []string{"client_set_post_logout_redirects", "grafana"},
		method: http.MethodPut, path: "/v1/clients/grafana/post-logout-redirect-uris",
		body:   `{"post_logout_redirect_uris":[]}`,
		status: 200, response: `{"client_id":"grafana","post_logout_redirect_uris":[]}`,
	},
	"client_create_post_logout": {
		args: []string{"client_create", "cli", "Command line", "--public", "--redirect-uri", "http://127.0.0.1/callback",
			"--post-logout-redirect-uri", "https://cli.example/bye", "--post-logout-redirect-uri", "https://cli.example/bye2"},
		method: http.MethodPost, path: "/v1/clients",
		body: `{"client_id":"cli","name":"Command line","client_type":"public","redirect_uris":["http://127.0.0.1/callback"],` +
			`"post_logout_redirect_uris":["https://cli.example/bye","https://cli.example/bye2"]}`,
		idempotent: true,
		status:     201, response: `{"client_id":"cli","client_type":"public"}`,
	},
	"client_set_id_token_alg": {
		args:   []string{"client_set_id_token_alg", "grafana", "RS256"},
		method: http.MethodPut, path: "/v1/clients/grafana/id-token-alg",
		body:   `{"id_token_alg":"RS256"}`,
		status: 200, response: `{"client_id":"grafana","id_token_alg":"RS256"}`,
	},
	"client_disable": {
		args:   []string{"client_disable", "grafana"},
		method: http.MethodPost, path: "/v1/clients/grafana/enablement-events",
		body: `{"enablement":"disabled"}`, idempotent: true,
		status: 201, response: `{"id":"grafana","enablement":"disabled","occurred_at":1700000000}`,
	},
	"client_enable": {
		args:   []string{"client_enable", "grafana"},
		method: http.MethodPost, path: "/v1/clients/grafana/enablement-events",
		body: `{"enablement":"enabled"}`, idempotent: true,
		status: 201, response: `{"id":"grafana","enablement":"enabled","occurred_at":1700000000}`,
	},
	"grant_add": {
		args:   []string{"grant_add", "group:" + groupID, "grafana"},
		method: http.MethodPut, path: "/v1/clients/grafana/grants/group:" + groupID,
		status:   200,
		response: `{"client_id":"grafana","principal":"group:` + groupID + `","newly_enabled":[{"user_id":"` + userID + `","client_id":"grafana"}]}`,
	},
	"grant_remove": {
		args:   []string{"grant_remove", "user:" + userID, "grafana"},
		method: http.MethodDelete, path: "/v1/clients/grafana/grants/user:" + userID,
		status: 200, response: `{"client_id":"grafana","principal":"user:` + userID + `"}`,
	},
	"grants_list": {
		args:   []string{"grants_list", "--client", "grafana", "--principal", "user:" + userID, "--limit", "5"},
		method: http.MethodGet, path: "/v1/grants",
		query:  map[string][]string{"client_id": {"grafana"}, "principal": {"user:" + userID}, "limit": {"5"}},
		status: 200,
		response: `{"items":[{"principal":"user:` + userID + `","client_id":"grafana","created_at":1700000000}],` +
			`"next_cursor":null,"prev_cursor":"eyJkIjoicHJldiJ9"}`,
	},
	"access_check": {
		args:   []string{"access_check", userID, "grafana"},
		method: http.MethodGet, path: "/v1/access",
		query:  map[string][]string{"user": {userID}, "client": {"grafana"}},
		status: 200,
		response: `{"user_id":"` + userID + `","client_id":"grafana","allowed":true,"user_enablement":"enabled","client_enablement":"enabled",` +
			`"grants":[{"via":"group","principal":"group:` + groupID + `","group_enablement":"enabled","counts":true}],"denied_because":[]}`,
	},
	"audit_tail": {
		args: []string{"audit_tail", "--target", "user:" + userID, "--operation", "user_create",
			"--since", "1700000000", "--until", "1700003600", "--limit", "10", "--cursor", "eyJkIjoibmV4dCJ9"},
		method: http.MethodGet, path: "/v1/audit-events",
		query: map[string][]string{
			"target": {"user:" + userID}, "operation": {"user_create"},
			"since": {"1700000000"}, "until": {"1700003600"}, "limit": {"10"}, "cursor": {"eyJkIjoibmV4dCJ9"},
		},
		status: 200,
		response: `{"items":[{"id":7,"occurred_at":1700000100,"actor":"admin","admin_name":"alice","admin_cert_sha256":"` +
			`0000000000000000000000000000000000000000000000000000000000000000","writer_version":"admin-worker@v1","operation":"user_create",` +
			`"target":"user:` + userID + `","result":"success","detail":{}}],"next_cursor":null,"prev_cursor":null}`,
	},
}

func TestEveryOperationSendsTheSpecifiedRequest(t *testing.T) {
	for name, tc := range operationCases {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t, fixed(tc.status, tc.response))
			got := h.run(tc.args...)
			if got.code != 0 {
				t.Fatalf("exit %d, stderr:\n%s", got.code, got.stderr)
			}
			requests := h.seen()
			if len(requests) != 1 {
				t.Fatalf("%d requests, want 1", len(requests))
			}
			r := requests[0]
			if r.Method != tc.method || r.Path != tc.path {
				t.Errorf("request %s %s, want %s %s", r.Method, r.Path, tc.method, tc.path)
			}
			if tc.query == nil {
				tc.query = map[string][]string{}
			}
			if !reflect.DeepEqual(r.Query, tc.query) {
				t.Errorf("query %v, want %v", r.Query, tc.query)
			}
			if tc.body == "" {
				if len(r.Body) != 0 {
					t.Errorf("unexpected body %q", r.Body)
				}
			} else {
				if ct := r.Header.Get("Content-Type"); ct != "application/json" {
					t.Errorf("Content-Type %q", ct)
				}
				if !jsonEqual(t, r.Body, []byte(tc.body)) {
					t.Errorf("body %s, want %s", r.Body, tc.body)
				}
			}
			key := r.Header.Get("Idempotency-Key")
			if tc.idempotent != (key != "") {
				t.Errorf("Idempotency-Key %q, idempotent write %v", key, tc.idempotent)
			}
			if tc.idempotent && !idempotencyKeyShape.MatchString(key) {
				t.Errorf("Idempotency-Key %q does not match the contract", key)
			}
			if !jsonEqual(t, []byte(got.stdout), []byte(tc.response)) {
				t.Errorf("stdout %s, want %s", got.stdout, tc.response)
			}
		})
	}
}

// TestOperationsMatchTheSpec keeps the subcommands equal to the operation
// names the spec lists in x-operation-names, so adding an operation to the
// admin API without a subcommand fails here.
func TestOperationsMatchTheSpec(t *testing.T) {
	spec := readSpec(t)
	var want []string
	for _, item := range spec.Paths {
		for _, op := range item {
			want = append(want, op.OperationNames...)
		}
	}
	slices.Sort(want)
	got := slices.Sorted(slices.Values(cli.Operations()))
	if !slices.Equal(got, want) {
		t.Fatalf("operations\n got %v\nwant %v", got, want)
	}
	if len(got) != 30 {
		t.Fatalf("%d operations, idpctl.md lists 30", len(got))
	}
	for _, name := range got {
		if _, ok := operationCases[name]; !ok && !slices.Contains([]string{"client_rotate_secret", "enroll_link_issue"}, name) {
			t.Errorf("operation %s has no request test", name)
		}
	}
}

type specDocument struct {
	Paths map[string]map[string]struct {
		OperationNames []string `json:"x-operation-names"`
	} `json:"paths"`
	Components struct {
		Schemas struct {
			Problem struct {
				Properties struct {
					Type struct {
						Enum []string `json:"enum"`
					} `json:"type"`
				} `json:"properties"`
			} `json:"Problem"`
		} `json:"schemas"`
	} `json:"components"`
}

func readSpec(t *testing.T) specDocument {
	t.Helper()
	raw, err := os.ReadFile("../../../../contract/openapi/admin.json")
	if err != nil {
		t.Fatal(err)
	}
	var spec specDocument
	if err := json.Unmarshal(raw, &spec); err != nil {
		t.Fatal(err)
	}
	return spec
}
