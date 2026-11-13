package cli

import (
	"context"
	"flag"
	"net/http"
	"strings"

	"github.com/OJILab-dev/idp/cmd/idpctl/internal/adminapi"
)

// postLogoutRedirectURIRules is the admin API's post-logout redirect URI
// rule set (POST_LOGOUT_REDIRECT_URI_RULES in packages/clients/src), shortened for
// the flag help and the usage summary.
const postLogoutRedirectURIRules = "https, canonical form, matched exactly, at most 2000 printable ASCII characters; " +
	"no fragment, userinfo, '*', localhost or *.localhost host (trailing dot or not), " +
	"or state query parameter (the IdP appends state); at most 10, no duplicates"

// opFlags holds every operation-specific flag; each operation registers only
// the ones it names.
type opFlags struct {
	limit, cursor     string
	idTokenAlg        string
	client, principal string
	target, operation string
	since, until      string
	public            bool
	redirectURIs      stringList
	// postLogoutRedirectURIs are RP-Initiated Logout's registered return
	// addresses; empty leaves the admin API's default (none).
	postLogoutRedirectURIs stringList
	secretOut              string
}

type stringList []string

func (l *stringList) String() string     { return strings.Join(*l, ",") }
func (l *stringList) Set(v string) error { *l = append(*l, v); return nil }

// response is what every generated *Response type offers.
type response interface {
	GetBody() []byte
	StatusCode() int
	ContentType() string
}

// operation is one subcommand, named exactly as the admin API operation.
type operation struct {
	name     string
	synopsis string
	summary  string
	// args is the exact number of positional arguments, or the minimum
	// when variadic is set.
	args     int
	variadic bool
	flags    []string
	// secret names the response member that holds an IdP-issued secret, or
	// returns "" when the response carries none.
	secret func(f *opFlags) string
	send   func(ctx context.Context, c *call, a []string, f *opFlags) (response, error)
}

func registerFlags(fs *flag.FlagSet, names []string, f *opFlags) {
	for _, name := range names {
		switch name {
		case "limit":
			fs.StringVar(&f.limit, "limit", "", "page size; the admin API defaults to 50 and caps it at 200")
		case "cursor":
			fs.StringVar(&f.cursor, "cursor", "", "opaque next_cursor or prev_cursor from a previous page")
		case "id-token-alg":
			fs.StringVar(&f.idTokenAlg, "id-token-alg", "", "ID token signing algorithm: Ed25519 or RS256")
		case "client":
			fs.StringVar(&f.client, "client", "", "only grants for this client_id")
		case "principal":
			fs.StringVar(&f.principal, "principal", "", "only grants for this principal (user:<id> or group:<id>)")
		case "target":
			fs.StringVar(&f.target, "target", "", "only events for this target (user:<id>, client:<id>, group:<id>, schema, none)")
		case "operation":
			fs.StringVar(&f.operation, "operation", "", "only events of this operation name")
		case "since":
			fs.StringVar(&f.since, "since", "", "only events at or after this UNIX time")
		case "until":
			fs.StringVar(&f.until, "until", "", "only events before this UNIX time")
		case "public":
			fs.BoolVar(&f.public, "public", false, "register a public client (no client secret)")
		case "redirect-uri":
			fs.Var(&f.redirectURIs, "redirect-uri", "redirect URI; repeat for several")
		case "post-logout-redirect-uri":
			fs.Var(&f.postLogoutRedirectURIs, "post-logout-redirect-uri", "URI to return to after RP-Initiated Logout ("+postLogoutRedirectURIRules+"); repeat for several")
		case "secret-out":
			fs.StringVar(&f.secretOut, "secret-out", "", "new file (mode 0600) that receives the IdP-issued secret")
		}
	}
}

var pageFlags = []string{"limit", "cursor"}

func noSecret(*opFlags) string { return "" }

func secretMember(member string) func(*opFlags) string {
	return func(*opFlags) string { return member }
}

func optional(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// query adds name/value pairs whose value is set. Integer-or-string
// parameters (limit, since, until) go through here because the generator
// models their union type with an unexported field that cannot be set.
func query(pairs ...string) adminapi.RequestEditorFn {
	return func(_ context.Context, req *http.Request) error {
		q := req.URL.Query()
		for i := 0; i+1 < len(pairs); i += 2 {
			if pairs[i+1] != "" {
				q.Set(pairs[i], pairs[i+1])
			}
		}
		req.URL.RawQuery = q.Encode()
		return nil
	}
}

func done[R response](r R, err error) (response, error) {
	if err != nil {
		return nil, err
	}
	return r, nil
}

func enablement(value string) adminapi.UserEnablementSwitchJSONBodyEnablement {
	return adminapi.UserEnablementSwitchJSONBodyEnablement(value)
}

// operations lists the 30 operations of idpctl.md in its order.
var operations = []operation{
	{
		name: "users_list", summary: "List users.", flags: pageFlags, secret: noSecret,
		send: func(ctx context.Context, c *call, _ []string, f *opFlags) (response, error) {
			return done(c.api.UsersListWithResponse(ctx, &adminapi.UsersListParams{Cursor: optional(f.cursor)}, query("limit", f.limit)))
		},
	},
	{
		name: "user_get", synopsis: "<user_id>", summary: "Show a user and their passkeys.", args: 1, secret: noSecret,
		send: func(ctx context.Context, c *call, a []string, _ *opFlags) (response, error) {
			return done(c.api.UserGetWithResponse(ctx, a[0]))
		},
	},
	{
		name: "clients_list", summary: "List clients.", flags: append([]string{"id-token-alg"}, pageFlags...), secret: noSecret,
		send: func(ctx context.Context, c *call, _ []string, f *opFlags) (response, error) {
			params := &adminapi.ClientsListParams{Cursor: optional(f.cursor)}
			if f.idTokenAlg != "" {
				alg := adminapi.ClientsListParamsIdTokenAlg(f.idTokenAlg)
				params.IdTokenAlg = &alg
			}
			return done(c.api.ClientsListWithResponse(ctx, params, query("limit", f.limit)))
		},
	},
	{
		name: "groups_list", summary: "List groups with their members and clients.", flags: pageFlags, secret: noSecret,
		send: func(ctx context.Context, c *call, _ []string, f *opFlags) (response, error) {
			return done(c.api.GroupsListWithResponse(ctx, &adminapi.GroupsListParams{Cursor: optional(f.cursor)}, query("limit", f.limit)))
		},
	},
	{
		name: "grants_list", summary: "List grants.", flags: append([]string{"client", "principal"}, pageFlags...), secret: noSecret,
		send: func(ctx context.Context, c *call, _ []string, f *opFlags) (response, error) {
			params := &adminapi.GrantsListParams{Cursor: optional(f.cursor), ClientId: optional(f.client), Principal: optional(f.principal)}
			return done(c.api.GrantsListWithResponse(ctx, params, query("limit", f.limit)))
		},
	},
	{
		name: "access_check", synopsis: "<user_id> <client_id>", summary: "Explain whether a user may sign in to a client.", args: 2, secret: noSecret,
		send: func(ctx context.Context, c *call, a []string, _ *opFlags) (response, error) {
			return done(c.api.AccessCheckWithResponse(ctx, &adminapi.AccessCheckParams{User: a[0], Client: a[1]}))
		},
	},
	{
		name: "audit_tail", summary: "Show audit events, newest first.",
		flags:  append([]string{"target", "operation", "since", "until"}, pageFlags...),
		secret: noSecret,
		send: func(ctx context.Context, c *call, _ []string, f *opFlags) (response, error) {
			params := &adminapi.AuditTailParams{Cursor: optional(f.cursor), Target: optional(f.target), Operation: optional(f.operation)}
			return done(c.api.AuditTailWithResponse(ctx, params, query("limit", f.limit, "since", f.since, "until", f.until)))
		},
	},
	{
		name: "user_create", synopsis: "<name>", summary: "Create a user.", args: 1, secret: noSecret,
		send: func(ctx context.Context, c *call, a []string, _ *opFlags) (response, error) {
			return done(c.api.UserCreateWithResponse(ctx, &adminapi.UserCreateParams{IdempotencyKey: c.key}, adminapi.UserCreateJSONRequestBody{Name: a[0]}))
		},
	},
	{
		name: "user_rename", synopsis: "<user_id> <name>", summary: "Change a user's display name.", args: 2, secret: noSecret,
		send: func(ctx context.Context, c *call, a []string, _ *opFlags) (response, error) {
			return done(c.api.UserRenameWithResponse(ctx, a[0], adminapi.UserRenameJSONRequestBody{Name: a[1]}))
		},
	},
	{
		name: "user_disable", synopsis: "<user_id>", summary: "Disable a user and end their sessions.", args: 1, secret: noSecret,
		send: func(ctx context.Context, c *call, a []string, _ *opFlags) (response, error) {
			return done(c.api.UserEnablementSwitchWithResponse(ctx, a[0], &adminapi.UserEnablementSwitchParams{IdempotencyKey: c.key},
				adminapi.UserEnablementSwitchJSONRequestBody{Enablement: enablement("disabled")}))
		},
	},
	{
		name: "user_enable", synopsis: "<user_id>", summary: "Enable a user.", args: 1, secret: noSecret,
		send: func(ctx context.Context, c *call, a []string, _ *opFlags) (response, error) {
			return done(c.api.UserEnablementSwitchWithResponse(ctx, a[0], &adminapi.UserEnablementSwitchParams{IdempotencyKey: c.key},
				adminapi.UserEnablementSwitchJSONRequestBody{Enablement: enablement("enabled")}))
		},
	},
	{
		name: "enroll_link_issue", synopsis: "<user_id>", summary: "Issue a 10-minute enrollment link; it is written to --secret-out.",
		args: 1, flags: []string{"secret-out"}, secret: secretMember("enrollment_link"),
		send: func(ctx context.Context, c *call, a []string, _ *opFlags) (response, error) {
			return done(c.api.EnrollLinkIssueWithResponse(ctx, a[0], &adminapi.EnrollLinkIssueParams{IdempotencyKey: c.key}))
		},
	},
	{
		name: "passkey_revoke", synopsis: "<user_id> <credential_id>", summary: "Revoke one passkey (never the last one).", args: 2, secret: noSecret,
		send: func(ctx context.Context, c *call, a []string, _ *opFlags) (response, error) {
			return done(c.api.PasskeyRevokeWithResponse(ctx, a[0], a[1]))
		},
	},
	{
		name: "session_revoke", synopsis: "<user_id>", summary: "End all of a user's sessions.", args: 1, secret: noSecret,
		send: func(ctx context.Context, c *call, a []string, _ *opFlags) (response, error) {
			return done(c.api.SessionRevokeWithResponse(ctx, a[0]))
		},
	},
	{
		name: "group_create", synopsis: "<name>", summary: "Create a group.", args: 1, secret: noSecret,
		send: func(ctx context.Context, c *call, a []string, _ *opFlags) (response, error) {
			return done(c.api.GroupCreateWithResponse(ctx, &adminapi.GroupCreateParams{IdempotencyKey: c.key}, adminapi.GroupCreateJSONRequestBody{Name: a[0]}))
		},
	},
	{
		name: "group_rename", synopsis: "<group_id> <name>", summary: "Change a group's name.", args: 2, secret: noSecret,
		send: func(ctx context.Context, c *call, a []string, _ *opFlags) (response, error) {
			return done(c.api.GroupRenameWithResponse(ctx, a[0], adminapi.GroupRenameJSONRequestBody{Name: a[1]}))
		},
	},
	{
		name: "group_disable", synopsis: "<group_id>", summary: "Disable a group; its grants stop applying.", args: 1, secret: noSecret,
		send: func(ctx context.Context, c *call, a []string, _ *opFlags) (response, error) {
			return done(c.api.GroupEnablementSwitchWithResponse(ctx, a[0], &adminapi.GroupEnablementSwitchParams{IdempotencyKey: c.key},
				adminapi.GroupEnablementSwitchJSONRequestBody{Enablement: adminapi.GroupEnablementSwitchJSONBodyEnablement("disabled")}))
		},
	},
	{
		name: "group_enable", synopsis: "<group_id>", summary: "Enable a group.", args: 1, secret: noSecret,
		send: func(ctx context.Context, c *call, a []string, _ *opFlags) (response, error) {
			return done(c.api.GroupEnablementSwitchWithResponse(ctx, a[0], &adminapi.GroupEnablementSwitchParams{IdempotencyKey: c.key},
				adminapi.GroupEnablementSwitchJSONRequestBody{Enablement: adminapi.GroupEnablementSwitchJSONBodyEnablement("enabled")}))
		},
	},
	{
		name: "group_member_add", synopsis: "<group_id> <user_id>", summary: "Add a user to a group.", args: 2, secret: noSecret,
		send: func(ctx context.Context, c *call, a []string, _ *opFlags) (response, error) {
			return done(c.api.GroupMemberAddWithResponse(ctx, a[0], a[1]))
		},
	},
	{
		name: "group_member_remove", synopsis: "<group_id> <user_id>", summary: "Remove a user from a group.", args: 2, secret: noSecret,
		send: func(ctx context.Context, c *call, a []string, _ *opFlags) (response, error) {
			return done(c.api.GroupMemberRemoveWithResponse(ctx, a[0], a[1]))
		},
	},
	{
		name: "client_create", synopsis: "<client_id> <name>",
		summary: "Register a client; a confidential client's secret is written to --secret-out.",
		args:    2, flags: []string{"public", "redirect-uri", "post-logout-redirect-uri", "id-token-alg", "secret-out"},
		secret: func(f *opFlags) string {
			if f.public {
				return ""
			}
			return "client_secret"
		},
		send: func(ctx context.Context, c *call, a []string, f *opFlags) (response, error) {
			body := adminapi.ClientCreateJSONRequestBody{
				ClientId:     a[0],
				Name:         a[1],
				ClientType:   adminapi.ClientCreateJSONBodyClientType("confidential"),
				RedirectUris: append([]string{}, f.redirectURIs...),
			}
			if f.public {
				body.ClientType = adminapi.ClientCreateJSONBodyClientType("public")
			}
			if f.idTokenAlg != "" {
				alg := adminapi.ClientCreateJSONBodyIdTokenAlg(f.idTokenAlg)
				body.IdTokenAlg = &alg
			}
			if len(f.postLogoutRedirectURIs) > 0 {
				uris := append([]string{}, f.postLogoutRedirectURIs...)
				body.PostLogoutRedirectUris = &uris
			}
			return done(c.api.ClientCreateWithResponse(ctx, &adminapi.ClientCreateParams{IdempotencyKey: c.key}, body))
		},
	},
	{
		name: "client_rename", synopsis: "<client_id> <name>", summary: "Change a client's display name.", args: 2, secret: noSecret,
		send: func(ctx context.Context, c *call, a []string, _ *opFlags) (response, error) {
			return done(c.api.ClientRenameWithResponse(ctx, a[0], adminapi.ClientRenameJSONRequestBody{Name: a[1]}))
		},
	},
	{
		name: "client_set_redirects", synopsis: "<client_id> <redirect_uri>...", summary: "Replace a client's redirect URIs.",
		args: 2, variadic: true, secret: noSecret,
		send: func(ctx context.Context, c *call, a []string, _ *opFlags) (response, error) {
			return done(c.api.ClientSetRedirectsWithResponse(ctx, a[0], adminapi.ClientSetRedirectsJSONRequestBody{RedirectUris: a[1:]}))
		},
	},
	{
		name: "client_set_post_logout_redirects", synopsis: "<client_id> [<post_logout_redirect_uri>...]",
		summary: "Replace a client's RP-Initiated Logout redirect URIs (" + postLogoutRedirectURIRules + "); none clears them.",
		args:    1, variadic: true, secret: noSecret,
		send: func(ctx context.Context, c *call, a []string, _ *opFlags) (response, error) {
			// A copy, so an empty list is sent as [] rather than null.
			uris := append([]string{}, a[1:]...)
			return done(c.api.ClientSetPostLogoutRedirectsWithResponse(ctx, a[0],
				adminapi.ClientSetPostLogoutRedirectsJSONRequestBody{PostLogoutRedirectUris: uris}))
		},
	},
	{
		name: "client_rotate_secret", synopsis: "<client_id>", summary: "Replace a confidential client's secret; it is written to --secret-out.",
		args: 1, flags: []string{"secret-out"}, secret: secretMember("client_secret"),
		send: func(ctx context.Context, c *call, a []string, _ *opFlags) (response, error) {
			return done(c.api.ClientRotateSecretWithResponse(ctx, a[0], &adminapi.ClientRotateSecretParams{IdempotencyKey: c.key}))
		},
	},
	{
		name: "client_set_id_token_alg", synopsis: "<client_id> <Ed25519|RS256>", summary: "Change a client's ID token signing algorithm.",
		args: 2, secret: noSecret,
		send: func(ctx context.Context, c *call, a []string, _ *opFlags) (response, error) {
			return done(c.api.ClientSetIdTokenAlgWithResponse(ctx, a[0],
				adminapi.ClientSetIdTokenAlgJSONRequestBody{IdTokenAlg: adminapi.ClientSetIdTokenAlgJSONBodyIdTokenAlg(a[1])}))
		},
	},
	{
		name: "client_disable", synopsis: "<client_id>", summary: "Disable a client.", args: 1, secret: noSecret,
		send: func(ctx context.Context, c *call, a []string, _ *opFlags) (response, error) {
			return done(c.api.ClientEnablementSwitchWithResponse(ctx, a[0], &adminapi.ClientEnablementSwitchParams{IdempotencyKey: c.key},
				adminapi.ClientEnablementSwitchJSONRequestBody{Enablement: adminapi.ClientEnablementSwitchJSONBodyEnablement("disabled")}))
		},
	},
	{
		name: "client_enable", synopsis: "<client_id>", summary: "Enable a client.", args: 1, secret: noSecret,
		send: func(ctx context.Context, c *call, a []string, _ *opFlags) (response, error) {
			return done(c.api.ClientEnablementSwitchWithResponse(ctx, a[0], &adminapi.ClientEnablementSwitchParams{IdempotencyKey: c.key},
				adminapi.ClientEnablementSwitchJSONRequestBody{Enablement: adminapi.ClientEnablementSwitchJSONBodyEnablement("enabled")}))
		},
	},
	{
		name: "grant_add", synopsis: "<user:<id>|group:<id>> <client_id>", summary: "Let a user or group use a client.", args: 2, secret: noSecret,
		send: func(ctx context.Context, c *call, a []string, _ *opFlags) (response, error) {
			return done(c.api.GrantAddWithResponse(ctx, a[1], a[0]))
		},
	},
	{
		name: "grant_remove", synopsis: "<user:<id>|group:<id>> <client_id>", summary: "Remove a grant.", args: 2, secret: noSecret,
		send: func(ctx context.Context, c *call, a []string, _ *opFlags) (response, error) {
			return done(c.api.GrantRemoveWithResponse(ctx, a[1], a[0]))
		},
	},
}

func lookup(name string) *operation {
	for i := range operations {
		if operations[i].name == name {
			return &operations[i]
		}
	}
	return nil
}

// Operations returns the subcommand names, which are exactly the admin API
// operation names of idpctl.md.
func Operations() []string {
	names := make([]string, len(operations))
	for i, op := range operations {
		names[i] = op.name
	}
	return names
}
