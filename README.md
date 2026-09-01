# AgentAdmit SDK for Ruby (Rails)

User-mediated AI agent authorization. Plug-and-play for any Rails app.

> **Get started:** Sign up at [agentadmit.com](https://agentadmit.com) -- Get your test keys -- Install the SDK -- Build.
> Test keys are available immediately after signup. Live keys become available when you subscribe an app.

## Quick Start

```ruby
# Gemfile
gem 'agentadmit'
```

```bash
bundle install
```

Add your credentials to `config/credentials.yml.enc` or `.env`:

```env
AGENTADMIT_APP_ID=app_yourappid
AGENTADMIT_API_KEY=aa_test_yourkey
```

Create an initializer at `config/initializers/agentadmit.rb`:

```ruby
AgentAdmit.configure do |config|
  # Defaults are read from ENV - nothing required here unless you need overrides.
end
```

Add scope enforcement to any controller:

```ruby
class OrdersController < ApplicationController
  before_action -> { require_scope_if_agent!('read:orders') }

  def index
    render json: current_user.orders
  end
end
```

The `require_scope_if_agent!` method is available in all controllers automatically
when you use Rails -- the Railtie includes `AgentAdmit::ScopeEnforcement` into
`ActionController::Base` on load.

Your app now supports AI agent connections with:
- Scoped access control (you define the scopes)
- User-controlled connection duration
- Token generation and exchange
- Mandatory introspection (every agent request validated through AgentAdmit)
- Revocation support via `tokens.revoke`

## How It Works

1. User clicks "AgentAdmit" in your app
2. Selects scopes and connection duration
3. Gets a token to give to their AI agent
4. Agent exchanges the token for scoped API access
5. User revokes anytime

The token goes to the human, not the agent. No automated delivery = no prompt injection surface.

## Important

**Mandatory introspection.** All token validation goes through api.agentadmit.com. There is no self-hosted mode. No local JWT validation. No bypass. This is required for security, audit logging, and scope enforcement.

**Embeddable admin panel.** Drop the `<AgentAdmitAdminPanel>` React component into your admin section to view all agent connections, usage metrics, billing status, and revoke any connection without leaving your app. See the React SDK for details.

**In-app AI scopes.** If your app has built-in AI features (analysis, plan generation, photo recognition), do not expose those as agent scopes. The user's AI agent can read the raw data and do the analysis itself. Exposing in-app AI endpoints to agents creates double cost.

### Consent Ledger (Caller-Identity Consent)

AgentAdmit can host per-user consent switches for three independent caller classes: `human_session`, `in_app_ai`, and `external_agent`. No class's setting implies another's.

**External agents:** the verify result already carries the verdict. The hosted service deliberately omits the verdict when its consent store is unreadable (degraded mode), so an absent verdict is *unresolved*, never a grant — `consent_granted?` fails closed on it. Resolve an absent or malformed verdict through the ledger:

```ruby
client = AgentAdmit::IntrospectionClient.new
result = client.verify(token)
consent = result.consent
unless consent.is_a?(Hash) && [true, false].include?(consent["granted"])
  # absent/malformed verdict: the ledger holds the authoritative answer
  consent = client.check_consent(app_user_id: result.user_id,
                                 caller_class: "external_agent") # fail closed on error
end
unless consent["granted"] == true
  # the data owner has switched external agents off: return your own 403
end
```

The `AgentAdmit::CallerConsent` middleware does all of this for you: it evaluates the consent verdict **before** the scope check (a caller whose class the owner denied learns nothing about scope state) and resolves an absent verdict through the Consent Ledger, fail-closed.

**Human sessions and in-app AI** never hold AgentAdmit tokens, so ask directly:

```ruby
verdict = AgentAdmit::IntrospectionClient.new.check_consent(
  app_user_id: "user_8842", caller_class: "in_app_ai"
)
head :forbidden unless verdict["granted"]
```

Consent is orthogonal to revocation: a denied verdict means your app returns its own 403; the connection and token stay valid so the user can flip consent back on without re-connecting. Write switches through `PUT /api/v1/consent/settings` from your backend; export the audit trail with `GET /api/v1/consent/export` (every plan).

**One-middleware drop-in.** Instead of wiring the three paths by hand, `AgentAdmit::CallerConsent` classifies the caller from the credential and evaluates the right independent path:

```ruby
use AgentAdmit::CallerConsent,
    # derive the class from your own credential structure, never caller input
    classify_non_agent: ->(env) {
      env["HTTP_X_INTERNAL_AI"] == ENV["INTERNAL_AI_SECRET"] ? "in_app_ai" : "human_session"
    },
    resolve_data_owner_id: ->(env) { Rack::Request.new(env).params["owner_id"] },
    required_scope: "read:records"
# Downstream: env["agentadmit.caller_class"], env["agentadmit.consent"], and the
# standard agent env variables on the external-agent path.
```

External agents are checked via hosted introspection (consent verdict plus scope); in-app AI via the Consent Ledger (fail closed); the human path defers to your own permission model unless `gate_human: true`. It is a consent gate, not an authenticator, so mount it after your own authentication.

### Presence verification

AgentAdmit can attest that the human who authorized a connection completed a WebAuthn presence ceremony on the consent page. The verify result carries the fact:

```ruby
result = AgentAdmit::IntrospectionClient.new.verify(token)
result.presence_verified?  # true only when the ceremony completed
```

For sensitive actions, enforce it in your controllers the same way you enforce scopes:

```ruby
class TransfersController < ApplicationController
  include AgentAdmit::ScopeEnforcement

  before_action -> { require_presence! }, only: [:create]
end
```

`require_presence!` fails closed: agents whose connection was minted without a completed ceremony get a 403 `presence_required`, and so do connections from servers that predate the feature. `presence_verified?` returns true only on an explicit boolean `verified: true`; absent or malformed presence data reads as not verified.

## Rate Limiting

The AgentAdmit introspection endpoint enforces rate limits. The Ruby SDK handles HTTP 429 responses **automatically** with exponential backoff and jitter -- no changes needed in your middleware code.

### Retry behavior

| Parameter | Default | Description |
|-----------|---------|-------------|
| Initial delay | 1 second | First retry wait |
| Backoff multiplier | 2x | Doubles each retry |
| Cap | 30 seconds | Maximum wait per retry |
| Jitter | 0-500 ms | Random addition to each delay |
| Max retries | **3** | Configurable |

The SDK also respects the `Retry-After` response header -- if present, it overrides the computed backoff delay.

### Configuring max retries

```ruby
AgentAdmit.configure do |config|
  config.max_retries = 5  # default: 3
end
```

Or via environment variable:

```env
AGENTADMIT_MAX_RETRIES=5
```

### Handling exhausted retries

When all retries are exhausted, `IntrospectionClient#verify` raises `AgentAdmit::RateLimitError`:

```ruby
begin
  result = client.verify(token)
rescue AgentAdmit::RateLimitError => e
  render json: { error: 'rate_limited', retry_after: e.retry_after }, status: 429
end
```

`RateLimitError` attributes:
- `retry_after` -- seconds from `Retry-After` header (`nil` if absent)
- `limit` -- `X-RateLimit-Limit` header value (`nil` if absent)
- `remaining` -- `X-RateLimit-Remaining` header value (`nil` if absent)
- `reset` -- `X-RateLimit-Reset` Unix timestamp (`nil` if absent)

## Documentation

Full integration guide: https://agentadmit.com/docs/app-owner-guide


## Data Collection & Privacy

The AgentAdmit Ruby SDK runs server-side and does not interact with app stores or end-user devices directly.

### What the SDK does
- Validates AgentAdmit tokens by calling AgentAdmit's hosted introspection endpoint (`https://api.agentadmit.com/api/v1/verify`) on every agent request -- this is mandatory introspection; there is no local or offline validation mode
- Enforces scope-based access control on your API routes
- Manages connection lifecycle (create, revoke) using the AgentAdmit hosted service

### What the SDK does NOT do
- Does not transmit raw end-user PII (such as name, email, or device identifiers) -- each introspection request sends the opaque access token and your API key
- Does not perform passive background telemetry or analytics -- network calls occur only during active token validation
- Does not maintain its own persistent local storage

### What the AgentAdmit hosted service records
On every token validation, AgentAdmit's `/api/v1/verify` endpoint receives the access token and API key, resolves the token to its `user_id`, `connection_id`, granted `scopes`, and `agent_label`, and records per-call metadata (including the endpoint and timestamp) for billing, audit logging, the security alerts engine, and usage metering. This is integral to how AgentAdmit works and applies to both test and live keys. See the "Mandatory introspection" notes above and the [compliance guide](https://agentadmit.com/docs/compliance) for the full data-handling description.

### Privacy impact
Since this SDK runs on your server, it has no direct App Store or Play Store compliance surface. Your client-side integration (e.g., the AgentAdmit React SDK) handles privacy manifest and data safety requirements.

For complete compliance guidance, see our [compliance guide](https://agentadmit.com/docs/compliance).

## License

All rights reserved. Patent pending.

## Security Alerts

```ruby
alerts = AgentAdmit::AlertsClient.new
```

Six alert type constants: `ALERT_TYPE_VOLUME_SPIKE`, `ALERT_TYPE_FAILED_SCOPE_ATTEMPTS`, `ALERT_TYPE_BURST_PATTERN`, `ALERT_TYPE_STALE_REACTIVATION`, `ALERT_TYPE_NEW_SCOPE_USAGE`, `ALERT_TYPE_REVOKED_CONNECTION_ATTEMPT`.

### Configure

```ruby
alerts.configure_alerts(
  app_id: 'app_abc123',
  alert_type: AgentAdmit::AlertsClient::ALERT_TYPE_VOLUME_SPIKE,
  enabled: true, threshold_value: 100, threshold_window_minutes: 5,
  kill_switch_enabled: true,
)
```

### List Events

```ruby
result = alerts.list_alerts(app_id: 'app_abc123', alert_type: AgentAdmit::AlertsClient::ALERT_TYPE_VOLUME_SPIKE)
```

### Get Config

```ruby
config = alerts.get_alert_config(app_id: 'app_abc123')
```


### Notifying Your Users

AgentAdmit detects anomalies, fires alerts, and (with kill switch) auto-revokes connections. **How you notify your own users is up to you.** AgentAdmit provides the data -- you deliver it through your own system (in-app notifications, email, push, etc.).

- **Poll alerts** -- Use the SDK methods above from your backend to check for new events, then notify users through your existing system.
- **Webhook delivery** -- Configure a webhook URL in your AgentAdmit dashboard. When an alert fires, AgentAdmit POSTs the payload to your server, signed with your `whsec_...` secret. The payload carries `alert_id`, `alert_type`, `severity`, the connection's `agent_label`, and the grant's declared `purpose`; the full shape is documented in the Webhook Delivery section of the MCP guide at https://agentadmit.com/docs/mcp-guide. Always verify the signature against the raw request body before trusting the payload:

  ```ruby
  # Rails controller
  def alerts
    AgentAdmit::Webhook.verify_signature(
      request.raw_post,
      request.headers["X-AgentAdmit-Signature"].to_s,
      AgentAdmit.configuration.webhook_secret # whsec_... from AGENTADMIT_WEBHOOK_SECRET
    )
    event = JSON.parse(request.raw_post)
    # ...
    head :ok
  rescue AgentAdmit::WebhookSignatureError
    head :bad_request
  end
  ```

  The header format is `t=<unix_ts>,v1=<hex>` -- an HMAC-SHA256 of `{t}.{raw_body}` keyed with your signing secret. Verification compares in constant time and rejects timestamps more than 5 minutes off (replay protection).
- **React SDK** -- Embed the `<AlertsPanel>` component so users can view their own alert history and tighten thresholds.

### Issuing & Exchanging Tokens

```ruby
tokens = AgentAdmit::TokensClient.new

# Duration is tri-state:
#   omit the argument          => AgentAdmit default (30 days)
#   nil                        => until the user revokes
#   Integer (60-31536000)      => explicit seconds
issued = tokens.issue_token(
  user_id: "user_42",
  scopes: ["read:orders"],
  role: "user",
  duration_seconds: nil # until revoked
)
connection_token = issued["token"] # ag_ct_...

# Agent side -- no API key needed; the connection token is the credential.
granted = tokens.exchange(connection_token, agent_label: "MyAssistant")

# Revoke when the user disconnects the agent.
tokens.revoke(granted["connection_id"], reason: "user_requested")
```

### Declared purpose

Declared purpose: the user-facing reason recorded on the grant at the consent moment. Review-time record only, never an enforcement input; authorization decisions ride scopes, connection status, and consent.

Pass it when issuing a connection token (optional, max 300 characters; omitted from the request when `nil`):

```ruby
issued = tokens.issue_token(
  user_id: "user_42",
  scopes: ["read:orders"],
  purpose: "Book quarterly travel for the sales team"
)
```

The verify result carries it back for display in dashboards, review screens, and audit views:

```ruby
result = AgentAdmit::IntrospectionClient.new.verify(token)
result.purpose # => "Book quarterly travel for the sales team" or nil
```

`purpose` is nullable -- connections issued without one (or by servers that predate the field) read as `nil`. Do not branch authorization on it; keep enforcement on scopes, connection status, and consent.

### User-declared intent

User-declared intent: the user's OWN words, typed at the consent moment. `purpose` is the app's words for why the connection exists; `user_intent` is what the user actually said they wanted ("build me a weekly workout summary"). On the hosted consent page the user can type it into an optional field; apps collecting consent in their own UI can pass it at token issuance.

Pass it when issuing a connection token (optional, 1-300 characters; a malformed value -- non-string, empty, or over 300 characters -- normalizes to `nil` and is omitted from the request rather than rejected):

```ruby
issued = tokens.issue_token(
  user_id: "user_42",
  scopes: ["read:orders"],
  purpose: "Book quarterly travel for the sales team",
  user_intent: "Book my flights to the Austin offsite in October"
)
```

It flows exactly like purpose: stored on the connection, returned by verify, stamped into every audit row, and carried on grant and revocation ledger events. When the hosted presence ceremony runs, the user's own words are included in the verifiable-consent-evidence commitment, so their authenticator signs what they said they wanted.

```ruby
result = AgentAdmit::IntrospectionClient.new.verify(token)
result.user_intent # => "Book my flights to the Austin offsite in October" or nil
```

`user_intent` is nullable -- connections issued without one (or by servers that predate the field) read as `nil`. Months later, a review screen can answer "is this still appropriate?" with the user's own stated boundary, not just the app's. Like purpose, it is a review-time record and never an enforcement input; authorization decisions ride scopes, connection status, and consent.

## App-Attested Presence

If your app gates token minting behind its own embedded passkey/WebAuthn ceremony, AgentAdmit never witnesses that ceremony (it is origin-bound), so by default the hosted service reports `presence.verified: false` for those connections. Attest the ceremony fact at issuance to close that gap -- AFTER verifying and consuming your own fresh, purpose-bound attestation:

```ruby
issued = tokens.issue_token(
  user_id: "user_42",
  scopes: ["read:orders"],
  presence: AgentAdmit::AppAttestedPresence.new(
    method: "my_webauthn",             # lowercase alphanumeric/underscore
    verified_at: attestation.created_at # Time or DateTime
  )
)
```

The SDK sends it as `presence: {verified: true, uv: true, method, verified_at}` -- `verified`/`uv` are literal true by construction and the class cannot represent anything else; a raw Hash is rejected so the wire contract stays owned by the typed class. The hosted service validates freshness (10-minute window, 60 s future clock-skew slack) and stores the method provenance-marked `app:<method>` so app-attested facts stay distinct from ceremonies AgentAdmit witnessed itself. Introspection, the grant-event ledger, and the evidence API then carry `presence.verified: true` for the connection.

Honesty ceiling: this is your app's attestation, recorded and provenance-marked. It is not witnessed by AgentAdmit and not independently verifiable. Only attest a ceremony that verified the user with UV (biometric or PIN user verification); a ceremony without UV carries no presence fact, so pass `nil` (the default). An out-of-contract method (`^[a-z0-9_]+$`, 1-60) raises `ArgumentError` at construction, before any request; Ruby `Time`/`DateTime` always carry an offset, so `verified_at` serializes RFC 3339 with an explicit offset by construction.

## Per-Call Audit Telemetry

Every verified call reports the exercised scope, endpoint, and method to your app's tamper-evident audit log on the hosted service. The introspection request body carries three optional fields alongside the token:

- `scope_used` -- the single declared scope this call enforces (never a joined list)
- `endpoint` -- the request path only; the query string is stripped before sending (queries can carry PII) and the path is truncated to 500 characters
- `method` -- the HTTP method, uppercased, capped at 20 characters

Each field is sent whenever it is known and OMITTED when it is not -- never null, never an empty string. When a field is omitted, the audit row honestly records "not reported".

The Rack middleware always sends `endpoint` (from `PATH_INFO`) and `method`; declare the enforced scope at mount time to send `scope_used` too:

```ruby
# Scope resolved per request (env -> scope String or nil) ...
use AgentAdmit::Middleware, scope_for: ->(env) { SCOPES[env["PATH_INFO"]] }
# ... or one static scope for everything behind this middleware.
use AgentAdmit::Middleware, scope_for: "read:orders"
```

`AgentAdmit::CallerConsent` never sends `scope_used` (its consent gate precedes any scope disclosure; the scope check stays local, after consent) but still reports endpoint and method. Direct client calls pass the same optional keyword arguments:

```ruby
result = AgentAdmit::IntrospectionClient.new.verify(
  token,
  scope_used: "read:orders",
  endpoint: request.path,
  method: request.request_method
)
```

The local `ScopeEnforcement` checks (`require_scope!`, `require_scope_if_agent!`) are unchanged -- defense in depth on top of the hosted decision.

### Active-error responses are denials

An introspection response with `active: true` AND a string `error` field means the token itself is valid but the authorization service refused this call. The SDK treats every such response as a denial, never a pass-through -- the downstream app does not run:

- `insufficient_scope` -> `AgentAdmit::InsufficientScopeError`; middlewares return 403 with the step-up shape (`error`, `required_scope`, `granted_scopes`)
- `bound_exceeded` -> `AgentAdmit::BoundExceededError`; middlewares return 403 passing the hosted fields (`error_description`, `bound`, `renewal`) through verbatim
- any other error string -> `AgentAdmit::ActiveDenialError`; middlewares return 403 with `{error: <code>, error_description: "Call refused by the authorization service."}` -- unknown codes fail closed

All three inherit from `AgentAdmit::ActiveDenialError` and expose `#code`, `#data` (the parsed hosted response), and `#denial_body` (the ready-made 403 JSON body) for apps that call `verify` directly.
