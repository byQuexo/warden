# Policy reference

Warden reads up to four files. They are deliberately separate:

| File | Question it answers | Owner |
|---|---|---|
| `catalog.yaml` | What exists, which scopes does it need, how risky is it? | platform / tool owners |
| `policy.yaml` | Which roles grant which scopes, which agents may use what, which rules restrict? | security |
| `identity.yaml` | Which issuers do we trust, how do we read their tokens? | identity team |
| `catalog.lock` | Which exact upstream definitions were reviewed? (generated) | `warden catalog accept` |

Every file has `version: 1`. Unknown keys are errors, not silently ignored.

## catalog.yaml

```yaml
version: 1
tool:                                   # one section per action kind
  crm.update_deal: { scopes: [crm:write], sensitivity: write }
  hr.get_salary:   { scopes: [hr:salary], tags: [pii] }
  "*.delete_*":    { scopes: [admin], sensitivity: write, tags: [destructive] }
resource:
  "docs://hr/**":  { scopes: [docs:hr] }
prompt:
  "crm.*":         { scopes: [crm:read] }
a2a_skill:
  research.deep_search: { scopes: [research] }
x-payment:                              # custom kinds start with x-
  _normalize: name                      # name (default) | uri
  payments.transfer: { scopes: [payments:write], sensitivity: write, tags: [financial] }
```

* **Kinds**: `tool`, `resource`, `prompt`, `a2a_skill`, or your own `x-…`.
* **Patterns**: `*` matches within one segment (`.` for names, `/` for URIs), `**` across segments.
* **Overlaps are restrictive**: if several patterns match, *all* their scopes are required and
  tags are merged. A later exact entry cannot drop a `destructive` tag from a glob.
* **No scopes = denied.** `warden catalog pull` writes entries with `scopes: []` so newly
  discovered tools stay blocked until someone classifies them.
* `audit_args: true` stores arguments in clear text in the audit log (never for `pii`).

## policy.yaml

```yaml
version: 1
defaults: { effect: deny }          # the only allowed value
model_messages: generic             # generic | rule_id — what the model sees on deny
service_subjects: deny              # may tokens without a user act?
roles:
  sales-rep: [crm:read, crm:write, "docs:sales"]
agents:
  acme-bot:
    max: [crm:read, crm:write, "docs:*"]
    delegation: { may_delegate_to: [acme-action] }
  acme-action:
    max: [crm:write]
    delegation: { max_depth: 2 }    # may act at the end of chains up to length 2
rules:
  - id: big-deals-need-approval
    match: { kind: tool, name: crm.update_deal }
    approve_if: { arg: amount, min: 50000 }
```

### Scopes

`area:right`, lowercase. A trailing `:*` matches every scope in the area (`docs:*` ⊇ `docs:hr`).
A bare `*` is rejected by lint.

### Agents and delegation

`max` is the ceiling of an agent no matter whom it acts for. For a chain
`bot → research → action` the principal is `agent = action, act = [bot, research]`:

* every edge must be listed in the sender's `may_delegate_to`,
* the chain length must be ≤ the acting agent's `max_depth`,
* every scope must be held by **every** agent in the chain.

### Rules

```yaml
- id: <unique>
  description: optional
  match: { kind: tool, name: "crm.*", tag: pii, sensitivity: write }   # all given fields must match
  require:    <condition>     # condition false → deny
  # or approve_if: <condition> # condition true → require approval
  # or deny_if:    <condition> # condition true → deny
```

Exactly one of `require` / `approve_if` / `deny_if`. All matching rules are evaluated.
`deny` beats `require_approval` beats `allow`.

### Conditions

| Form | Meaning |
|---|---|
| `always` | unconditional |
| `{ arg: amount, min: 0, max: 100 }` | several operators on one value are ANDed |
| `{ context: hour_utc, not_in_range: [7, 19] }` | values supplied by the adapter (`hour_utc`, `weekday`, `transport`) |
| `{ all: [c1, c2] }` / `{ any: [c1, c2] }` | combinators |

`arg` supports dotted paths (`filter.tenant`).

| Operator | Applies to | Notes |
|---|---|---|
| `equals` | string / number / bool | literal or placeholder |
| `in` | string | literal list or list placeholder |
| `glob` | string | `*`, `**` with `/` as separator |
| `regex` | string | must be anchored `^…$`; linear-time engine with size limit |
| `min`, `max`, `not_in_range` | JSON number | strings are a type error |
| `sql` | string | single read-only `SELECT`, table allowlist for every reference (joins, subqueries, CTEs), function allowlist, dialect |
| `custom` | any | Rust-registered `CustomConstraint`; not portable to TypeScript |

**Placeholders** come only from the verified principal or adapter context, never from
arguments: `{subject.id}`, `{subject.attrs.<key>}`, `{agent.id}`, `{context.<key>}`.

**Unknown denies.** A missing argument, a value of the wrong type, a string containing control
or invisible format characters (e.g. zero-width space), or a placeholder that cannot be
resolved makes the condition *unknown*, and unknown always denies — even inside `approve_if`,
so leaving out `amount` can never skip an approval.

### Visibility

A tool is listed to the model when normalization, principal, catalog, pin, kill switch and
scope gate pass and no `deny_if: always` matches. Argument-dependent rules do not hide a tool:
an HR lead sees `hr.get_salary` but may only query their own unit.

## identity.yaml

```yaml
version: 1
issuers:
  - issuer: https://login.example.com/realms/acme
    audience: https://gateway.example.com/mcp
    algorithms: [RS256, ES256]           # none/HS* are rejected; EdDSA allowed
    jwks_uri: https://…/certs            # optional; OIDC discovery otherwise
    mapping: { preset: keycloak, attrs: { org_unit: /org_unit, tenants: /tenants } }
    introspection:                       # optional: RFC 7662, for opaque tokens and instant revocation
      endpoint: https://login.example.com/realms/acme/protocol/openid-connect/token/introspect
      client_id: warden-gateway
      secret_env: INTROSPECTION_SECRET
      cache_s: 10                        # 0 = ask on every request
delegation_issuers: [https://sts.example.com]   # who may put `act` chains into tokens
scope_claim: required                    # required | ignore
clock_skew_s: 30
```

With `introspection:`, opaque (non-JWT) access tokens are accepted: the claims come from the
introspection response and go through the same mapping and checks. JWTs are verified locally
and then also introspected, so a revoked token is refused within `cache_s` seconds. If the
endpoint is unreachable the request is denied.

A mapping can be a preset (`keycloak`, `auth0`, `entra-id`, `okta`, `generic-oidc`) plus extra
attributes, or fully inline:

```yaml
mapping:
  subject: [/oid, /sub]                  # first present pointer wins
  agent: [/azp, /client_id]
  roles: /realm_access/roles
  scopes: { path: /scope, split: " " }
  act: /act
  token_type: { path: /typ, equals: Bearer }
  service_if: { path: /gty, equals: client-credentials }   # equals | prefix | same_as
  attrs:
    tenants: /tenants
```

## Lint

`warden lint` (and every engine build) reports:

| Errors (engine will not load) | Warnings |
|---|---|
| default effect not `deny` | scope granted but required by nothing |
| malformed or bare `*` scopes | catalog scope no role grants (dead action) |
| rule without exactly one condition, duplicate ids, empty match | overlapping catalog globs |
| rule that matches no catalog entry | `deny_if` with string matching (denylist) |
| unanchored regex, invalid placeholders, `equals` with a list | `require: always` (no-op) |
| catalog names that are not normalized ASCII, collisions (`get_x` vs `get-x`) | custom constraints (not portable) |
| unregistered custom constraint, unknown delegation target | |

## Scenario files (eval)

```yaml
suite: my-policy
principals:
  sven: { subject: { id: sven, roles: [sales-rep], attrs: { tenants: [dach] } }, agent: acme-bot }
cases:
  - id: A2
    title: Sales rep reads another tenant
    as: sven
    action: { kind: tool, name: crm.list_deals, args: { tenant: enterprise } }
    context: { kill_switch: off, values: { hour_utc: 10 } }   # optional
    args_raw: '{"tenant":"dach","tenant":"x"}'               # optional, strict-parsed
    expect: { effect: deny, rule: tenant-pinning, visible: true }
```

`warden eval --suite <file> --generate --mutate --coverage --gate` runs your cases plus
generated attacks and enforces the gates described in the README.
