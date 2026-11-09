> Hinweis: Das Projekt heißt inzwischen **Warden**; dieser Originalplan verwendet noch den Arbeitsnamen `agent-scope`.

# agent-scope: Bauplan (generisches Autorisierungs-Framework für Agenten)

> Nur Plan, gebaut wird in einem agentischen Entwicklungs-Workflow. Stand: 04.11.2026 (Rev. 3). Ersetzt die RBAC-Teile aus `agent-scope/PLAN.md` (TS-Lib) und `agent-scope-next/PLAN.md`. Der Acme Company Bot (`plans/company-bot/PLAN.md`) ist ab Rev. 3 **ein Konsument von vielen**, nicht der Zielkunde.
> Markierung: **[Annahme]** = nicht verifiziert, im genannten Spike prüfen. **[Verifiziert]** = am 04.11.2026 nachgeschaut.

---

## 0. Änderungen

### Rev. 3: generisches Framework

| # | Änderung | Warum |
|---|---|---|
| 1 | **Neutrales Kernmodell:** `Subject` (User/Service mit Rollen + freien Attributen), `Agent` + `act`-Kette, `Action` mit erweiterbaren Arten (`tool`, `resource`, `prompt`, `a2a_skill`, eigene `x-…`). Keine Acme-, Keycloak- oder MCP-Begriffe im Core. | Rev. 2 hatte `department`/`tenants` und MCP-Tools faktisch fest verdrahtet. |
| 2 | **Erweiterungspunkte als Traits** (§5): `TokenVerifier`, `ClaimMapper`, `AttributeResolver`, `Approver`, `AuditSink`, `PolicySource`, `UpstreamAuth`, `Constraint`, `Engine`, Protokoll-Adapter. Jeder mit mindestens einer mitgelieferten Implementierung. | Ein Framework muss sich ohne Fork an IdP, Approval-Kanal, Audit-Ziel und Agent-Framework anpassen lassen. |
| 3 | **IdP-agnostisch:** deklaratives Claim-Mapping per JSON-Pointer, Presets als YAML (`keycloak`, `auth0`, `entra-id`, `okta`, `generic-oidc`), OIDC Discovery, mehrere Issuer. Keycloak ist nur noch das Dev-/Referenz-Setup. | Rev. 2 kannte nur Keycloak. |
| 4 | **Adapter statt einer Integration:** MCP (Middleware + Gateway), A2A, rig; in TS ein generisches `guard()` für beliebige Tool-Funktionen plus MCP-SDK und Vercel AI SDK. | Generisch heißt: funktioniert mit dem Agent-Framework des Nutzers, nicht nur mit unserem. |
| 5 | **Eval für fremde Policies:** `agent-scope eval --generate` leitet aus Catalog + Policy des Nutzers Angriffsfälle ab (fehlende Scopes, Typverwechslung, Unicode, doppelte Keys, Delegations-Eskalation, Grenzwerte). Token-Suite ist policy-unabhängig. Die 40 Acme-Szenarien werden zur Referenz-Suite. | Der Security-Nachweis soll für jeden Nutzer funktionieren, nicht nur für die Demo. |
| 6 | **Acme wandert nach `examples/acme/`** (Policy, Realm, Mock-Upstreams, Szenarien). Dazu `examples/minimal/`: 20-Zeilen-Policy, generischer OIDC-Issuer, ein Tool. CI-Check: keine Acme-/Keycloak-Begriffe außerhalb von `examples/` und `presets/`. | Hält den Core sauber und beweist, dass er ohne Acme funktioniert. |
| 7 | **API-Stabilität:** SemVer-Regeln, `#[non_exhaustive]`, stabile Trait-Signaturen, Policy-Format-Versionierung, Kriterien für 1.0. | Ein Framework hat externe Nutzer; ohne Stabilitätsversprechen ist es nicht einsetzbar. |
| 8 | **Abgrenzung zu OPA/Cedar/OpenFGA** (§2.1): agent-scope liefert die agentenspezifische Semantik; diese Systeme können als `Engine` oder `AttributeResolver` andocken. | Beantwortet die erste Frage jedes Reviewers: „Warum nicht einfach OPA?“ |
| 9 | Aufwand **~15 Tage** (Stufe 0 ~8½). | Traits, Presets, zusätzliche Adapter, generierte Eval. |

### Rev. 2 (weiterhin gültig)

Regeln nur einschränkend (`require`/`approve_if`/`deny_if`; Rev. 1 hätte A1 erlaubt) · fehlendes Argument/Typfehler = deny · strikte Arg-Kanonisierung (doppelte Keys) · ASCII-Allowlist für Namen, URI-Normalisierung · Claims → Principal im Core mit Token-Vektoren · HMAC für Args, signierte Audit-Checkpoints, Sink-Fehler = deny · generische Modell-Texte bei deny · Session-Bindung, Server→Client-Requests blockiert, Annotations ignoriert, kein TOFU im Lockfile · Approval an Args gebunden + Re-Check · Rule-Coverage- und Mutations-Gate · Keycloak-Spike vorgezogen.

---

## 1. Ziel

Ein Framework, das für **beliebige Agenten-Systeme** eine Frage beantwortet: **Darf dieser Agent im Auftrag dieses Subjekts gerade diese Aktion ausführen?** Und das so, dass ein LLM die Antwort nicht beeinflussen kann.

```
effective  = scopes(subject.roles) ∩ agent.max ∩ token.scopes ∩ ⋂ { actor.max | actor ∈ act-Kette }
decision   = scope_gate(effective, catalog[action]) → rules (nur einschränkend) → Effekt
```

- **Deny by default, fail-closed.** Unbekannte Aktion, unbekannte Rolle, fehlendes Argument, Typfehler, Token-Fehler, Policy-Fehler, Audit-Fehler, Timeout, Panic, Fehler in einer Erweiterung → `deny`.
- **Scopes gewähren, Regeln schränken ein.** Keine Regel und keine Erweiterung kann mehr erlauben als die Schnittmenge.
- **Reihenfolge:** `deny` > `require_approval` > `allow`.
- **Protokoll- und IdP-neutral:** Core kennt nur `Subject`, `Agent`, `Action`, `Catalog`, `Policy`. MCP, A2A, Keycloak, Auth0 … sind Adapter bzw. Presets.
- **Eine Engine, drei Wege:** Rust in-process, TypeScript über WASM, jede Sprache über den MCP-Gateway-Prozess.
- **Unsichtbar statt verboten:** Adapter filtern Listen (Tools, Ressourcen, Prompts, Skills), jeder Aufruf wird trotzdem erneut geprüft.
- **Nachweisbar:** Security-Eval, die auf die Policy des Nutzers angewendet werden kann, harte CI-Gates, verifizierbares Audit-Log, `explain` für jede Entscheidung.

### Zielgruppen

| Wer | Nutzt | Beispiel |
|---|---|---|
| Plattform-Team mit vielen MCP-Servern | Gateway + YAML, keine Zeile Code | „Unsere 12 internen MCP-Server nur rollenbasiert für Agenten freigeben“ |
| Entwickler eines Rust-Agenten | Core + Identity + Adapter (rig, eigener Loop) | Acme Company Bot |
| Entwickler eines TS-Agenten | npm-Paket, `guard()` / MCP-SDK / AI SDK | incident-triage-demo |
| Security/Compliance | `lint`, `explain`, `eval --generate`, `audit verify` | Policy-Review vor Rollout |

### Vertrauensmodell

| Komponente | Vertrauen |
|---|---|
| Modell-Output, Tool-Ergebnisse, Dokument-/Tickettexte | **nicht vertrauenswürdig** |
| Upstream-Server / Tools | halb: Erreichbarkeit aus Config; Namen, Beschreibungen, Schemas, Annotations, Ergebnisse untrusted |
| Agent-Anwendung (hält Tokens) | vertrauenswürdig für ihre Tokens; kompromittiert = Rechte ihrer aktuellen Tokens (nicht abgedeckt, nur begrenzt) |
| Erweiterungen (eigene Traits) | vertrauenswürdiger Code des Nutzers; ihre **Fehler** führen trotzdem zu deny |
| Gateway, IdP, Mini-STS, Policy-Dateien | Trusted Computing Base |

## 2. Nicht im Scope

| Nicht drin | Warum / wo stattdessen |
|---|---|
| Eigener Identity Provider, User-Verwaltung, Login-UI | Jeder OIDC-IdP. Keycloak nur als Dev-Referenz. |
| Allgemeine Policy-Sprache | YAML mit festem Constraint-Set, lintbar und portabel (Rust = TS). Komplexe Logik über `Engine`-Trait (Cedar) oder `AttributeResolver` (OpenFGA, DB). |
| Prompt-Injection-Erkennung per Klassifikator | Wir verhindern die *Folgen* (Rechte), nicht den Text. |
| Exfiltration *innerhalb* erlaubter Aktionen | Im Threat Model dokumentiert, nicht gelöst. |
| Approval-UI, Admin-UI | `Approver`-Trait + Admin-API. UI baut der Konsument. |
| Memory, Kosten, Orchestrierung, Qualitäts-Eval | Sache der Agent-Anwendung. agent-scope liefert Entscheidungen und Audit-Events. |
| Rate Limiting / Quotas | Payload-Caps ja, Rate Limits „Später“. |
| Python-/Go-Bindings | Über den Gateway abgedeckt. Binding „Später“, wenn Nachfrage da ist. |
| Produktions-HA, Multi-Region | Stateless bis auf Audit-Sink (eine Kette pro Instanz), horizontal skalierbar. |

### 2.1 Abgrenzung

| System | Was es kann | Was agent-scope ergänzt | Zusammenspiel |
|---|---|---|---|
| OPA/Rego, Cedar | allgemeine Policy-Auswertung | Delegationsketten, Tool-Sichtbarkeit, Arg-Kanonisierung, Rug-Pull-Pinning, Approval-Effekt, Agent-Eval | Cedar als alternatives `Engine`-Backend (Später) |
| OpenFGA/SpiceDB | Beziehungen (ReBAC) | s. o. | als `AttributeResolver`: „ist Subjekt Owner von Deal X?“ → Attribut |
| MCP-Gateways ohne RBAC | Routing, Aggregation | Autorisierung pro Subjekt + Agent | agent-scope-Middleware davor oder eigener Gateway |
| IdP-Scopes allein | grobe Scopes im Token | Argumente, Delegation, Approval, Sichtbarkeit, Audit | IdP bleibt Quelle der Identität |

## 3. Sprachentscheidung

**Rust-Core + Rust-Gateway, TypeScript über WASM-Paket und über den Gateway-Prozess.**

| Option | Pro | Contra |
|---|---|---|
| **A. Rust-Core-Crate + Gateway-Binary + npm (WASM)** ✅ | Eine Engine, keine Drift. Core ohne I/O und ohne Uhr → `wasm32-unknown-unknown` → Node, Bun, Deno, Edge, Browser. Rust-Agenten in-process. Passt zu Tims Profil und zu `agent-approval-gate`. | WASM-Binding braucht eigene Tests. Signaturprüfung in TS separat (jose); Claim-Logik bleibt im Core. Eigene `Constraint`-Erweiterungen sind nur in Rust möglich (s. §5). |
| B. TS-Lib + Node-Gateway | Schneller Start. | Rust-Konsumenten nur über HTTP. Zweite Engine später = Drift. |
| C. Rust-Core + napi-rs | Native Speed. | Prebuilds pro Plattform, kein Browser/Edge. |

**Konformität:** `spec/vectors/decisions/*.json` und `spec/vectors/tokens/*.json` (inkl. Claim-Fixtures pro Preset). Rust und TS laufen gegen dieselben Vektoren. Ohne grüne Vektoren kein Release. Die Vektoren sind Teil der öffentlichen Spezifikation: eine dritte Implementierung kann sich daran messen.

**Name:** `agent-scope`. crates.io: frei **[Verifiziert]**. npm: Name war 02/2026 von Dritten veröffentlicht (0.1.0–0.5.2) und wurde am 19.02.2026 komplett unpublished **[Verifiziert]**; vor Publish prüfen. Fallback: `@byquexo/agent-scope`.

## 4. Kernmodell

```rust
pub struct Subject   { id: String, kind: SubjectKind /* User | Service */, roles: BTreeSet<Role>, attrs: Attrs }
pub struct Principal { subject: Subject, agent: AgentId, act: Vec<AgentId>, token_scopes: Option<BTreeSet<Scope>>, expires_at: Timestamp }
pub struct Action    { kind: ActionKind, name: String, args: CanonicalJson }
pub enum   ActionKind { Tool, Resource, Prompt, Completion, A2aSkill, Custom(KindName /* "x-…" */) }
pub struct Decision  { effect: Effect, rule: RuleId, reason: String, model_message: String, trace: Trace }
pub type   Attrs = BTreeMap<String, AttrValue>;  // String | Vec<String> | Number | Bool
```

- **Attribute sind frei.** Was Acme `department` nennt, heißt woanders `cost_center` oder `org_unit`. Sie kommen aus dem Claim-Mapping und/oder einem `AttributeResolver`.
- **Action-Arten sind erweiterbar.** Eigene Arten (`x-sql`, `x-payment`, `x-shell`) bekommen Catalog-Einträge und Regeln wie eingebaute; Normalisierung wählt man pro Art (`name` oder `uri`).
- **Alle Typen** `#[non_exhaustive]`, Konstruktion über Builder → neue Felder brechen keine Konsumenten.

## 5. Erweiterungspunkte

Der Core ist rein (keine I/O, keine Uhr). Alles mit I/O sitzt in Traits außerhalb des Core. Jeder Trait hat einen Fehlerpfad, der zu `deny` führt; eine Erweiterung kann nie direkt `allow` liefern.

| Trait | Zweck | Wo | Mitgeliefert | Fehler → |
|---|---|---|---|---|
| `TokenVerifier` | Token → verifizierte Claims | identity | JWKS via OIDC Discovery, statischer Key (`--dev`); Introspection: Später | `token_rejected` |
| `ClaimMapper` | Claims → `Principal` (rein) | **core** | deklarativ per JSON-Pointer; Presets `keycloak`, `auth0`, `entra-id`, `okta`, `generic-oidc` | `token_rejected` |
| `AttributeResolver` | Principal vor `check` anreichern (DB, LDAP, OpenFGA, HR-System) | identity (async) | `static` (YAML), `http` (JSON-Endpoint, Cache) | deny (`attrs.unavailable`) |
| `PolicySource` | Policy/Catalog/Lock laden + Änderungen melden | gateway | `file` (watch), `embedded`, `http` (ETag) | alte Policy bleibt |
| `Approver` | Approval einholen | aus `agent-approval-gate` | `webhook`, `cli`, `deny-all`, `auto-approve` (nur Tests, nur `--dev`) | deny |
| `AuditSink` | Events schreiben | audit | `jsonl` (Hash-Kette + Checkpoints), `stdout`, `otel`, `multi` | `on_sink_error` (Default deny) |
| `UpstreamAuth` | Credential für Upstream | gateway | `token-exchange`, `client-credentials`, `static`, `none` | deny |
| `Constraint` | eigene Argument-Prüfung, rein und synchron | core | eingebautes Set (§7) | deny |
| `Engine` | Entscheidungs-Backend | core | YAML-Engine; Cedar: Später | deny |
| Protokoll-Adapter | Protokoll ↔ `Action`, Listen filtern | eigene Crates/Subpaths | MCP (rmcp-Middleware, Gateway), A2A, rig; TS: `guard`, MCP-SDK, AI SDK | deny |

**Eigene Constraints** sind nur in Rust möglich und machen eine Policy **nicht portabel** (TS kennt sie nicht). Die Policy markiert sie explizit (`custom: my_check`); die TS-Engine lehnt Policies mit unbekannten Custom-Constraints beim Laden ab (kein stilles Ignorieren). Lint warnt.

**Stabilität der Traits:** `async fn` in Traits (stabil seit Rust 1.75), keine `async_trait`-Makros in der öffentlichen API **[Annahme, MSRV in Phase 0]**. Trait-Änderungen nur in Minor-Versionen vor 1.0, danach Major.

## 6. Ziel-API

### Rust (in-process, minimal)

```rust
use agent_scope::{Engine, Policy, Catalog, Action, Effect};
use agent_scope_identity::{OidcVerifier, mapping::Preset};

let engine = Engine::builder()
    .policy(Policy::from_yaml_str(POLICY)?)
    .catalog(Catalog::from_yaml_str(CATALOG)?)
    .build()?;                                              // lint-Fehler = Err, nie „halb geladen“

let verifier = OidcVerifier::discover("https://idp.example.com", "https://my-agent.example.com").await?;
let principal = verifier.verify(bearer, &Preset::GenericOidc, now).await?;   // Signatur hier, Mapping im Core
let principal = resolver.enrich(principal).await?;          // optional: AttributeResolver

let d = engine.check(&principal, &Action::tool("crm.update_deal", &args));
match d.effect {
    Effect::Allow => run().await,
    Effect::RequireApproval => gate.guard(call.bind(&d), run).await?,   // jeder Approver
    Effect::Deny => return Err(d.model_error()),                         // generischer Text fürs Modell
}

let visible = engine.filter(&principal, ActionKind::Tool, &tools);
let why = engine.explain(&principal, &Action::tool("hr.get_salary", &args));
```

`Decision` hat kein `Default`, `check` gibt kein `Result` zurück (interne Fehler → deny mit Regel `internal.error`).

### Adapter (Rust)

```rust
// rig: zweite Verteidigungslinie im Agent-Loop
let agent = AgentBuilder::new(model).add_hook(agent_scope_rig::ScopeHook::new(engine.clone(), principal.clone())).build();

// rmcp: eigener MCP-Server schützt sich selbst, ohne Gateway
let service = agent_scope_mcp::ScopeLayer::new(engine, verifier).wrap(my_mcp_server);

// A2A: Skill-Aufruf eines anderen Agenten prüfen
let d = engine.check(&principal, &Action::a2a_skill("research.deep_search", &input));
```

**[Annahme]** rig-Hook laut Beispiel `agent_with_approval_policy` (rig 0.46): `async fn on_dispatch(&self, ctx: &HookContext, event: DispatchEvent<'_>) -> DispatchAction`. Spike Phase 0.

### TypeScript (npm, WASM)

```ts
import { createScope, guard } from "agent-scope";           // WASM-Core + generischer Wrapper
import { verifyToken, presets } from "agent-scope/identity"; // jose (Signatur) + WASM (Mapping)
import { withScope } from "agent-scope/mcp";                 // @modelcontextprotocol/sdk
import { scopeTools } from "agent-scope/ai-sdk";             // Vercel AI SDK

const scope = await createScope({ policyYaml, catalogYaml });
const principal = await verifyToken(bearer, { issuer, audience, mapping: presets.auth0 }, scope);

// Framework-unabhängig: jede async-Funktion als Aktion schützen
const updateDeal = guard(scope, () => principal, "crm.update_deal", rawUpdateDeal, { approver });

// Framework-spezifisch
const server = withScope(mcpServer, scope, { principalFrom: (req) => req.authInfo });
const tools = scopeTools(scope, principal, { updateDeal: tool({...}) });   // filtert + prüft
```

Ein WASM-Trap wird im Wrapper gefangen → deny (`internal.error`), Instanz wird neu erzeugt. **[Annahme]** AI-SDK-Tool-Shape stabil genug für einen dünnen Adapter; Version pinnen.

### CLI und Gateway

```bash
agent-scope init                                   # minimale policy.yaml + catalog.yaml + identity.yaml
agent-scope lint policy.yaml catalog.yaml
agent-scope explain --policy policy.yaml --catalog catalog.yaml --principal principal.json --action tool:crm.update_deal --args '{...}'
agent-scope catalog pull --gateway gateway.yaml    # Upstream-Definitionen holen → Catalog-Gerüst + Lock
agent-scope catalog diff|accept [--tool crm.update_deal]
agent-scope audit verify audit/ --pubkey audit.pub
agent-scope eval --policy policy.yaml --catalog catalog.yaml --identity identity.yaml --generate [--suite my/scenarios] --gate [--mutate]
agent-scope dev token --subject alice --agent my-bot [--act other-agent]
agent-scope-gateway --config gateway.yaml          # MCP auf :8088/mcp, Admin auf :8089
```

`catalog pull` ist der Einstieg für bestehende MCP-Landschaften: es listet alle Upstream-Tools, erzeugt einen Catalog mit `scopes: []` (= deny, bis jemand taggt) und den Lock.

## 7. Policy-Format und Auswertung

Dateien, bewusst getrennt: **Catalog** (was gibt es, wie riskant), **Policy** (wer darf was), **Identity** (wem wird geglaubt, wie werden Claims gelesen), **Gateway** (nur beim Gateway: wo läuft was), **Lock** (gepinnte Upstream-Definitionen). `policy_version` = SHA-256 über Catalog, Policy, Identity und Lock in kanonischer Form. JSON-Schema für alle Dateien aus den Rust-Typen (schemars) in `spec/`.

```yaml
# catalog.yaml: Aktionen taggen. Untagged = deny.
version: 1
tool:
  hr.get_salary:        { scopes: [hr:salary],   sensitivity: read,  tags: [pii] }
  crm.list_deals:       { scopes: [crm:read],    sensitivity: read }
  crm.update_deal:      { scopes: [crm:write],   sensitivity: write }
  crm.query:            { scopes: [crm:read],    sensitivity: read }
  "*.delete_*":         { scopes: [admin],       sensitivity: write, tags: [destructive] }
resource:
  "docs://hr/**":       { scopes: [docs:hr] }
prompt:
  "crm.*":              { scopes: [crm:read] }
a2a_skill:
  research.deep_search: { scopes: [research] }
x-payment:                                      # eigene Action-Art
  _normalize: name                              # name | uri
  "payments.transfer":  { scopes: [payments:write], sensitivity: write, tags: [financial] }
```

- `sensitivity` ist `read | write`; alles Weitere sind **freie Tags** (`pii`, `destructive`, `financial` sind Konventionen, keine Sonderfälle im Code).
- **Matching:** `*` = genau ein Segment, `**` = beliebig viele. Treffen mehrere Einträge, gelten **alle**: Scopes = Vereinigung (alle nötig), Tags = Vereinigung. Überlappung = Lint-Warnung.

```yaml
# policy.yaml
version: 1
defaults: { effect: deny }                    # nicht änderbar (lint-Fehler)
model_messages: generic                       # generic | rule_id
roles:                                        # Rollennamen frei, kommen aus dem Claim-Mapping
  hr-lead:     [hr:read, hr:salary, docs:hr]
  sales-rep:   [crm:read, crm:write]
agents:                                       # Agent-IDs frei (meist OAuth client_id)
  my-bot:      { max: [hr:read, hr:salary, crm:read, crm:write, "docs:*"], delegation: { may_delegate_to: [my-action] } }
  my-action:   { max: [crm:write], delegation: { max_depth: 1 } }
service_subjects: deny                        # deny | allow: dürfen Tokens ohne User handeln?
rules:
  - id: salary-only-own-unit
    match: { kind: tool, name: hr.get_salary }
    require: { arg: unit, equals: "{subject.attrs.org_unit}" }
  - id: big-deals-need-approval
    match: { kind: tool, name: crm.update_deal }
    approve_if: { arg: amount, min: 50000 }
  - id: tenant-pinning
    match: { kind: tool, name: "crm.*" }
    require: { arg: tenant, in: "{subject.attrs.tenants}" }
  - id: destructive-always-approval
    match: { tag: destructive }
    approve_if: always
  - id: no-agent-after-hours                  # Kontext kommt vom Adapter, nicht vom Modell
    match: { sensitivity: write }
    deny_if: { context: hour_utc, not_in_range: [6, 20] }
```

### Auswertung (fest, in dieser Reihenfolge)

1. **Normalisieren** (Name/URI je nach Art, Argumente). Fehler → `deny` (`normalize.*`).
2. **Principal prüfen:** Agent bekannt, Delegationskette erlaubt (`may_delegate_to`, `max_depth`), Service-Subjekt erlaubt. Sonst `deny` (`principal.*`).
3. **Kill-Switch** → `deny` (`kill_switch`).
4. **Catalog:** kein Eintrag → `deny` (`catalog.untagged`). Lock-Abweichung oder fehlender Lock-Eintrag (bei gepinnten Arten) → `deny` (`catalog.unpinned`).
5. **Scope-Gate:** alle benötigten Scopes ∈ `effective`, sonst `deny` (`scope.missing`).
6. **Argumente** gegen gepinntes Schema, falls vorhanden. Fehler → `deny` (`args.schema`).
7. **Regeln:** alle passenden werden ausgewertet. `require: C` → C falsch → deny. `approve_if: C` → C wahr → require_approval. `deny_if: C` → C wahr → deny. Bei jeder Regelart: Argument/Attribut/Kontext fehlt oder Typ falsch → deny.
8. **Kombinieren:** `deny` > `require_approval` > `allow`. Keine passende Regel → `allow`.

**Sichtbarkeit (`filter`):** sichtbar, wenn 1–5 durchgehen und keine Regel *unbedingt* deny ergibt. Argumentabhängige Regeln machen nicht unsichtbar.

**Placeholder-Quellen:** `{subject.id}`, `{subject.attrs.*}`, `{agent.id}`, und `context.*` (vom Adapter gesetzte, nicht vom Modell beeinflussbare Werte wie Uhrzeit, Kanal, IP). Nie aus Argumenten. Listenwerte nur mit `in`, Skalare mit `equals` (sonst lint-Fehler).

### Constraints

Eingebaut und portabel: `equals`, `in`, `glob`, `min`, `max`, `not_in_range`, `regex` (Rust-`regex`, linear-time, `size_limit`, Anker Pflicht), `sql`. Nicht portabel: `custom: <name>` (§5).

- **Typen strikt:** `min`/`max` nur auf JSON-Zahlen; `equals`/`in`/`glob`/`regex` nur auf Strings.
- **Strings exakt** (bytegleich). Steuer- oder unsichtbare Zeichen (Cc, Cf) → deny.
- **`sql`:** `sqlparser` mit konfiguriertem Dialekt, ein einzelnes `SELECT`, Tabellen-Allowlist für **alle** Referenzen inkl. Subqueries/CTEs/Joins, kein `INTO`, `FOR UPDATE`, datenverändernde CTEs, Funktionen nur aus Allowlist. Defense in Depth; der Upstream braucht trotzdem eine Read-only-Rolle.

### Normalisierung

- **Namen** (`_normalize: name`): NFKC → lowercase → `^[a-z0-9][a-z0-9_.-]{0,127}$`, sonst verworfen (`tool_rejected`). Kollision mit `_` ≡ `-` → beide deny + lint-Fehler. Präfix setzt der Adapter/Gateway, nicht der Upstream.
- **URIs** (`_normalize: uri`): Schema/Host lowercase, Percent-Decoding einmal, danach kein `%`, keine `.`/`..`-Segmente, keine doppelten Slashes/Backslashes, sonst deny.
- **Argumente:** strikter Parse (doppelte Keys → deny, Tiefe ≤ 32, ≤ 64 KB). Geprüft und weitergegeben wird dieselbe re-serialisierte Struktur (`CanonicalJson`).

### Lint-Regeln (Auswahl)

| Regel | Stufe |
|---|---|
| Default ≠ deny; `auth.mode: local` ohne `--dev`; `auto-approve` ohne `--dev` | Fehler |
| Regel-`match` trifft keinen Catalog-Eintrag | Fehler |
| Platzhalter aus Argument; Listen-Platzhalter mit `equals`; `context.*`-Schlüssel, den kein konfigurierter Adapter liefert | Fehler |
| `regex` ohne `^…$`; Normalisierungs-Kollision | Fehler |
| `custom`-Constraint in einer Policy, die als portabel markiert ist | Fehler |
| Attribut-Platzhalter, den das Claim-Mapping/der Resolver nicht liefert | Warnung |
| Scope ohne Catalog-Träger; Catalog-Scope, den keine Rolle vergibt; überlappende Globs; überdeckte Regel | Warnung |
| `deny_if` mit `equals`/`glob`/`regex` auf Strings (Denylist) | Warnung |

**YAML-Crate [Annahme]:** `serde_yaml` ist archiviert; Kandidaten `serde-saphyr` oder `serde_norway`, Entscheidung in Phase 0 (doppelte Keys = Fehler, Größenlimit gegen Alias-Bomben, Fehler mit Zeile/Spalte).

## 8. Identität

### 8.1 Identity-Config

```yaml
# identity.yaml
version: 1
issuers:                                      # mehrere IdPs möglich
  - issuer: https://idp.example.com           # OIDC Discovery → jwks_uri
    audience: https://gw.example.com/mcp
    algorithms: [RS256, ES256]                # none/HS* sind nicht konfigurierbar
    mapping: { preset: keycloak }             # oder explizit:
  - issuer: https://example.eu.auth0.com/
    audience: https://gw.example.com/mcp
    mapping:
      subject: /sub
      agent: /azp
      roles: /https:~1~1example.com~1roles    # JSON-Pointer (RFC 6901)
      scopes: { path: /scope, split: " " }
      act: /act
      token_type: { path: /typ, equals: Bearer }   # ID-Tokens ausschließen
      attrs:
        org_unit: /org_unit
        tenants: /tenants
delegation_issuers: [https://sts.example.com]   # wer act-Ketten ausstellen darf
scope_claim: required                         # required | ignore
clock_skew_s: 30
```

- **Presets** sind YAML-Dateien in `presets/` (gleiches Format), versioniert und mit Claim-Fixtures in `spec/vectors/tokens/<preset>/` getestet. **[Annahme]** Claim-Formen von Auth0, Entra ID, Okta laut deren Doku; Fixtures beim Bau aus echten Beispieltokens der Doku ableiten. Nur `keycloak` und `generic-oidc` werden in CI gegen einen echten IdP getestet.
- Neue Presets beizutragen heißt: YAML + Fixtures, kein Rust-Code.

### 8.2 Token-Validierung

| Punkt | Festlegung |
|---|---|
| Aufteilung | `TokenVerifier` (Rust) bzw. `jose` (TS) prüfen **nur** Signatur und JWKS. Claims, Zeit, Mapping, `act` macht der Core (`ClaimMapper`, rein, `now` als Parameter). |
| Algorithmen | RS256, ES256 (erweiterbar um EdDSA); `none`/HS* hart abgelehnt; `alg` muss zu `kty` des JWK passen. |
| Prüfungen | `iss` exakt aus der Liste, `aud` enthält konfigurierte Audience, `exp`/`nbf` mit Skew, `kid` im JWKS, Agent bekannt, `token_type` passt (keine ID-Tokens). |
| JWKS | Cache mit TTL, Refresh bei unbekanntem `kid` max. 1×/min pro Issuer, Fehler → deny |
| Delegation | RFC 8693 `act`-Kette; nur von `delegation_issuers` akzeptiert; jede Kante in `may_delegate_to`, Tiefe ≤ `max_depth`; Schnittmenge über alle Akteure. |
| Upstream-Credentials | über `UpstreamAuth`; nie Token-Passthrough. |
| Metadata | `/.well-known/oauth-protected-resource` (RFC 9728) am Gateway bzw. per Helper für eigene Server. |
| Crates | `jsonwebtoken` (11.x, **[Verifiziert]** auf crates.io), `reqwest`, `openidconnect` nur für Dev-Helfer |

### 8.3 Mini-STS (optional, IdP-unabhängig)

Viele IdPs stellen keine `act`-Ketten aus (**[Annahme]** gilt vermutlich auch für Keycloak Standard Token Exchange V2; Spike nach Phase 0). Deshalb liefert `agent-scope-identity` einen optionalen STS (`POST /token`, grant `urn:ietf:params:oauth:grant-type:token-exchange`):

- Eingabe: `subject_token` (von einem konfigurierten Issuer) + `actor_token` (Client-Credentials-Token des delegierenden Agenten).
- Ausgabe: Token ≤ 5 min, `sub` = Subjekt, `azp` = Ziel-Agent, `act` = Kette, `aud` = Ziel, eigener ES256-Key + JWKS.
- Prüft `may_delegate_to`/`max_depth` beim Ausstellen; die Engine prüft trotzdem erneut.
- Funktioniert mit jedem IdP aus `issuers`, weil er nur dessen Tokens verifiziert.

### 8.4 Dev-Modus

Statischer Signierschlüssel + `agent-scope dev token`. Nur mit `--dev`, rotes Banner, lint-Fehler in Configs ohne `--dev`.

## 9. MCP-Adapter und Gateway

Der MCP-Adapter gibt es in zwei Formen: **Middleware** (`agent-scope-mcp`, für eigene rmcp-Server) und **Gateway** (Binary vor beliebigen fremden MCP-Servern). Beide nutzen denselben Code.

```mermaid
sequenceDiagram
  participant C as MCP-Client (beliebiger Agent)
  participant G as agent-scope-gateway
  participant E as Core-Engine
  participant U as Upstream
  C->>G: tools/list (Bearer, Mcp-Session-Id)
  G->>G: TokenVerifier → ClaimMapper → AttributeResolver → Principal; Session-Bindung
  G->>U: tools/list (UpstreamAuth)
  G->>G: Namen normalisieren, Hashes gegen Lock
  G->>E: filter(principal, Tool, tools)
  G-->>C: nur erlaubte, gepinnte Tools (namespaced)
  C->>G: tools/call x.update {amount: 80000}
  G->>G: Args strikt parsen + Schema
  G->>E: check(principal, action)
  E-->>G: require_approval
  G->>G: Approver (gebunden an args_hash), Progress-Keepalive
  G->>E: Re-Check nach Approval
  G->>U: tools/call (geprüfte Args, UpstreamAuth)
  G->>G: AuditSink
  G-->>C: Ergebnis (Payload-Cap)
```

- Gefiltert: `tools/list`, `resources/list`, `resources/templates/list`, `prompts/list`. Durchgesetzt: `tools/call`, `resources/read`, `prompts/get`, `completion/complete`.
- **Re-Check bei jedem Call.**
- **Session-Bindung** an (`subject`, `agent`, `act`); Abweichung → 403 + `session_mismatch`.
- **Server→Client-Requests** (`sampling/createMessage`, `elicitation/create`, `roots/list`) per Default blockiert, opt-in pro Upstream.
- **Upstream-Annotations** ignoriert; an den Client gehen die aus dem Catalog.
- **Rug-Pull-Schutz:** Hash über (Name, Beschreibung, `inputSchema`, `outputSchema`, Annotations) im Lock; Abweichung oder fehlender Eintrag → deny bis `catalog accept`. Kein TOFU.
- `list_changed` vom Upstream → re-listen, Hashes prüfen, eigene `list_changed` senden.
- JSON-RPC-Batches abgelehnt. Payload-Caps: Request 64 KB, Ergebnis 256 KB, pro Tool überschreibbar.
- **Kontext für Regeln** (`context.*`): Gateway setzt `hour_utc`, `client_ip`, `transport`; eigene Werte per Config aus Request-Headern **nur** von vertrauenswürdigen Proxies.
- MCP-Spec-Version: was `rmcp` 3.8 (**[Verifiziert]**, 26.10.2026) unterstützt; **[Annahme]** Streamable HTTP + Resource-Server-Rolle über rmcp-Features, sonst axum-Schicht davor.

```yaml
# gateway.yaml
listen: 0.0.0.0:8088
public_url: https://gw.example.com/mcp
identity: identity.yaml
policy: { source: file, catalog: catalog.yaml, policy: policy.yaml, lock: catalog.lock, reload: watch }
attributes: { resolver: http, url: http://directory:8080/attrs/{subject.id}, cache_s: 60 }   # optional
limits: { request_bytes: 65536, result_bytes: 262144, json_depth: 32 }
upstreams:
  hr:   { url: http://hr-mcp:9001/mcp,   auth: { strategy: token-exchange, audience: hr-mcp } }
  docs: { url: http://docs-mcp:9003/mcp, auth: { strategy: client-credentials, client_id: gw-docs, secret_env: DOCS_SECRET } }
approval:
  approver: webhook                 # webhook | cli | deny-all
  url: http://my-app:8080/approvals
  timeout_ms: 120000
  progress_interval_ms: 10000
audit:
  sinks:
    - { type: jsonl, dir: /var/lib/agent-scope/audit, hmac_key_env: AUDIT_HMAC_KEY, checkpoint_key_env: AUDIT_SIGNING_KEY }
    - { type: otel }
  on_sink_error: deny
kill_switch: { file: /run/agent-scope/kill }   # "writes" | "all"
```

- **Namespacing:** `<upstream>.<tool>`; Upstreams können sich nicht überschreiben.
- **Approval:** an (`principal`, `action`, `args_hash`, `policy_version`) gebunden; Re-Check danach; `approver == subject` → deny; Progress-Notifications während des Wartens (**[Annahme]** Clients verlängern Timeout, sonst `timeout_ms` ≤ Client-Timeout); nie gecacht; Fehler/Timeout = deny.
- **Webhook-Approver-Protokoll** ist dokumentiert und versioniert (JSON rein, JSON raus, HMAC-signiert), damit jede App (Slack-Bot, Web-UI, Ticket-System) Approver sein kann.
- **Hot Reload:** lint, dann atomar tauschen; Fehler → alte Policy, `policy_reload_failed`.
- **Admin-API** (:8089, eigenes Admin-Token): `GET /explain`, `GET /effective?subject=&agent=`, `POST /kill`, `GET /upstreams`, `GET /audit/tail`. OpenAPI-Spec in `spec/`.
- **Decision-Cache:** nur Listen; Schlüssel = Token-Hash + `policy_version` + Lock-Hash + Kill-Switch + Attribut-Hash; TTL 30 s.
- **Panics:** `catch_unwind` pro Request, `panic = "unwind"`; Panic → deny, Prozess lebt.
- Health/Circuit-Breaker, stdio-Upstreams: Stufe 2.

## 10. Audit

```json
{"v":1,"ts":"2026-11-04T10:12:03.120Z","chain":"gw-1","seq":4812,"event":"decision","effect":"require_approval",
 "rule":"big-deals-need-approval","subject":"sven","agent":"my-bot","act":["my-bot"],
 "action":{"kind":"tool","name":"crm.update_deal","args_hmac":"hmac-sha256:…"},
 "policy_version":"sha256:…","trace_id":"…","prev":"sha256:…","hash":"sha256:…"}
```

- **Event-Schema versioniert** (`v`) und als JSON-Schema in `spec/audit.schema.json`; Konsumenten (SIEM, eigene Dashboards) können sich darauf verlassen.
- Kette pro Instanz, `hash = sha256(prev || canonical_json(event))`, tägliche Datei, Kopfeintrag verweist auf den Vortag.
- Signierte Checkpoints (Ed25519) alle N Events + Tagesende; Checkpoint-Hash zusätzlich an alle anderen Sinks.
- Argumente als HMAC; Klartext pro Aktion opt-in (`audit_args: true`), Einträge mit Tag `pii` nie.
- Sink-Fehler → `on_sink_error` (Default deny).
- `agent-scope audit verify` findet Lücken, Umordnung, Manipulation, Neuberechnung (Checkpoint-Signatur).
- OTEL-Attribute `agent_scope.effect|rule|policy_version|subject|agent`.
- Event-Typen: `decision`, `approval_requested|granted|denied|timeout`, `tool_changed|tool_unpinned|tool_rejected`, `policy_reloaded|reload_failed`, `kill_switch`, `token_rejected`, `session_mismatch`, `attrs_unavailable`, `internal_error`, `checkpoint`.

## 11. Security-Eval

Drei Suiten, alle über denselben Runner. Ergebnisse werden immer gegen Audit und (beim Gateway) gegen das Request-Log der Mock-Upstreams geprüft, nie gegen Modell-Text.

### 11.1 Token-Suite (policy-unabhängig)

Läuft gegen jede `identity.yaml`, mit einem Test-Issuer, der absichtlich kaputte Tokens signiert: `alg: none`, HS256 mit Public Key als Secret, falsche `aud`/`iss`, abgelaufen, `nbf` in Zukunft, unbekannte `kid` (Flood → max. 1 Refresh/min), ID-Token statt Access-Token, `act` von nicht erlaubtem Aussteller, Token-Wechsel innerhalb einer Session.

### 11.2 Generierte Suite (aus der Policy des Nutzers)

`agent-scope eval --generate` erzeugt Fälle deterministisch aus Catalog + Policy + Identity:

| Generator | Erzeugt |
|---|---|
| Scope-Grenzen | pro Aktion: Principal mit allen Scopes außer einem benötigten → deny + unsichtbar |
| Rollen × Agenten | pro (Rolle, Agent): effektive Rechte = erwartete Schnittmenge; Tabelle als Report |
| Delegation | pro Agent-Paar ohne `may_delegate_to`-Kante: deny; pro Kette > `max_depth`: deny; Eskalation (Ziel hat Scope, Delegierender nicht): deny |
| Constraints | pro `require`/`approve_if`/`deny_if`: Grenzwerte (min−1/min/min+1), fehlendes Argument, falscher Typ (`"80000"`), Unicode-Varianten (Zero-Width, NFKC-Varianten), doppelte Keys |
| Platzhalter | Principal ohne referenziertes Attribut → deny; Service-Subjekt → deny bei `service_subjects: deny` |
| Namen/URIs | Homoglyph- und Separator-Varianten jedes Catalog-Namens; `..`/`%2e`-Varianten jedes Resource-Musters |
| Kill-Switch | jede `write`-Aktion unter `writes` → deny |

Erwartungen leitet der Generator aus der Spezifikation (§7) ab, nicht aus der Engine (sonst testet die Engine sich selbst). Der Generator ist ein eigenständiges Modul mit eigener, kleiner Referenz-Implementierung der Auswertungsregeln.

### 11.3 Referenz-Suite (`examples/acme/eval`)

Handgeschriebene End-to-End-Szenarien mit Keycloak, Gateway und Mock-Upstreams. Jedes Szenario: YAML mit Setup, Schritten (Script oder Angreifer-Prompt) und Erwartung.

| # | Kategorie | Szenario | Erwartung |
|---|---|---|---|
| T1–T5 | Token | Token-Suite gegen Keycloak | `token_rejected` / deny |
| T6 | Token | Gateway gibt Client-Token nie an Upstream | Mock-Upstream-Log enthält es nie |
| V1 | Sichtbarkeit | Hanna listet Tools | kein `hr.get_salary`, kein `crm.*` |
| V2 | Sichtbarkeit | Hanna ruft `hr.get_salary` direkt | deny (`scope.missing`) |
| V3 | Sichtbarkeit | `resources/read docs://it/runbook` als Sven | deny |
| V4 | Sichtbarkeit | `docs://sales/../it/runbook`, `%2e%2e`-Variante | deny (`normalize.uri`) |
| A1 | Argumente | Henrik: `get_salary(unit: "sales")` | deny (`salary-only-own-unit`) |
| A2 | Argumente | Sven: `crm.list_deals(tenant: "enterprise")` | deny (`tenant-pinning`) |
| A3 | Argumente | SQL: `; DROP`, CTE mit `DELETE`, Subquery auf fremde Tabelle, `pg_sleep()` | deny |
| A4 | Argumente | ReDoS-Payload / 1-MB-String | < 50 ms, deny |
| A5 | Argumente | `update_deal(amount: 80000)` | `require_approval` |
| A6 | Argumente | ohne `amount`, `"80000"`, `8e4` | deny, deny, `require_approval` |
| A7 | Argumente | doppelter Key `tenant` | deny, Upstream sieht nichts |
| A8 | Argumente | `tenant: "dach​"` | deny |
| D1 | Delegation | `research` delegiert an `action` (`crm:write`, Research nicht) | deny |
| D2 | Delegation | Kette > `max_depth` / Kante fehlt | deny |
| D3 | Delegation | `act` von nicht erlaubtem Aussteller, unbekannter Akteur | deny |
| S1 | Session | Hannas Session-ID mit Svens Token | 403 |
| S2 | Session | Upstream sendet `sampling/createMessage` | nicht weitergereicht |
| I1 | Injection | Ticket-Text verlangt `hr.get_salary` für alle (Angreifer-Agent) | Tool unsichtbar, kein Call erfolgreich |
| I2 | Injection | Tool-Beschreibung ändert sich mit Anweisung | `tool_changed`, deny |
| I3 | Injection | Homoglyph-Tool von zweitem Upstream | `tool_rejected` |
| I4 | Injection | Upstream setzt `readOnlyHint: true` auf Write-Tool | ignoriert, Approval bleibt |
| I5 | Injection | Angreifer iteriert über Deny-Texte | keine Regel-/Rollendetails im Modell-Text |
| P1–P3 | Approval | Args nach Approval geändert; Token läuft während Warten ab; Self-Approval | neue Approval / deny / deny |
| L1 | Lifecycle | Rolle entzogen, Token gültig | deny nach Token-TTL (5 min) |
| L2 | Lifecycle | Reload mit Syntaxfehler | alte Policy, `reload_failed` |
| L3 | Lifecycle | Rug Pull / neues Tool ohne Lock | deny bis `catalog accept` |
| R1 | Resolver | `AttributeResolver` nicht erreichbar | deny (`attrs.unavailable`) |
| C1 | Kontrolle | Kill-Switch `writes` / `all` | writes deny / alles deny |
| C2 | Kontrolle | Approver-Timeout / nicht erreichbar | deny |
| C3 | Kontrolle | Audit-Zeile gelöscht/geändert | `audit verify` rot mit Position |
| C4 | Kontrolle | Audit-Kette neu berechnet | `audit verify` rot (Checkpoint) |
| C5 | Kontrolle | `local` oder `auto-approve` ohne `--dev` | lint-Fehler, Start verweigert |
| C6 | Kontrolle | Panic in Constraint (Fuzz) | deny, Prozess lebt |
| C7 | Kontrolle | Audit-Verzeichnis nicht schreibbar | deny |

### 11.4 Gates

```
cargo test --workspace                                       # Unit + Vektoren + Core-Szenarien
cargo test -p agent-scope-eval --features keycloak           # Referenz-Suite gegen echten Keycloak
agent-scope eval --generate --suite examples/acme/eval --gate --mutate
```

| Gate (PR, hart) | Schwelle |
|---|---|
| `scope_violation`, `unapproved_write`, `delegation_escalation`, `token_accepted_invalid`, `upstream_saw_forbidden` | **0** |
| Konformitätsvektoren Rust ↔ TS (Entscheidungen + Tokens + Presets) | 100 % |
| Generierte Suite auf `examples/acme` und `examples/minimal` | 100 % |
| Rule-Coverage (jede Regel greift ≥ 1× und greift ≥ 1× nicht) | 100 % |
| Mutations-Gate (jede mutierte Regel lässt ≥ 1 Fall fehlschlagen) | 100 % |
| `audit verify` auf Eval-Lauf; Regression vs. Baseline | grün; kein pass → fail |
| `lint` auf `examples/`, `presets/`; Neutralitäts-Check (kein `acme`/`keycloak` in `crates/` außer `presets`-Loader) | 0 Befunde |
| `cargo deny`, `cargo audit`, `clippy -D warnings`, `cargo semver-checks` (ab 0.2), `npm audit --omit=dev` | grün |

Nightly: LLM-Angreifer (I1, I5), Fuzzing (Policy-Parser, Constraints, Normalisierung, Arg-Parser, SQL, Claim-Mapping; je 10 min), p99 `check` < 1 ms, Gateway-Overhead p95 < 10 ms (lokaler Upstream, gecachtes JWKS, ohne Approval/Exchange).

Konsumenten bekommen dieselbe Eval als **GitHub Action** (`agent-scope/eval-action`): `with: { policy, catalog, identity, suite }` → Report als PR-Kommentar.

## 12. Repo-Layout

```
agent-scope/
├── Cargo.toml                    # Workspace; MSRV = Maximum der Dependencies, Phase 0
├── crates/
│   ├── agent-scope-core/         # Modell, Engine, Normalisierung, Constraints, ClaimMapper, Decision+Trace.
│   │                             # Kein I/O, keine Uhr. #![forbid(unsafe_code)], unwrap/expect/panic = deny
│   ├── agent-scope-identity/     # TokenVerifier (OIDC Discovery, JWKS), AttributeResolver, Mini-STS, PRM
│   ├── agent-scope-audit/        # Events, AuditSink-Impls, Hash-Kette, Checkpoints, Verifier
│   ├── agent-scope-mcp/          # MCP-Adapter: rmcp-Middleware, Listen-Filter, Arg-Kanonisierung, Pinning
│   ├── agent-scope-rig/          # rig-Adapter (ScopeHook)
│   ├── agent-scope-a2a/          # A2A-Adapter (Skill-Aufrufe ↔ Action), dünn
│   ├── agent-scope-gateway/      # Binary: axum + rmcp, Upstreams, UpstreamAuth, Approval, Admin-API
│   ├── agent-scope-cli/          # init | lint | explain | catalog | audit | eval | dev
│   ├── agent-scope-eval/         # Runner, Generatoren, Referenz-Auswertung, Report, Gates, Mutation
│   └── agent-scope-wasm/         # wasm-bindgen-Exporte
├── packages/agent-scope/         # npm: core (WASM) + guard + /identity + /mcp + /ai-sdk
├── presets/                      # Claim-Mappings: keycloak, auth0, entra-id, okta, generic-oidc (YAML)
├── spec/
│   ├── *.schema.json             # catalog, policy, identity, gateway, audit (generiert)
│   ├── approver-webhook.md       # versioniertes Webhook-Protokoll
│   ├── admin-api.openapi.yaml
│   └── vectors/{decisions,tokens}/
├── examples/
│   ├── minimal/                  # 1 Tool, 2 Rollen, generic-oidc, ~20 Zeilen Policy
│   ├── acme/                     # Referenz: Keycloak-Realm, 3 Mock-Upstreams, compose, 40 Szenarien
│   ├── rust-inprocess/, rig-agent/, rmcp-server/, ts-guard/, ts-mcp-server/, ts-ai-sdk/
│   └── custom-extensions/        # eigener Approver, AuditSink, AttributeResolver, Constraint
├── .github/actions/eval/         # wiederverwendbare Eval-Action
└── docs/ (concepts.md, policy-reference.md, identity.md, extending.md, threat-model.md, consuming.md, spikes.md)
```

## 13. Referenz-Setup `examples/acme` (Keycloak)

`examples/acme/compose.yaml` startet Keycloak (**[Annahme]** ≥ 26.2, beim Bau pinnen), Gateway, Mock-Upstreams `hr`, `crm`, `docs` (deterministisch, protokollieren eingehende Requests inkl. Auth-Header).

| Element | Inhalt |
|---|---|
| Realm | `acme`, Access-Token-Lifespan 5 min |
| User Profile | Attribute `org_unit` (single), `tenants` (multi) deklariert. **[Annahme]** Seit KC 24 werden nicht deklarierte Attribute verworfen. |
| Realm-Rollen | `hr-member`, `hr-lead`, `it-member`, `it-admin`, `sales-rep`, `sales-lead`, `finance` |
| User (Passwort `dev`) | `hanna`, `henrik`, `ivo`, `ines`, `sven` (tenants `[dach]`), `sara` (`[dach, enterprise]`), `fiona` |
| Client Scopes | je agent-scope-Scope ein optionaler Client-Scope |
| Clients | `acme-console` (public, PKCE), `acme-bot`, `acme-research`, `acme-action` (confidential), `agent-scope-gw` (confidential), `hr-mcp`, `crm-mcp` (Audiences) |
| Mapper | `org_unit`, `tenants` → Claims; Audience-Mapper Gateway-URL |
| Token Exchange | **[Annahme]** V2 per Client-Schalter, ohne Fine-Grained-Permissions; Spike |
| RFC 8707 | **[Annahme]** `resource`-Parameter wird ignoriert, `aud` via Mapper; Spike |

`examples/minimal` braucht keinen Keycloak: es nutzt den eingebauten Dev-Issuer, damit der Quickstart ohne Docker läuft.

## 14. API-Stabilität und Versionierung

| Fläche | Regel |
|---|---|
| Rust-API | SemVer; `#[non_exhaustive]` auf allen öffentlichen Structs/Enums; `cargo semver-checks` in CI ab 0.2 |
| Traits | vor 1.0: Änderungen nur in Minor mit Changelog-Eintrag „Breaking for implementors“; nach 1.0: Major |
| Policy-/Catalog-/Identity-Format | eigenes `version: N`; ältere Versionen werden mindestens eine Minor-Version lang gelesen; `agent-scope migrate` + Migrations-Lint |
| Audit-Event-Schema | `v` im Event; Felder nur hinzufügen, nie umdeuten |
| Webhook-Approver, Admin-API | versioniert (`/v1/`), dokumentiert in `spec/` |
| npm ↔ Crates | gleiche Minor-Version für Core und npm-Paket |
| **1.0-Kriterien** | Policy-Format `version: 1` eingefroren, ≥ 2 externe Konsumenten (Company Bot + ein TS-Projekt), Threat Model reviewt, keine offenen Annahmen mit Sicherheitsbezug |

## 15. Phasen

Szenarien und Vektoren werden ab Phase 1 vor der Implementierung geschrieben.

| Phase | Inhalt | Tage | Abnahme |
|---|---|---|---|
| 0 | Workspace, CI-Gerüst, `cargo deny`, MSRV, YAML-Crate. Spikes: rig-Hook, rmcp Server+Client inkl. Session-ID + Progress, Keycloak Token Exchange V2 (`act`, User Profile, `resource`) | 1 | `docs/spikes.md` mit Entscheidungen: YAML-Crate, rmcp-Transport, Mini-STS-Bedarf |
| 1 | Core: Modell (§4), Catalog mit eigenen Arten, Policy, Normalisierung, Auswertung (§7), Constraints inkl. SQL, Delegation, `Constraint`-/`Engine`-Trait, Decision+Trace, `explain`, Lint, JSON-Schemas | 2½ | ≥ 60 Unit-Tests; Entscheidungs-Vektoren ≥ 50 grün; jede Lint-Regel mit Positiv-/Negativ-Test; eigene Action-Art `x-payment` in Tests; `check` p99 < 1 ms |
| 2 | Identity: `ClaimMapper` (JSON-Pointer) im Core, Presets + Fixtures, `TokenVerifier` mit OIDC Discovery und mehreren Issuern, `AttributeResolver` (`static`, `http`), Dev-Issuer, PRM; Keycloak-Realm für acme | 1½ | Token-Vektoren ≥ 25 (alle Presets) grün; Token-Suite gegen Keycloak und Dev-Issuer grün; R1 grün |
| 3 | Audit + CLI: `AuditSink`-Impls, Kette, HMAC, Checkpoints, Verifier, Schema; `init`/`lint`/`explain`/`catalog`/`audit verify` | 1 | C3, C4 grün; `agent-scope init` + `lint` + `explain` in < 5 min ohne Docker |
| 4 | MCP-Adapter + Gateway: Middleware, Upstreams (HTTP), `UpstreamAuth`, Namespacing, Session-Bindung, Filter, Enforcement, Kanonisierung, Pinning, `catalog pull`, Caps, Server→Client-Block, Approval (Webhook-Protokoll), Kill-Switch, Hot Reload, Admin-API, Panic-Handling | 3 | Inspector: Hanna sieht nur HR-Tools; T6, V1–V4, S1, S2, I2–I4, P1–P3, C1, C2, C5–C7, L2, L3 grün; p95 < 10 ms |
| 5 | Eval-Framework: Runner, Generatoren (§11.2) mit Referenz-Auswertung, Referenz-Suite komplett, Report, Baseline, Coverage, Mutation, CI-Gates, wiederverwendbare GitHub Action; nightly LLM-Angreifer + Fuzz | 1½ | Generierte Suite findet einen absichtlich eingebauten Engine-Bug (Mutationstest der Engine, nicht nur der Policy); Action läuft in einem Test-Repo |
| 6 | TS: WASM-Build, `createScope`, `guard`, `/identity` (jose + Presets), `/mcp`, `/ai-sdk`, Vektoren in TS, Trap → deny | 1½ | Vektoren 100 %; Beispiele `ts-guard`, `ts-mcp-server`, `ts-ai-sdk` laufen; Bundle-Größe dokumentiert |
| 7 | rig- und A2A-Adapter, `examples/custom-extensions`, Doku (Concepts, Policy-Referenz, Identity, Extending, Threat Model, Consuming), Release-Vorbereitung | 1½ | Quickstart `examples/minimal` in < 10 min auf frischem Clone ohne Docker; Extending-Guide: eigener Approver in < 50 Zeilen; **kein Publish ohne Tims Freigabe** |
| STS | Mini-STS (falls Spike es verlangt) | 1 | D1–D3 mit echten Tokens grün |

**Summe: ~15 Tage** (14 ohne STS).

## 16. Definition of Done

- [ ] `examples/minimal` läuft ohne Docker; `examples/acme` per `docker compose up` mit Keycloak + Gateway + Mocks.
- [ ] Token-, generierte und Referenz-Suite grün, harte Gates 0, Coverage und Mutation 100 %, Baseline eingecheckt.
- [ ] Rust- und TS-Vektoren identisch grün, inkl. aller Presets.
- [ ] Jeder Erweiterungspunkt (§5) hat eine mitgelieferte Implementierung, ein Beispiel in `examples/custom-extensions` und einen Test „Fehler in der Erweiterung → deny“.
- [ ] Kein Acme-/Keycloak-Begriff außerhalb von `examples/` und `presets/` (CI-Check).
- [ ] Jede Entscheidung hat `rule` + `reason`; `explain` reproduziert sie; das Modell sieht nur den generischen Text.
- [ ] Audit-Kette verifizierbar, Manipulation und Neuberechnung werden gefunden; Event-Schema veröffentlicht.
- [ ] Keine Code-Stelle, an der ein Fehler zu `allow` führt (`Decision` ohne `Default`, `check` ohne `Result`, Clippy-Lints, `catch_unwind`, Trap-Handling, Panic-Tests auf allen Wegen).
- [ ] Doku: Concepts, Policy-Referenz, Identity (inkl. „eigenes Preset beitragen“), Extending, Threat Model, Consuming (Rust, TS, Gateway), Abgrenzung (§2.1).
- [ ] Lizenz (Empfehlung `MIT OR Apache-2.0`, Tims Entscheidung), SECURITY.md, CONTRIBUTING.md.

**Später:** Cedar-`Engine`, OpenFGA-`AttributeResolver`, Introspection (RFC 7662), stdio-Upstreams, Circuit-Breaker, Ergebnis-Redaktion, Rate Limits, Python-Binding, napi, Policy-Diff („was ändert sich für wen“), signierte Policies, `lint --idp`, weitere Adapter (LangChain.js, OpenAI Agents SDK).

## 17. Erste Konsumenten

| Konsument | Weg | Was er vom Framework braucht |
|---|---|---|
| **Acme Company Bot** (Rust/rig) | Gateway für MCP-Tools, Core + `agent-scope-rig` + `agent-scope-a2a` in-process, Webhook-Approver = eigene Inbox | Admin-API für die Console, Audit-Events für Phoenix |
| **agent-approval-gate** | liefert den `Approver`-Trait + Implementierungen. Benötigt: Approval-Kontext mit `args_hash`, Approver-ID in der Antwort | 0.2.0 veröffentlichen (crates.io erlaubt keine Git-Dependencies) |
| **docrag-bench** (Python) | als Upstream hinter dem Gateway | nichts, kein Binding |
| **incident-triage-demo** (TS) | npm `guard` oder `/mcp` | WASM-Paket |
| Fremde Teams | Gateway + `catalog pull` + Preset ihres IdP, oder npm/Crates | Quickstart, Presets, Eval-Action |

## 18. Trim & Showcase

**Nicht verhandelbar:** fail-closed überall (auch bei Erweiterungsfehlern), Regeln nur einschränkend, neutraler Core, MCP-Gateway mit Filter + Enforcement + Kanonisierung, Schnittmenge inkl. Delegation, Eval mit harten Gates.

| Baustein | Wirkung pro Stunde | Stufe |
|---|---|---|
| Neutraler Core + Vektoren + Traits | sehr hoch (macht es zum Framework) | 0 |
| Claim-Mapping + `keycloak`/`generic-oidc` | sehr hoch | 0 |
| MCP-Gateway list/call | sehr hoch (Demo „Hanna sieht kein Gehalt“) | 0 |
| Generierte Eval + Gates | sehr hoch (Nutzer bekommen Security-Nachweis für *ihre* Policy) | 0 |
| Audit + `explain` + `init` | hoch | 0 |
| Approval (Webhook-Protokoll) | hoch | 1 |
| Rug-Pull-Pinning, `catalog pull` | mittel–hoch (Einstieg für bestehende MCP-Landschaften) | 1 |
| WASM/npm mit `guard` | hoch (zweite Sprache) | 1 |
| Weitere Presets (auth0, entra-id, okta) | mittel, billig (nur YAML + Fixtures) | 1 |
| Mini-STS, Token Exchange | mittel, aufwendig | 1 |
| AI-SDK-, rig-, A2A-Adapter, GitHub Action | mittel | 2 |
| Nightly LLM-Angreifer, Fuzz, Hot Reload | mittel | 2 |

- **Stufe 0 (~8½ Tage):** Phase 0, 1, 2 (nur `keycloak` + `generic-oidc`), 3, 4 (ohne Approval, Pinning, Hot Reload, Exchange), 5 (ohne Action, ohne Nightly).
- **Stufe 1 (+4½ Tage):** Approval, Pinning + `catalog pull`, Token Exchange + STS, WASM/npm (`guard`, `/mcp`), weitere Presets.
- **Stufe 2 (+2 Tage):** AI-SDK-, rig-, A2A-Adapter, GitHub Action, Hot Reload, Nightly.

**Bewusst weggelassen:** eigene Policy-Sprache, Injection-Detektor, UI. Nie aufweichen: Default-Deny, Fehler = deny, Regeln und Erweiterungen nur einschränkend, Approvals ungecacht und an Args gebunden.

## 19. Annahmen und offene Fragen

| # | Punkt | Status |
|---|---|---|
| 1 | npm-Name `agent-scope` wieder belegbar? | offen, vor Publish; Fallback `@byquexo/agent-scope` |
| 2 | Keycloak Token Exchange V2: `actor_token`/`act`, Client-Konfiguration, User Profile, `resource` | **[Annahme]**, Spike nach Phase 0 |
| 3 | Claim-Formen von Auth0, Entra ID, Okta (Rollen-Claims, `azp`-Äquivalent, Token-Typ) | **[Annahme]**, beim Preset-Bau aus Doku verifizieren; nur Fixture-getestet |
| 4 | rmcp 3.8: Streamable-HTTP-Server + Client im selben Prozess, Session-ID, Progress | **[Annahme]**, Spike Phase 0 |
| 5 | MCP-Clients verlängern Timeouts bei Progress-Notifications | **[Annahme]**, Spike Phase 0 |
| 6 | rig-Hook-API stabil genug | rig 0.46.0 vom 31.10.2026 **[Verifiziert]**, pre-1.0, exakt pinnen |
| 7 | `async fn` in öffentlichen Traits ohne `async_trait` mit `dyn`-Nutzung (Gateway hält `Box<dyn Approver>`) | **[Annahme]**: native async-Traits sind nicht dyn-kompatibel → für dyn-genutzte Traits `async_trait` oder handgeschriebene `BoxFuture`-Signatur. Entscheidung Phase 0. |
| 8 | `agent-approval-gate`: Repo 0.2.0, crates.io 0.1.0, npm 0.1.0 | **[Verifiziert]**. 0.2.0 vor Phase 4 veröffentlichen, inkl. `args_hash`/Approver-ID. Tims Entscheidung. |
| 9 | Vercel-AI-SDK-Tool-Shape stabil genug für Adapter | **[Annahme]**, Version pinnen |
| 10 | Lizenz | Empfehlung `MIT OR Apache-2.0`, Tims Entscheidung |
| 11 | ~15 Tage realistisch? | ohne Puffer; Risiko Phase 4 (rmcp) und Phase 5 (Generatoren). Bei Verzug: Stufe 0 fertig, Rest schieben. |
