# Implementation doc D1: review-database — install/update state schema

**Repo:** `aicers/review-database` · **Grounded on** `origin/main` @ `1285590`
(v0.46.0; DB format `COMPATIBLE_VERSION_REQ = ">=0.46.0,<0.47.0"`).
Re-verify before relying.

**Status:** Accepted; implementation is decomposed from §6.
`aicers/review-database` is an aicers repo (in-repo issue flow,
AgentCoop-decomposable, no external gate). The D set is `review-database`
(this doc, D1), `review` (D2),
and `review-web` (D3). This is the review-database slice of the RFC-D scope —
made implementation-grade (the one coupled RFC across review-web + review +
review-database); it is referred to as **D1** across the RFC set. Its filing
home is `aicers/review-database` (`docs/rfcs/`, its first RFC). This document
is **self-contained**: it restates inline every cross-repo contract an issue
needs, because AgentCoop issues take their text as sole input. It is the
**first** of the three D docs to implement. The three repos do **not** land in
a simple `review-database → review → review-web` order — review (D2)
implements the `PackageDeployer` **trait defined in review-web** (D3), so the
precise cross-repo order is **review-database (D1 types) → review-web trait
definition (D3 §4) → review impl (D2) → review-web resolvers / upload route /
UI-facing surface (D3 §5a/§5b/§5c)**. Nothing in **this** doc depends on the other
two; both of them depend on the types defined here.

## 1. Scope

review-database today stores per-node **config** (applied + draft) and a
coarse **config-reload** status. It has **no** notion of installed software:
no version, no install/run lifecycle, no package-operation record. This doc
adds, additively:

1. an **install/update lifecycle** value type (distinct from the existing
   config-reload `Status`);
2. **`installed_version` + `installed_commit` + `lifecycle`** on `Agent` and
   `ExternalService`;
3. a **core-component registry** table (REView / aice-web-next / roxyd /
   bootroot — host-fixed infrastructure, not agents);
4. an **`operation_attempt`** ledger (durable in-flight package operations,
   for crash-safe resume);
5. the **migration** (data-dir migration + `COMPATIBLE_VERSION_REQ` bump)
   and the **`Node::update` diff** extension to persist the new fields.

There is **no `desired_version`** — install/update is an immediate imperative
action, not a stored intent (RFC-D model note). Only **actual** state is
stored, for display.

## 2. Current state (grounded, `origin/main` @ `1285590`)

- **`Node`** (`src/tables/node.rs:70`): `id`, `name`, `name_draft`,
  `profile`, `profile_draft`, **`agents: Vec<Agent>`**,
  **`external_services: Vec<ExternalService>`**, `creation_time`. **The
  `agents`/`external_services` on the public `Node` struct are an ASSEMBLED
  view — they are NOT stored inside the node record.** The persisted node
  record is `Inner` (`node.rs:783`), which holds only the agent/external
  **string keys** (`agents: Vec<String>`, `external_services: Vec<String>`);
  the actual **`Agent` and `ExternalService` VALUES are stored in their own
  column families** — `AGENTS` (`"agents"`) and `EXTERNAL_SERVICES`
  (`"external services"`) (`tables.rs`, `MAP_NAMES`) — keyed per record and
  opened as `Table::<Agent>` / `Table::<ExternalService>`. Atomic diff/commit
  of a node is **`Node::update(id, old: &Update, new: &Update)`**
  (`node.rs:459`), where `Update` (`node.rs:82`) carries the assembled
  `agents`/`external_services`; but the per-record values live in the AGENTS /
  EXTERNAL_SERVICES CFs, which is what the migration (§4f) must walk.
- **`Status`** (`src/tables/node.rs:35`): `Disabled=0`, `Enabled=1`,
  `ReloadFailed=2`, `Unknown=u8::MAX` — a **config-reload** state. Keep it
  as-is; the new lifecycle is a **separate** field.
- **`Agent.key` is composed per instance, but it is not where the instance
  number is read from.** review resolves an agent from its certificate as
  `agent_id = <instance>.<service>` and `host_id = <host>.<domain>`
  (`review/src/tls/certificate.rs`), then finds the node by `host_id` and
  the agent **within that node** by `a.key == agent_id`
  (`review/src/agent/requests.rs`); review-web composes the same pair
  (`gen_agent_lookup_key`, `graphql/node/crud.rs`). So `key` is
  `<instance>.<service>` and is unique **per node**, exactly matching the
  hierarchical identity (RFC-A §4) where an instance number is scoped by
  `{service_name}.{hostname}`. Two `piglet` instances on one node are two
  rows, `001.piglet` and `002.piglet`, under the same `node_id` and the
  same `kind` — **no new key**. What this does invalidate is any assumption
  that a node holds at most one row per `AgentKind`.
  **An earlier revision concluded from this that multi-instance needs no new
  field, and that half is wrong.** `key` is a `String` with no documented
  format, so recovering the number from it would make a contract of a value
  that has none, and the failure would be **silent**: the day a key is minted
  differently every reader shows a wrong number rather than an error. The
  number is therefore recorded in its own field, `instance` (§4b), and `key`
  gains no format in exchange.
- **`Agent`** (`src/tables/agent.rs:38`): `node_id`, `key`, `kind: AgentKind`,
  `status: AgentStatus`, `config: Option<AgentConfig>`,
  `draft: Option<AgentConfig>`. `AgentKind` (`agent.rs:30`): `Unsupervised=1`,
  `Sensor=2`, `SemiSupervised=3`, `TimeSeriesGenerator=4`. Update at
  `agent.rs:169`.
- **`ExternalService`** (`src/tables/external_service.rs:36`): `node_id`,
  `key`, `kind: ExternalServiceKind`, `status`, `draft`.
  `ExternalServiceKind` (`external_service.rs:30`): `DataStore=1`,
  `TiContainer=2`. Update at `external_service.rs:155`.
- **Migration mechanism** (`src/migration.rs`): `COMPATIBLE_VERSION_REQ`
  (`:111`) is the DB-format range; `migrate_data_dir` (`:130`) runs a
  `Vec<Migration>` where `Migration = (VersionReq, Version, fn)`
  (`:135`, `:177`) — e.g. `migrate_0_45_to_0_46` (`:216`),
  `migrate_0_44_to_0_45` (`:380`). Old-shape structs used during a migration
  live in `src/migration/migration_structures.rs`. Records are bincode in
  RocksDB, so a struct field addition needs a data migration that reads the
  old shape and writes the new.

## 3. Contract this repo must provide (restated, self-contained)

The manager (review) and the API (review-web) consume these types:

- **Lifecycle** = the install/run state of a package on a host, **actual**
  and **distinct from `Status`** (config-reload). Values (with `Unknown` as
  the unrecognized-value fallback, §4a): `NotInstalled`,
  `Installing`, `Running`, `Stopped`, `Failed`, `Removing`, `Unknown`. `UpdateAvailable`
  is **not** stored — review computes it per build (installed
  `(version, commit)` ≠ the store's `latest_build`).
- **Build identity is `(version, commit)`**, never `version` alone: the same
  `version` may carry different `commit`s (a pre-release rebuilt from
  a new commit, or a hotfix without a version bump — RFC-A §4; `version` is an
  opaque display label, not required to be semver). So the
  installed build is recorded as **both** `installed_version` **and**
  `installed_commit`.
- **Core components are host-fixed infrastructure** (REView, aice-web-next,
  roxyd, bootroot), **not** agents or external services — they get their own
  registry keyed by `(component, host)`. **bootroot** is flagged
  installer-managed / not UI-updatable.
- **`operation_attempt`** is a **durable** record of a package operation,
  written before an apply begins and **finalized in place** — with its outcome
  recorded — on terminal success or failure. It is **not** a standing desired
  state, and it is **not deleted on completion**: the terminal record is
  **retained** for display and audit (§4d), because it is the only thing that
  can answer "did the last update succeed, fail, or roll back?" — RFC-D2 §4b
  reads it for that, and RFC-E §5 depends on it to re-derive state after a
  self-update reconnect, when the UI has no other source. It must uniquely
  identify a host-scoped operation for crash-safe resume, and hold the
  compensation still owed (e.g. a pending deregister).
- **[DECISION] `operation_attempt` is NOT aice-web-next's `apply_attempts`,
  and neither replaces the other.** aice-web-next already ships an
  attempt ledger of its own — an `apply_attempts` table in its auth
  database, with `attempt_id`, `draft_fingerprint`, `planned_dispatches`,
  `expires_at`, an `executing_lock` and a `pending / executing / succeeded /
  failed_retryable / failed_terminal / stale / expired` status, plus a
  stale-lock sweep. It tracks **one operator's config-Apply run through the
  UI**: which drafts that click intended to dispatch, and whether the
  browser-side run is still holding the lock. `operation_attempt` tracks
  **the package operation REView is executing on a host**, survives a REView
  restart, and carries the compensation owed to bootroot. They sit on
  different sides of the API, key on different things, and have different
  lifetimes; the UI ledger cannot answer "is there an owed `Deregister`" and
  this one cannot answer "did that click finish dispatching". Implementations
  must not collapse them or drive one from the other — but the naming
  overlap is a live trap, so a reader of either should be pointed at this
  paragraph.

## 4. Changes

### 4a. New value type: `Lifecycle`

- Add a `Lifecycle` enum (a `#[repr(u8)]`, `FromPrimitive`), in a new
  `src/tables/lifecycle.rs` (or beside `Status` in
  `node.rs`): `NotInstalled=0`, `Installing=1`, `Running=2`, `Stopped=3`,
  `Failed=4`, `Removing=5`, `Unknown=u8::MAX`.
- **[DECISION] An unrecognized stored value maps to `Unknown`, NOT to
  `NotInstalled` — and the fallback lives at the CALL SITE.** num-derive's
  `FromPrimitive` yields `from_u8(..) -> Option<Self>`, so "the derive's
  default" is not a thing this crate can express (unlike `num_enum`, which the
  wire crate uses, RFC-C §4). The rule is therefore stated where it is
  enforceable: **every conversion from a stored integer resolves `None` to
  `Unknown`**, and no call site may write `unwrap_or(NotInstalled)`.
  A default of `NotInstalled` inverts the sentinel's purpose: a value this
  build does not recognize — a row written by a newer build, or a byte read
  back after a partial rollback — would be presented as *nothing is
  installed* on a host that is in fact `Failed` or `Running`, and the UI
  would offer an install where a remediation is due. `Unknown` is the value
  that says "this build cannot interpret what is stored," which is exactly
  the truth in that case. (`Status`'s own default is `Enabled`
  (`node.rs`) — but note that is a `#[default]` **serde/Default** attribute on
  a config-reload state where "no adverse reload recorded" is sound, not a
  `FromPrimitive` fallback; the two are not analogous.)
- **[DECISION] This encoding is INDEPENDENT of review-protocol's wire
  `Lifecycle` (RFC-C §4), and neither side may read the other's number.**
  The variant sets match, the numbers do not: with the plain serde derive
  this repo uses, bincode persists the **variant index**, so
  `Lifecycle::Unknown` reaches disk as **6** rather than `u8::MAX` — exactly
  as `Status::Unknown` persists as **3** today, not `255`. The `u8::MAX`
  discriminant is the `FromPrimitive` house style, not the stored value. The
  wire type pins its own encoding to the discriminant with an unknown-value
  fallback (RFC-C §4); the manager maps between them.
- It is **orthogonal to `Status`** (a service can be `Running` yet
  `ReloadFailed`); do **not** fold the two.

### 4b. `Agent` + `ExternalService`: install/update fields

- Add to **both** `Agent` (`agent.rs:38`) and `ExternalService`
  (`external_service.rs:36`), beside `draft` (and `config`, which only
  `Agent` has — `ExternalService` stores a draft alone, §2, because
  Giganto's applied configuration lives in Giganto):
  - `installed_version: Option<String>`
  - `installed_commit: Option<String>`
  - `lifecycle: Lifecycle`
  - `bound_addrs: Vec<(String, String)>` — the addresses this instance
    **actually bound**, as `(config-key, host:port)` pairs reported by roxyd
    (RFC-C §4 `PackageState.bound_addrs`, RFC-B §9). **Empty for everything
    except Giganto**: the four agent modules bind no service address at all
    (they dial out on an ephemeral port), so in practice this is populated on
    `ExternalService` and stays empty on `Agent`. It is recorded rather than
    derived because **only the host knows where the instance actually ended
    up**. **REView chooses the addresses** and sends them on `Install` as
    `bind_addrs` (RFC-D2 §4f, RFC-C §4); roxyd renders them verbatim before
    the unit starts and never picks. That reverses the earlier position that
    roxyd renders the component's own defaults and chooses nothing, and it
    changes what this field is **for**: not how the manager learns what the
    instance got, which it already knows, but whether the host **agrees**.
    An instance that failed to bind reports nothing here, and that is the
    signal.
    So this field has **one** reader, not two. The direct-to-Giganto config
    push now dials **the allocated address** (RFC-D2 §4b/§4f) rather than the
    latest reported value, because the manager assigned it and does not need
    to read it back — and a reported value is empty exactly when the instance
    is down, which is when a destination is most needed. The UI reads it to
    show whether an instance is bound where it was placed (RFC-E §4).
  - `instance: Option<u32>` — the number of the instance this row **is**, the
    same option an `operation_attempt` carries (§4d) and the number the
    allocation table holds (§4g). It is `None` for a row with no instance
    dimension, and for a row written before the field existed. It is
    **recorded, never parsed out of `key`** (§2). It is the one field here
    the host does not report — the allocator assigns it and the row is
    created carrying it — but it is state rather than intent on the same
    terms as the rest: a later configuration edit never changes it.
- These are **actual** state (what roxyd reports). No `desired_*`. In
  particular `bound_addrs` is **observed, not intent**: it records where the
  instance *is*, while `draft`/`config` carry what the operator *wants*, and
  the two are deliberately not merged — after the first install the operator
  owns the ports through the config plane, and a later edit moves `config`
  without REView rewriting what roxyd reported.
- Update the `FromKeyValue` / `ValueTrait` impls and the embedded
  (de)serialization so the new fields round-trip. `Agent::update`
  (`agent.rs:169`) and `ExternalService::update` (`external_service.rs:155`)
  already diff the whole record; ensure they carry the new fields.

### 4c. Core-component registry (new table)

- New table (`src/tables/core_component.rs`), keyed by **`(component, host)`**:
  - `component: String` (canonical package-id: `review` / `aice-web-next` /
    `roxyd` / `bootroot` — RFC-A §4)
  - `host: String`
  - `installed_version: Option<String>`, `installed_commit: Option<String>`
  - `lifecycle: Lifecycle`
  - `installer_managed: bool` (**`true` for bootroot** — excluded from UI
    update; it is the trust anchor)
- **[DECISION] The `(component, host)` key is an unambiguously-encoded tuple,
  never a naive byte concatenation.** Both fields are variable-length strings,
  so concatenating their bytes collides — `("ab", "c")` and `("a", "bc")`
  would map to the same key. The key MUST be a **length-prefixed / serialized
  tuple** (or a delimiter that is **validated to not occur** in either field —
  `component` is a fixed package-id from the RFC-A §4 registry and `host` is a DNS
  label, so a reserved delimiter is viable, but the encoding must be stated and
  tested). This applies to a genuine **composite** key — here the
  `(component, host)` registry key — whose collision test exercises two
  non-empty registry/DNS-label segments (`("ab", "c")` vs `("a", "bc")` map to
  **distinct** keys, §5). **`operation_attempt` is NOT a composite key** — it is
  keyed by the single global `idempotency_key` (§4d), so it needs no
  composite-key encoding and no such collision test. (`Onboard`'s empty-string
  `target` / `package_digest` / resolved fields are **non-key data**, governed
  by §4d's one-consistent-absent-encoding rule, not by any key-collision test;
  neither `component` nor `host` is ever empty, so the `(component, host)` key
  has no empty-segment input.)
- roxyd is **per-host**, so multiple rows share `component = "roxyd"` with
  distinct `host`. REView/aice-web-next are singletons (one row each).
- **[DECISION] Its column family is registered together with the format bump
  (§4f), not ahead of it.** `StateDb::open` auto-creates any CF listed in
  `MAP_NAMES` (`tables.rs`), while `migrate_data_dir` returns early for a
  compatible `0.46.0` data dir (`migration.rs`) — so adding this CF to
  `MAP_NAMES` **before** `COMPATIBLE_VERSION_REQ` bumps would silently mutate a
  `0.46.0` data dir with a new CF and no version change. So the CF registration
  lands in the **same slice** as the format bump (§4f, §6 issue 5). Follow an
  existing simple table (e.g. `hosts.rs`/`status.rs`) for the CF-registration +
  open pattern.

### 4d. `operation_attempt` ledger (new table)

- New table (`src/tables/operation_attempt.rs`), a **transient** record:
  - **`idempotency_key: String` is the GLOBALLY UNIQUE key** (not a plain field
    beside a surrogate `id`). There is one key per logical operation, so the
    key **alone** identifies it — `host` and `target` are **data on the row,
    not part of the uniqueness key**.
    **Who generates it depends on whether the operation allocates.** For an
    **allocating install** it is the client-supplied `requestKey` (RFC-D3
    §5a), persisted verbatim: an allocating call forms a fresh
    `(host, target, instance)` on every attempt, so only a value the client
    holds across retries can dedupe the operator's intent, and holding it only
    in memory would let a resubmit after a REView restart allocate a second
    instance. For **every other operation** REView generates it, as before.
    **The format is a UUIDv4 in its canonical hyphenated form** and a value
    that does not parse as one is **refused**. Canonical is **lowercase**:
    the key is the row's identity, compared as the bytes it arrived as, so
    accepting `A`-`F` too would let one UUID arrive as two request keys,
    each finding nothing under the other and each allocating an instance.
    A client that holds a UUID uppercase renders it lowercase before
    submitting; nothing downstream normalizes it for them. That is a shape
    check and nothing more: it does not stop a client sending a constant or
    replaying a stored value, and this document does not pretend otherwise — **not
    re-using a key is a client obligation** (RFC-E §4), and the server cannot
    verify it.
    **A key that matches an existing row is resolved by comparing a stored
    DIGEST of the request, because the row does not otherwise carry enough to
    compare.** "Same payload" is not decidable from what
    `operation_attempt` holds today: it records the resolved
    `(version, commit)`, not the `BuildSelector` the operator submitted, so a
    selector that resolves to a different commit later would read as a
    different request when it is the same one — and as the same request when
    it is not. So the row gains
    **`install_intent: Option<[u8; 32]>`** — `Option`, because the
    non-allocating operations below store none — holding a SHA-256 over a
    **byte-exact** encoding. "Length-prefixed" is not a specification: a
    digest two REView builds compute differently turns every retry across an
    update into a `RequestKeyReused` refusal, so the transcript is fixed here
    and a **golden vector** ships with the implementation, so a change to it
    fails a test rather than a deployment. The hashed transcript is, in order:
    - `b"clumit-install-intent-v1"` — 24 bytes, domain and version separation;
    - `host` then `target`, each as a `u32` **big-endian** byte length
      followed by its UTF-8 bytes;
    - the selector's **kind** as a `u8` tag, pinned **here** rather than
      delegated: `0 = Version`, `1 = Commit` — `BuildSelector` is version
      **XOR** commit (RFC-D2 §3), and a table "beside the type" would let two
      implementations number them differently and disagree on every digest.
      Then its value length-prefixed in the same shape — the value **as
      submitted**, never its resolution;
    - `on_failure` as a `u8` tag: `0 = Rollback`, `1 = Hold`;
    - the `bind_addrs` list as a `u32` **big-endian count**, then each entry
      in ascending `listener_key` order as the length-prefixed key followed by
      the length-prefixed address rendered as `SocketAddr`'s own `Display` —
      `<ip>:<port>`, an IPv6 address in square brackets, lowercase, RFC 5952
      compressed — named explicitly so no implementation re-derives it.
      **`None` and an empty list are distinct**: `None` encodes count
      `u32::MAX`, an empty list encodes count `0`.

    Every length and count is `u32` big-endian and fixed width, so no field
    boundary can shift. Nothing else enters the transcript — not the instance
    number, which the call allocates, and not any timestamp.
    Then: a key whose stored `install_intent` **equals** the incoming one
    **returns that row**, which is what makes a retry idempotent; a key whose
    digest **differs** is refused with **`RequestKeyReused { request_key }`**,
    **non-retryable** — it is a client bug, and overwriting the first row
    would destroy a live attempt's record, including the allocation rows that
    hang off it. The digest is stored rather than the fields because the only
    question ever asked of it is equality; the refusal names the key rather
    than the difference for the same reason.
    **The comparison is repeated at the write**, against the row the write
    would replace and under that row's lock, because the lookup on its own
    reserves nothing: two requests carrying one key can both be told it is
    free, and without the second comparison the one that commits second
    replaces the attempt the first created instead of being refused.
    **And the lookup is not the decision to create.** Repeating the
    comparison catches the second request whose digest *differs*; the one
    carrying the *same* digest passes it and would go on to write its own
    allocation over the first attempt's row — which is the retry the
    idempotence above is about, so it is the one case that must not be
    handled by a write at all. So the store makes all three answers — create
    it, return the attempt already held, refuse the key — as **one decision
    under that key's own lock, in the transaction that writes**, and refuses
    to create a row carrying an `install_intent` by any other path. The
    request that gets there second is handed the attempt the first created,
    and releases the instance it had allocated for a row it did not write.
    **`install_intent` is `None` for every non-allocating operation.** Update,
    remove and onboard are keyed by a REView-generated value that is unique by
    construction, so there is nothing to compare — and a stored `None`
    presented with a digest, or the reverse, is a `RequestKeyReused` refusal
    like any other mismatch.
    **The dedupe guarantee is bounded by retention, and the bound is stated
    rather than implied.** An earlier revision claimed keys are never
    reclaimed while also saying retention frees them, which cannot both hold.
    The row **is** removed by the ordinary retention sweep, and a client that
    replays a stored request after its row is gone gets a **new** install —
    there is no tombstone. A permanent tombstone was considered and rejected:
    it is unbounded growth to defend against a client replaying a request days
    later, which the client contract already forbids. So the guarantee reads:
    **a repeated request is deduped for as long as its `operation_attempt`
    row survives retention**, which is far longer than any dialog lives.
    Crash-safe resume
    depends on **one** record per logical operation: a re-drive/resume with the
    same key **finds and returns the existing row, and never writes over it**.
    The write is **insert-once**: an insert whose key already exists is not an
    upsert but a read followed by the digest comparison above.
    **[DECISION]** enforce this by making the table **keyed by
    `idempotency_key`** (or, if a surrogate `id` primary key is kept, a
    **single global unique index on `idempotency_key`**) — **not** a
    `(host, target, idempotency_key)` composite, which would let one key spawn
    multiple rows and break the "one record per `idempotency_key`" acceptance
    (§5). A plain non-unique `idempotency_key` field is **not** sufficient —
    with this repo's table pattern it would admit duplicate attempts for the
    same retry/resume path. (The `(component, host)` registry key and other
    genuinely-composite keys still follow §4c length-prefixed encoding; the
    `operation_attempt` uniqueness key is not one of them.)
  - `host: String`, `target: String` (host-agnostic package-id), and
    **`instance: Option<u32>`** — the instance number this operation
    concerns (RFC-A §4), `None` for a component whose class has no instance
    dimension. **It records the number, NOT a composed name**, and it is the
    **same type the wire carries** (RFC-C §4/§5) so nothing has to convert
    or compare string forms — the three-digit zero-padded rendering belongs
    to the SAN and the `registration_id` (RFC-A §4), never to this field.
    It is the allocated number for a module (§4g) and `None` for a core
    component. The owed
    `Deregister` this row may carry is driven with
    `(service_name, host, instance)` and the **registrar** derives the
    composed identity from those (RFC-C §5, RFC-F §5.1/§5.5), so a name
    composed here would be a second, un-verified derivation of something
    review does not own. Together with `target` and `host` the triple is
    exactly what a re-drive needs.
    For an **`Onboard`** attempt `host` is the pending host and `instance`
    is empty (a host's roxyd is single-instance);
    **`target`, `package_digest`, and the
    resolved-build fields (`resolved_version`, `resolved_commit`) are all the
    empty string** — an onboarding has no package yet (RFC-D2 §4d). (Use one
    consistent "absent" encoding: the empty string for **every** package-scoped
    field — not a mix of empty-`String` for some and `Option` for others. Every
    package-scoped field is a plain `String` that is empty **exactly when**
    `action = Onboard`, so a reader never has to guess an absent value. These
    are non-key data fields, so the empty string here raises no key-collision
    concern — `idempotency_key`, the table's only key, is never empty.)
  - `action` (enum `Install` / `Update` / `Remove` / **`Onboard`**) — this
    records the **operator's intent** for display/audit; it is **not** a wire
    distinction (`node.package` has no separate update code — `install =
    update` on the wire, RFC-C §4 / RFC-D2 §4b). `Install` vs `Update` here
    just reflects whether the target already had a build; **`Onboard`** is the
    pending host-onboarding record (no package, host not yet checked in, cleaned
    up on expiry/cancel — RFC-D2 §4d).
  - `package_digest: String`
  - `resolved_version: String`, `resolved_commit: String` (the exact build
    the selector resolved to — **both**, per §3)
  - `phase` (coarse, REView-driven — the manager sets it at the boundaries it
    controls; the fine verify/enroll/start sub-steps are roxyd-internal and
    not stored, RFC-C §4)
  - `cleanup_state` (compensation still owed — e.g. a pending `Deregister`
    on uninstall, or an owed teardown of a never-checked-in onboarding
    identity, RFC-D2 §4d)
  - `started_at: DateTime<Utc>`, `retry_policy`, `outcome: Option<...>`
  - `expires_at: DateTime<Utc>` — the **durable absolute deadline**, set for
    **every** action, not only `Onboard`. For an `Onboard` it is the
    join-token wrap TTL at mint, so the expiry/teardown clock **survives a
    REView restart** (the single-use token itself is not persisted,
    RFC-C §5). For `Install`/`Update`/`Remove` it is a **generous** absolute
    deadline — large enough that a slow link carrying a core-component image
    is normal — and it exists because the apply `retry_policy` budget is
    advanced **only on a roxyd check-in** (RFC-D2 §4b): a host that never
    returns would otherwise leave its attempt non-terminal forever, holding
    an instance number, the `(host, target, instance)` single-flight slot, a
    minted bootroot identity and an in-flight card (§4g). The same sweep
    finalizes any expired attempt (RFC-D2 §4d).
  - `backup_id: Option<u32>`, `pre_update_version: Option<String>` — set
    **only** for a core-component update of **REView** (§4f, RFC-D2 §4e):
    the id returned by the pre-update `backup::create` and the format version
    in effect **before** the swap. The rollback restores exactly that snapshot
    via `backup::restore(store, Some(backup_id))` and rewrites both `VERSION`
    markers to `pre_update_version`. **"Restore latest" is deliberately not
    used** — the periodic backup scheduler (`review/src/lib.rs:85`, always on:
    `backup_schedule` is a `(Duration, Duration)` with no disable flag) can add
    a backup, and `create_new_backup_flush` purges beyond
    `num_of_backups_to_keep`, so "latest" is not stable across the update
    window. `None` for every other attempt. (These two are core-update-scoped,
    not package-scoped, so they use `Option` rather than the empty-string
    convention above; both use the same encoding as each other.)
- **Why these fields (do not trim):** `target` is host-agnostic but modules /
  roxyd / core components apply **per host**, so without `host` +
  `instance` + resolved `(version, commit)` + `idempotency_key`,
  two concurrent applies of the same package to different hosts — or two
  commits of one version — are indistinguishable on resume.
- Written **before** an apply begins. **The apply outcome and the owed
  `cleanup_state` are tracked separately, because the `cleanup_state` obligation
  is DURABLE and is NOT bounded by the apply's `retry_policy` budget.** The
  apply itself reaches a terminal outcome (success, or `Failed` once the small
  terminating retry budget is spent — RFC-D2 §4b), but if it terminates `Failed`
  with a teardown still owed (e.g. the registrar was unreachable within the
  apply budget), the owed `Deregister` **persists in `cleanup_state`** and is
  re-driven when the registrar becomes reachable — so a registrar outage past
  the apply budget never orphans the minted identity. An attempt is **fully
  discharged** only once the apply is terminal **and** any owed `cleanup_state`
  is discharged.
- **[DECISION] A fully discharged attempt is FINALIZED IN PLACE and retained,
  and the row carries `finalized_at: Option<DateTime<Utc>>` so "retained for
  how long" is measurable at all.** `started_at` and `expires_at` cannot
  express it — the first is when the attempt began and the second is a
  deadline it may never reach.
  **The invariant is `finalized_at.is_some()` if and only if the outcome is
  terminal AND `cleanup_state` is empty**, which is the "fully discharged"
  state the bullet above defines — not merely "terminal". An earlier revision
  wrote it in the same transaction as the terminal outcome, which is wrong for
  exactly the case that bullet exists for: an apply that terminates `Failed`
  with a teardown still owed is terminal and **not** finished, and stamping it
  then would start a retention clock on a row that still has work to do.
  So it is written by whichever transaction **completes the pair**: the
  terminal-outcome write when nothing is owed, and otherwise the later
  transaction that discharges the last of `cleanup_state`. A terminal row that
  still owes cleanup carries `finalized_at = None`, and the retention sweep
  therefore cannot reach it — which is the behaviour that was wanted.
  "Transient" describes the *obligation*, not the row. Deleting the row on
  completion would break the two readers that need it after the fact: RFC-D2
  §4b's "what did the operator last do here" display/audit, and RFC-E §5's
  self-update recovery, where reading the operation record is the **only** way
  the UI learns whether a REView / aice-web-next update succeeded (the response
  channel was torn down by the swap, RFC-C §4). So, and these two rules are
  stated together because an earlier revision had them contradicting each
  other:
  - **The most recent terminal attempt per `(host, target, instance)` is kept
    indefinitely**, along with every attempt still non-terminal or still owing
    `cleanup_state`. It is the same triple the single-flight key uses (below),
    so a module running several instances keeps one record each rather than
    collapsing to one per `(host, target)` and masking a sibling's outcome.
    This is the row RFC-D2 §4b's "what did the operator last do here" and
    RFC-E §5's self-update recovery read, and neither has a useful expiry.
  - **Every OLDER terminal attempt is swept 30 days after its
    `finalized_at`.** Without the prune, every install, update, remove and
    onboard accumulates forever.
  **[DECISION] ONE new structure — a latest pointer — and the sweep scans
  rows.** The primary key is `idempotency_key` and the existing indexes cover
  non-terminal rows, owed cleanup and `expires_at` — none of which answers
  "which is the current attempt for this triple". So a **new** column
  family holds a **latest pointer**, `(host, target, instance)` →
  `idempotency_key`, **overwritten in the same transaction that stamps
  `finalized_at`**. Last writer in transaction order wins, which *is* the most
  recent finalization — no timestamp comparison, no tie to break.
  **An earlier revision added a finalization-time index beside it, and that
  index is WITHDRAWN.** It was designed to answer "latest per triple" from its
  last key, and that job moved to the pointer as soon as it was clear that
  appending an `idempotency_key` for uniqueness makes a key unique, not
  ordered — UUID byte order has nothing to do with which attempt finished
  second. What was left was an index kept **only to find age candidates for
  the sweep**, whose key still began `host` + `target` + `instance`. That key
  cannot range-serve a global "older than the cutoff" scan at all — it orders
  by triple first — so the sweep walked the whole index anyway, and the
  per-triple time order it did provide was read by **nothing**. It bought one
  avoided row deserialization on a housekeeping pass, at the price of a column
  family and a bespoke byte encoding.
  **The sweep therefore walks the terminal rows themselves**, which already
  carry `finalized_at`: for each row past the cutoff it **keeps** the row when
  the latest pointer for that triple names it — the current attempt is
  retained indefinitely regardless of age — and otherwise **deletes** it. The
  table holds operator actions (installs, updates, removes, onboards), not
  event data, so a periodic scan is the right shape here; if it ever outgrows
  that, the answer is an index keyed `finalized_at_nanos` + `idempotency_key`
  **with no triple prefix**, which is what a cutoff scan actually needs.
  **[DECISION] "The latest attempt" is not read from the pointer alone,
  because a terminal attempt that still owes cleanup has no `finalized_at`
  and therefore no pointer entry.** That is deliberate — §4d
  distinguishes terminal from fully discharged — but it means a reader
  consulting only finalized rows would show a **superseded** attempt as
  current while newer work is still owed. So the lookup is three steps, in this
  order:
  - **first**, if a **non-terminal** row exists for the triple, that is the
    latest attempt. At most one can: the non-terminal
    `(host, target, instance)` index below enforces one live attempt per
    triple, so a second cannot start on a triple while one is in flight —
    and an allocating install forms a *fresh* triple, so it never contends
    for this slot;
  - **then**, if the **cleanup-owed** row exists, that is the latest;
  - **otherwise** follow the **latest pointer**.
  **[DECISION] At most ONE cleanup-owed row exists per triple, and that is an
  invariant rather than a convention.** An earlier revision allowed several
  and picked the one with the greatest `started_at`. That is wrong on the
  reading half: `started_at` does not order attempts, since two can share an
  instant and a clock can go backwards, so "the latest owed row" is not a
  question the store can answer.
  **The storage half was a CODE CHANGE, not an existing property, and an
  earlier revision of this section had it backwards.** It argued the invariant
  was already enforced because the owed-teardown index carries no
  discriminator and a second row would overwrite the first. The index as
  shipped did the opposite: `owed_cleanup_key` **appended the
  `idempotency_key`** after `(target, host, instance)`, its own doc comment
  said "several attempts may owe a cleanup for one triple", and the read
  returned a **`Vec<OperationAttempt>`**, so a second row **queued** rather
  than overwriting and the three-step lookup's second step had no single row
  to return. Making the invariant real therefore meant **dropping the
  discriminator from the key and narrowing the read to at most one row**, and
  retiring the tests that asserted several. That has landed: the owed-cleanup
  key is the triple alone, and the read is `attempt_owing_cleanup`, returning
  at most one row.
  **The invariant needs RFC-D2's guard to be WIDER than it was, and §4f
  widens it**: while a triple has an owed teardown, **no new
  `operation_attempt` may be created THAT NAMES THAT TRIPLE** — no update, no
  remove, and no re-onboard of the same identity, where the earlier guard
  covered host onboarding alone. **An install is not among them.** It
  allocates a fresh number (§4g) and so names a different triple, so this
  guard never reaches it — a rule that blocked installs as well would be the
  component-wide refusal this design removed (§4g). Resuming the **same**
  `idempotency_key`, and the cleanup driver discharging the teardown, are the
  only writes that proceed on the owed triple.
  **A narrower guard would leave the three-step lookup wrong, not merely
  untidy.** Suppose an owed-cleanup row `A` and a later attempt `B` could
  coexist. While `B` runs, step one returns `B` and the answer is right. But
  when `B` **succeeds** the pointer names `B`, and step two — which is
  consulted before the pointer — returns `A`: the finished newer work is
  hidden behind older cleanup, and the reader is told the wrong thing at
  exactly the moment the operator is watching for completion. The priority
  compares **row states**, and nothing in it compares the two rows' order.
  Widening the guard removes the coexistence rather than adding an ordering to
  reason about it, which is the smaller change: the alternative is a
  per-triple attempt sequence maintained at creation time, and a second thing
  that has to stay consistent with the pointer.
  **The three candidate sources are consulted in order rather than merged**,
  and what they can overlap on is **one row**, not two. A *later* attempt
  cannot sit beside an earlier cleanup-owed one on the same triple — RFC-D2's
  guard refuses the update or remove that would create it, and an install
  allocates a different number and so a different triple. What remains is a
  **single in-flight row that is both**: non-terminal, and already carrying
  the `cleanup_state` armed before its mint (§4d), so it appears under both
  indexes at once. Order matters there only to make the answer deterministic —
  both steps would name the same row — and it matters for the sequence as a
  whole, since step two must still run before the pointer for a terminal row
  whose teardown is outstanding.
  Both RFC-D3 §5b's inline read and anything else asking "what is the state
  here" use exactly this order, and it is tested as **one ordered three-branch
  lookup** rather than as three independent ones — the order is the rule, so
  testing the branches separately would not exercise it.
  **[DECISION] The row and the latest pointer move together, in ONE
  transaction.** They are writes to two column families, and a crash between
  them leaves a **stale pointer** naming an attempt that is no longer current
  — silently, since nothing else records which attempt is latest. So the
  **finalization write and the pointer overwrite** are one transaction. The
  sweep's delete is a single row and needs no pairing: it never touches the
  pointer, because it never prunes the row the pointer names.
  So the dedupe guarantee above is **at least 30 days**, and for the most
  recent attempt on a triple it does not expire at all — which is strictly
  stronger than the client's 24-hour key lifetime needs (RFC-E §4).
- **[DECISION] Secondary indexes — four orchestration guards need a durable
  "is there a live operation for X?" lookup.** The uniqueness key is
  `idempotency_key` alone (above), which deliberately gives no way to ask that
  question. But RFC-D3 §5a's single-flight per `(host, target, instance)`
  **for update and remove** (an install dedupes on its `requestKey`, which
  *is* the `idempotency_key` and so is already unique above), and RFC-D2
  §4d's per-hostname onboard idempotency, `Register`/`Deregister` mutual
  exclusion, and "blocked while a teardown is owed" **all** need it
  — and need it to survive a REView restart, so it cannot live in process
  memory (a double-click followed by a restart would otherwise re-drive two
  live attempts for one operation). So this table carries:
  - an index on **`(host, target, instance)` restricted to non-terminal
    rows**, enforcing **at most one live attempt per triple**. **The
    instance is part of the key**: a host may run several instances of one
    module (RFC-A §4), so an index on `(host, target)` alone would enforce
    "one live attempt per module per host" and thereby block **adding** a
    second instance while the first one's install is still running — a
    legitimate concurrent operation, not a double-click (RFC-D2 §4b);
  - an index on **`(target, host, instance)`** for rows with a non-empty
    `cleanup_state` (the owed-teardown lookup). The key carries no
    discriminator, which is **why** at most one such row may exist per triple
    (§4d): a second would overwrite the first's entry and lose an owed
    teardown silently. RFC-D2's owed-teardown guard — no further update,
    remove or re-onboard on a triple whose teardown is outstanding (§4d) —
    is what keeps a second from arising;
  - an index on **`expires_at`** over **all** rows, not only `Onboard`
    ones — every action carries a deadline (above) and the sweep scans them
    all (the expiry sweep,
    RFC-D2 §4d).
  RFC-D3's single-flight and RFC-D2's blocking guards read **these**, not
  process state.

### 4e. `Node::update` diff + read path

- Extend `Node::update` (`node.rs:459`) so the atomic diff/commit persists the
  new `Agent`/`ExternalService` fields (they ride the existing whole-record
  `Update`). The core-component registry and `operation_attempt` are **sibling
  tables** updated directly on roxyd reports, not through `Node::update`.
- Surface `lifecycle` through the **same read path** as `Status` (one status
  read returns both) so review-web gets them together.

### 4f. Migration + format bump

- **[DECISION] One target version, written out, and every other statement in
  this document defers to it.** The crate is on a `0.47.0` **prerelease** by
  the time this lands, so the target is the **next alpha**. `alpha.3` is
  already released and is what `main` carries, so this amendment targets
  **`0.47.0-alpha.4`**:
  - `COMPATIBLE_VERSION_REQ` becomes `">=0.47.0-alpha.4,<0.47.0-alpha.5"`;
  - the existing `migrate_0_46_to_0_47` entry is **extended**, not joined by a
    sibling: its requirement becomes `">=0.46.0,<0.47.0-alpha.4"` and its
    target `0.47.0-alpha.4`.
  **Read the numbers off the crate, not off this document.** If a further
  alpha lands before this work does, every literal here moves with it. What
  does not move is the shape: target the next alpha, and widen the single
  0.46-to-newest-alpha step to reach it.
  An earlier revision wrote the target as plain `0.47.0` with a
  `">=0.47.0,<0.48.0"` range in one place and "the next alpha" in another;
  those cannot both be implemented, and the prerelease form is the correct
  one — a released `0.47.0` range would wave through every alpha store.
- **[DECISION] The target version moves with the shapes, or an existing alpha
  store is silently accepted.** By the time the allocation table of §4g-bis
  lands, this crate is at a `0.47.0` **prerelease** and
  `COMPATIBLE_VERSION_REQ` is a narrow alpha range; `migrate_data_dir` returns
  `Ok` immediately inside that range, so changing the stored shapes **without**
  moving the target means a store marked with the superseded alpha is waved
  through, migrated by nothing, and fails to decode at runtime. The target and
  the range therefore advance to the next alpha together, in the same change
  that adds the shapes.
  **The comparator literal matters, and this crate uses it deliberately.** A
  `<`-bound carrying a prerelease at `0.47.0` brings that version's *other*
  prereleases into consideration, so `<0.47.0-alpha.N` also **matches**
  `0.47.0-alpha.(N-1)`. An earlier revision of this section read that as a
  hazard and wrote the requirement `">=0.46.0,<0.47.0-alpha"` to exclude every
  prerelease. **That is backwards.** `migrate_0_46_to_0_47` states the rule it
  follows — "an alpha-to-alpha change extends the migration that produced the
  earlier alpha instead of adding one beside it, so a 0.46.x database reaches
  the newest alpha in a single step" — and its `">=0.46.0,<0.47.0-alpha.3"`
  catches an `alpha.2` store **on purpose**. Excluding prereleases would
  strand every alpha store with no step that matches it. The bound therefore
  carries the target's prerelease and widens with it.
  **There is no alpha data to convert**, and this crate's own rule is why:
  migration is supported "between **released versions only**", prereleases
  being "assumed to be incompatible with each other". An operator upgrading a
  running alpha deployment performs an operator action — reset or
  re-provision — and this document says so rather than pretending a conversion
  could reconstruct records nobody kept.
- **The new shapes land inside the existing `0.46 → 0.47` step**, which is
  still a real conversion: `0.46.0` stores exist and their rows predate the
  install-state fields, so that one step preserves existing fields,
  initializes the new ones empty, and creates the new column families —
  including the allocation table's and its two indexes'.
- **The migration walks the `AGENTS` and `EXTERNAL_SERVICES` column families
  — NOT the `Node` records.** The new fields live on `Agent` /
  `ExternalService`, whose values are persisted in those CFs (§2), while a
  node's `Inner` record holds only their string keys. So walking `Node`
  records would touch **none** of the values that need the new fields; old
  `Agent::Value` / `ExternalService::Value` records would stay in the `0.46`
  shape and fail or lose defaults on read after the struct changes. Instead,
  the migration iterates every record in the `AGENTS` CF and every record in
  the `EXTERNAL_SERVICES` CF, **preserving each key** and **rewriting each
  value** with `installed_version = None`, `installed_commit = None`,
  `lifecycle = NotInstalled`, `bound_addrs = []` (an existing deployment's
  Giganto is already bound and configured; the empty vector simply means
  "nothing reported yet", and the next status report fills it) and
  `instance = None` (a row written before the field existed describes an
  instance whose number was never recorded, and any number chosen here would
  assert an allocation nothing made). Add
  old-shape structs **`AgentV0_46`** and
  **`ExternalServiceV0_46`** to `migration_structures.rs` to deserialize the
  pre-migration value, then write the new shape. (`Node` itself gains no new
  field, so **no `NodeV0_46`** is needed.)
- The **core-component registry** and **`operation_attempt`** tables are
  net-new key spaces — they start **empty**, so they need CF creation but
  **no data migration**.
- **[DECISION] Register the new CFs in `MAP_NAMES` only in THIS format-bump
  slice — never in an earlier slice.** `StateDb::open` auto-creates every CF
  named in `MAP_NAMES` (`tables.rs`), and `migrate_data_dir` returns early on a
  compatible `0.46.0` dir (`migration.rs`). So if the new-table issues added
  their CF names to `MAP_NAMES` before `COMPATIBLE_VERSION_REQ` bumps, opening
  a `0.46.0` data dir would create the new CFs **without** a version change —
  format drift with no migration record. Therefore the CF registration (adding
  the **five** names this amendment introduces to `MAP_NAMES`) is part of the
  **same** change that bumps
  `COMPATIBLE_VERSION_REQ` to the next alpha (§4f); the type/CRUD work for
  those tables may
  precede it, but their CFs are **not registered/opened until the bump lands**.
- **[DECISION] How `migrate_0_46_to_0_47` opens a dir whose new CFs do not
  exist yet — AND stays rerun-safe after a mid-migration crash. `main` has
  settled this, and the amendment follows it rather than re-deciding it.**
  The migration opens a **pinned historical CF list** with
  `create_missing_column_families(true)`, so whichever families are absent are
  created and the rest are left alone. The list is written out as a constant
  and **never taken from `crate::tables::MAP_NAMES`**, for the reason the code
  gives: it is what *this* migration creates, and a later rename or format
  bump must change what a *future* migration creates, never what this
  historical one did. `MAP_NAMES_V0_47_ALPHA_2` (39 names) is the current one.
  **So this amendment adds `MAP_NAMES_V0_47_ALPHA_3` (44 names)** — the 39
  plus the five of §4g and §4g-bis — and points the migration at it.
  `crate::tables::MAP_NAMES` still moves to 44 in the same slice, but the two
  are separate constants on purpose and must not be collapsed.
  **The crash case is already handled and must not be re-solved.** A run that
  stops part-way leaves a version marker older than the families physically
  present, and RocksDB refuses an open that names a family the database does
  not have or omits one it does. `map_names_for_existing_format` therefore
  reads the physical set back with `list_cf` rather than choosing a static
  list or inferring one from a count, and the retry runs through to
  `migrate_0_46_to_0_47`, which repairs whichever families are still missing.
  An earlier revision of this section proposed both options as open choices
  and noted that `list_cf` was "a standard rocksdb API this repo does not yet
  use". It does now.
  - **The walk+rewrite is likewise rerun-safe**, following this repo's house
    pattern: convert **only** old-shape `Agent`/`ExternalService` values and
    treat an already-new-shape record as a no-op — the `migrate_*_fields ->
    Option<Vec<u8>>` + `already_current` convention (`migration.rs:1146`/`:1202`,
    rerun-tested at `:1543`/`:1574`). So re-running over a partially-rewritten CF
    **skips** the already-migrated records instead of failing to deserialize
    them as `AgentV0_46`.

  Either open option, after `migrate_0_46_to_0_47` the CFs exist, so every
  **other** migration opening `MAP_NAMES` + `false` still works.
- **[DECISION] The migration is forward-only, so a REView core-update that
  carries it MUST snapshot the states DB BEFORE migrating, and rollback
  restores that snapshot together with the format-version markers.**
  `migrate_0_46_to_0_47` bumps `COMPATIBLE_VERSION_REQ` to the value §4f
  fixes
  with **no** down-migration. So if a REView update whose binary carries this
  migration is rolled back to the `.previous` binary (RFC-D2 §4e / RFC-B §8),
  the old binary (below the target) would face an already-migrated
  next-alpha dir and
  **refuse to start** — a control-plane brick. To keep the binary A/B rollback
  safe:
  - **The public backup surface is the `backup` module**, not the `StateDb` /
    `Store` methods: `review_database::backup::create(store, flush,
    backups_to_keep)`, `backup::list(store) -> Vec<BackupInfo { id, timestamp,
    size }>`, and `backup::restore(store, backup_id: Option<u32>)` — which
    already restores a **specific** backup id (`lib.rs:2` `pub mod backup`;
    `backup.rs:39`/`:57`/`:81`). `StateDb::create_new_backup_flush`
    (`tables.rs:428`, `pub(super)`) and `Store::backup` (`lib.rs:1068`,
    `pub(crate)`) are crate-internal and are **not** the contract.
  - **[DECISION] What the snapshot covers — the states DB, NOT the whole data
    dir.** `backup::create` drives RocksDB's `BackupEngine` over the `states.db`
    handle alone (`Store::new` opens `data_dir/states.db`, `lib.rs:107`;
    `tables.rs:428`). It does **not** cover `data_dir/pretrained/`, the
    classifier files under `data_dir`, or `data_dir/VERSION`, and the module's
    own TODO records that PostgreSQL is not covered either
    (`backup.rs:40`/`:58`/`:82`). All install/update state this RFC adds lives
    in `states.db`, so the snapshot is the right object — but the wording
    matters: "back up the data dir" would overstate the protection.
    **Constraint (v1 acceptance): a migration whose rollback is claimed by
    RFC-D2 §4e MUST confine its writes to `states.db`.** All four migrations
    shipping today already do (`migration.rs:231`/`:350`/`:785`). A future
    migration that rewrites data outside `states.db` MUST either extend the
    pre-update snapshot to cover it or declare itself non-rollbackable —
    otherwise the rollback silently reverts only part of the change.
  - **[DECISION] The rollback MUST also restore the format-version markers, or
    it bricks anyway.** `migrate_data_dir` writes the new version into **both**
    `data_dir/VERSION` and `backup_dir/VERSION` (`migration.rs:208`/`:209`) and
    refuses to run when the two disagree (`:155`). A RocksDB restore writes
    only into `data_dir/states.db` and leaves `VERSION` untouched. So restoring
    the snapshot alone yields `0.46` **content** under a next-alpha
    **marker**: the
    reverted older binary reads that marker, matches no `VersionReq` in
    the
    migration chain, and fails with `migration from 0.47.0 is not supported` —
    the same brick, reached through metadata instead of content. Therefore
    review-database exposes **one** public entry point that writes a given
    version string into both `data_dir/VERSION` and `backup_dir/VERSION`
    (`create_version_file` is private and always writes the crate's own
    `CARGO_PKG_VERSION`, so it cannot serve this), and RFC-D2 §4e records the
    **pre-update version string** alongside the backup id so the rollback
    reverts content and markers as one unit.
  - The ordering (snapshot → swap → start + migrate → health-gate → on failure:
    restore snapshot + restore version markers + revert binary) is specified in
    RFC-D2 §4e.
- Follow the existing style-guide cases in the `migration.rs` doc comment for
  choosing the version range.

### 4g-bis. Bind-address allocation

- **[DECISION] One row per allocated address**, keyed
  **`(host, transport, port)`** — the uniqueness that prevents a double
  allocation. It carries an **owner** `(component, instance, listener_key)`:
  one Giganto instance owns three listeners, two of them UDP, so
  `(component, instance)` alone cannot say which row is which key. It carries
  the full **`SocketAddr`** as a value, because the key deliberately drops the
  address — the conflict model is address-blind — while a retry must rebuild
  the request's map. And it carries the **`idempotency_key`** of the attempt
  that owns it.
- **[DECISION] No state column.** An earlier shape gave the row
  `Held | Allocated | Compensating`. Every rule treats a row the same way
  whatever its attempt is doing — the scan counts every row, the transaction
  counts a row's existence, no failure is keyed on a state — so the column
  would decide nothing while standing up a second state machine beside
  `operation_attempt`'s, which no transaction spans and which a crash can
  therefore leave disagreeing with it. What remains is a row's **existence**,
  written once and deleted once.
- **[DECISION] `Released` is not a state; it is the absence of a row.** This
  crate is RocksDB, so the uniqueness key is the row's own key: there is no
  partial index and no way to say "unique among rows that are not released".
  A released row would make its port permanently unusable. Release is a
  **delete**, and an audit trail, if wanted, goes to a separate history table
  rather than into the key space that enforces the invariant.
- **[DECISION] Two secondary indexes, both one-to-many, both with the
  discriminator in the key.** Nothing reads a row by the number it already
  knows, and one attempt and one instance each own three of Giganto's rows —
  so an index keyed on the attempt or the instance alone would have its
  entries overwrite one another in a store with no multi-map:
  - **`(idempotency_key, listener_key)` → the primary key** — a re-driven
    attempt restores its own rows by prefix scan on `idempotency_key`.
  - **`(host, component, instance, listener_key)` → the primary key** —
    removal deletes an instance's rows and the UI reads them, both by prefix
    scan on `(host, component, instance)`.
  **Index entries are written and deleted in the same transaction as the
  primary row.** A half-updated index is not a safe pause, it is a row the
  only two readers can no longer find; a partial failure must leave the row
  and both entries all absent or all present.
- **[DECISION] The write needs a conflict-detecting primitive, and this crate
  already has one.** Two concurrent installs write **different**
  `operation_attempt` rows, so their transactions do not conflict and both
  could commit the same port — "in the same transaction" does not prevent it,
  the unique key does. A plain atomic write batch is not that primitive:
  two batches writing one key both succeed and the second overwrites the
  first. This crate is an `OptimisticTransactionDB`, its generic table helper
  exposes `insert_with_transaction`, and tables needing a uniqueness check
  take `get_for_update_cf(..., EXCLUSIVE)` first. The allocation write follows
  that pattern, reading each key for update before writing it, together with
  the `operation_attempt` mutation.
- **[DECISION] Every delete rides the record that justifies it.** "The port
  stays held" is not an acceptable crash answer on its own: a row whose
  attempt is terminal and whose cleanup is discharged has nothing left that
  would revisit it, so a lost delete is a permanent leak rather than a safe
  pause. There are exactly three deletes, each in the **same transaction** as
  its justification — the write recording a **failed, cancelled or expired**
  attempt that owes no cleanup; the `cleanup_state` discharge; and the write
  recording a confirmed removal. **A terminal SUCCESS is not one of them**:
  saying "a terminal outcome with no cleanup owed" would sweep success in and
  contradict the next decision, which is the whole point of holding the row
  past the attempt. The same three occasions, and the same exclusion, govern
  the **instance** row of §4g. If the transaction fails, neither half lands, so
  the existing
  re-drive path sees work still owed. No sweep, reaper or reconciliation pass
  is needed for these rows.
- **[DECISION] Success writes nothing, and lifetime changes hands at success.**
  A row released on success would be worse than no row at all: a stopped
  service reports nothing, so its ports would read as free and collide the
  moment it starts again. **Before** success the row is subordinate to the
  attempt, which §4d's durable `expires_at` and its sweep already bound.
  **After** success the **instance** owns it — the attempt is terminal within
  minutes while the address is owed for as long as the instance exists — so a
  successful row deliberately outlives its attempt.
- **`operation_attempt` is otherwise unchanged.** No new action and no new
  field: this adds no operation of its own, and the expiry sweep it relies on
  already exists.

### 4g. Instance-number allocation

**This section replaces the earlier "one instance per `(component, host)`,
the number is always `1`, no allocation state exists" decision.** That
decision deferred an allocator by name — no counter, no reservation table, no
release rule — and deferring it is no longer possible: §4g-bis allocates
*ports* per instance, and a port row's owner is `(component, instance,
listener_key)`, so the port allocator consumes an instance number it does not
produce. Two Giganto instances on one host cannot be installed while the
number is pinned, and that is the case the bind-address work exists for.
**The two allocators are separate things and both are needed.**

- **[DECISION] One instance row per allocated number**, keyed
  **`(host, component, instance)`**, carrying the `idempotency_key` of the
  attempt that owns it. It is deliberately the **same shape and the same
  primitive** as the port row of §4g-bis: existence means taken, there is no
  state column, and the uniqueness key is the row's own key, so a
  `get_for_update_cf(..., EXCLUSIVE)` before the write is what makes two
  concurrent installs pick different numbers rather than both committing one.
- **[DECISION] The number is the smallest free `u32` in `1..=999` for
  `(host, component)`**, found by prefix scan over the instance rows for that
  pair. Smallest-free rather than monotonic, because instance numbers are
  **reused** after teardown (RFC-A §4, RFC-D2 §4d) and a monotonic counter
  would drift upward forever while the reused numbers sat free. A prefix scan
  is affordable precisely because the count is small.
  **The ceiling is `999`, and it is not a tuning knob.** RFC-A §4 pins the
  instance to a **three-digit zero-padded** segment inside the registration
  identity, bounded at 131 octets; a four-digit number would not fit the shape
  every certificate and registry entry is composed from. So the allocator's
  range is fixed by that contract rather than configured, and
  `InstanceNumbersExhausted` is raised at `1000`, not at some deployment
  setting.
- **[DECISION] The prefix scan alone does NOT serialize two concurrent
  allocations, so the conflict is resolved by re-selecting.** Two
  transactions that both read an empty prefix both pick `1` and both take
  `get_for_update_cf` on the **same absent key** — the outcome is `1` and a
  commit conflict, not `1` and `2`. Locking an absent key orders the writers;
  it does not tell the loser to look again.
  So on a commit conflict **the whole transaction re-runs**, not just the
  port classification: the loser re-reads the prefix, now sees `1` taken, and
  picks `2`. Re-selecting an instance number is correct rather than a
  substitution — it came from the allocator, not from the operator, unlike
  the port candidates the port path must preserve (RFC-D2 §4f). But it is
  only correct **after** the check below.
- **[DECISION] EVERY retry re-checks the `requestKey` FIRST, and only then
  re-selects.** Two concurrent requests carrying the **same** key must not
  produce two instances, and "re-run from instance selection" alone would do
  exactly that: the loser would re-read the prefix, see `1` taken, and pick
  `2` for what is one operator action. So the retry order is fixed —
  1. re-read the `operation_attempt` by `idempotency_key` (the persisted
     `requestKey`, RFC-D2 §4f); if a row now exists, **return that attempt**
     and allocate nothing;
  2. only when none exists, re-select the instance number, then the ports,
     then write.
  This is the single retry rule for the whole allocating transaction. It
  **supersedes** any statement that a conflict re-runs only the port
  classification: that narrower rule belongs to the port scan considered
  alone, and applying it here would skip the key check that makes concurrent
  same-key requests safe. The three-attempt bound and
  `AllocationContended` are unchanged.
- **[DECISION] The instance row and the port rows are written in ONE
  transaction, instance first.** The port rows' owner names the instance, so
  it must be chosen before they can be keyed; and if the two were separate
  transactions a crash between them would leave a held number owning no
  ports, which nothing would ever collect. The `operation_attempt` mutation
  joins the same transaction, exactly as §4g-bis requires for ports.
- **[DECISION] Exhaustion is a typed refusal, not a wrap.**
  `InstanceNumbersExhausted { component, host }` when every number in
  `1..=999` is taken. The ceiling is the fixed one above, not a deployment
  setting. There is no wrap and no reuse of a number whose row still exists.
- **[DECISION] Release is a delete, on the same three occasions and in the
  same transactions as the port rows** (§4g-bis): a **failed, cancelled or
  expired** attempt that owes no cleanup, the `cleanup_state` discharge, and
  the confirmed removal. **A terminal SUCCESS is not one of them** — the
  number is owed to the instance for as long as it exists, exactly as its
  ports are, and writing the exclusion here rather than only at the port row
  is what stops the two from drifting apart again.
  This is what the earlier decision meant by "the release rule has to agree
  with the compensation ledger" — the agreement is that there is no separate
  rule at all, because the instance row and the port rows are released
  together by the same write.
- **[DECISION] A second install for a `(component, host)` that already has a
  row is no longer refused** — it is given the next free number. The refusal
  stands for **core components**, which have no instance dimension (RFC-B §4:
  only the five modules are multi-instance), and for those the number remains
  `None` rather than being allocated.
- **What this schema already carried, and still does:** `Agent.key` is
  `<instance>.<service>` (§2), so two instances are two rows under one
  `node_id` and one `kind` with **no schema change**; `operation_attempt`
  records the `instance` (§4d); and the non-terminal index is keyed
  `(host, target, instance)` (§4d), which now varies rather than being
  pinned. **No code path may assume one row per `(node_id, kind)`** — that
  assumption is what this section unpicks, and §5 tests against it.

## 5. Acceptance criteria

**Idempotency and retention (§4d).** `install_intent` round-trips as
`Some(digest)` for an allocating install and `None` for update, remove and
onboard, and a stored `None` presented with a digest is refused. The digest
matches a **golden vector** committed beside the test, and a re-encode after
any change to the transcript fails against it rather than silently changing
what "the same request" means; the `None`-versus-empty `bind_addrs` pair
produces **different** digests. `finalized_at` is set **iff** the outcome is terminal
**and** `cleanup_state` is empty: a test asserts a terminal row that still owes
cleanup has `finalized_at = None` and is **not** reachable by the sweep, and
that discharging the last owed item stamps it in that same transaction.
Retention keeps the **most recent** terminal attempt per
`(host, target, instance)` indefinitely and sweeps **older** terminal attempts
30 days past their `finalized_at`; a test asserts a sibling instance's record
is not collapsed away by a newer attempt on the same `(host, target)`, and
that the latest row survives an advance well past 30 days. **The latest
pointer is the only thing that names the current attempt**, and it is tested
on commit order rather than on any key ordering: a test finalizes two attempts
in the **same nanosecond** in a known order and asserts the pointer names the
one that committed **second** — the assertion that fails against any scheme
deriving "latest" from a key, since a key made unique by an appended
`idempotency_key` is unique, not ordered. **The sweep consults the pointer
before deleting**: a test ages every terminal row for a triple past the cutoff
and asserts the pointed-at row survives while the rest are pruned. And the
**three-step lookup**
is tested in all three branches: a triple whose newest work is a **running**
attempt reports that one; a triple with **no** running attempt but a terminal
row still owing cleanup reports **that** one, even though the pointer names an
older row; and a triple whose rows are all fully discharged reports the
**pointed-at** one.
**The second branch assumes at most one cleanup-owed row per triple, and this
crate tests the storage side of that only**: a test asserts the owed-teardown
index holds **one** entry per `(target, host, instance)` and that writing a
second for one triple **overwrites** rather than queues — which is why the
invariant matters here. That a second row never arises is RFC-D2's
owed-teardown guard, and it is asserted **there**, in the repository whose
orchestration enforces it; a review-database test cannot drive that path.
Atomicity is
tested on the one write that can leave a lie behind: a failure injected
between the finalization write and the pointer overwrite leaves **neither**,
so no stale pointer names a superseded attempt. The sweep's delete is a single
row and needs no pairing.

**Bind-address allocation (§4g-bis).** A `0.46` fixture migrates with existing
values **preserved**, new fields empty and the new column families created. The
allocation row round-trips; **all three** of one instance's rows survive in
**each** secondary index and come back from one prefix scan — the test that
fails against an index keyed on `idempotency_key` or `(host, component,
instance)` alone, where the third entry overwrites the first two; and an index
write failing mid-transaction leaves the primary row and **both** entries
absent, never one listener's entry orphaned from its siblings.

Two concurrent proposals for one host contending for one port produce exactly
**one** winner, and the loser answers `PortAllocationConflict` **carrying the
winner's owner triple** — the assertion that fails if the commit conflict is
reported without looking again. A released port is **immediately
re-allocatable**, which is the observable consequence of release being a delete.

Delete atomicity has its own tests, because the leak it prevents is invisible
afterwards: a **failed transaction** at each of the three delete sites leaves
the row **and** leaves its justifying record unwritten, so a re-drive finds work
still owed; and after each successful pair the port is allocatable again while
nothing owed remains.

The migration guard is tested on the literal: the `0.46 → 0.47` entry's
requirement matches `0.46.0` and `0.46.9` and **not** any `0.47.0` prerelease,
and a store marked with a superseded alpha is **refused** rather than waved
through.

- Adding, reading, and updating an `Agent`/`ExternalService` round-trips
  `installed_version`, `installed_commit`, and `lifecycle`; `lifecycle` is
  independent of `Status` (both readable from one status read).
- **The instance is ALLOCATED (§4g).** A test asserts an `operation_attempt`
  for a module carries the number it was given and one for a core component
  carries `None`, and that the non-terminal index is keyed
  `(host, target, instance)` with a number that **varies**. A first install
  for a `(component, host)` takes `1`; a **second** install takes `2` rather
  than being refused; and after the first is removed, a third install
  **reuses `1`** — the observable consequence of smallest-free over
  monotonic. Two concurrent installs for one `(component, host)` produce
  **different** numbers with exactly one winner per number, which is the
  test that fails if the row is written without `get_for_update_cf`. A core
  component's second install is still refused, because it has no instance
  dimension. `InstanceNumbersExhausted` is raised rather than wrapping.
  **The instance row and the port rows are written in ONE transaction**: a
  test injects a failure after the instance row and asserts **neither** it
  nor the port rows exist, since a held number owning no ports is a leak
  nothing collects.
- **Every attempt expires.** A test writes an `Install` attempt whose
  `expires_at` has passed with no check-in ever arriving, runs the sweep, and
  asserts the attempt is finalized `Failed` and the owed compensation is
  discharged — so a host that never returns leaks neither the
  single-flight slot nor the minted identity (§4d).
- **Several instances of one component coexist on one node.** A test writes
  two `Agent` rows under the same `node_id` and the same `kind`, keyed
  `001.piglet` and `002.piglet` (RFC-A §4), and asserts both round-trip
  with independent `config`, `draft`, `installed_version`,
  `installed_commit` and `lifecycle`, that reads return both, and that
  deleting one leaves the other intact. No code path may assume one row per
  `(node_id, kind)`. The **core-component registry** is unaffected: core
  components are single-instance (RFC-A §4), so its `(component, host)` key
  stays as is.
- `Lifecycle` and `Status` are distinct types; no code path conflates them.
- **An unrecognized stored `Lifecycle` decodes to `Unknown`.** A test writes a
  discriminant this build does not know and asserts the read yields `Unknown`,
  never `NotInstalled` — the latter would report "nothing installed" for a host
  that is actually `Failed` or `Running` and invite an install where a
  remediation is due (§4a). A second test asserts no call site resolves the
  `Option` to `NotInstalled`.
- **The stored encoding is this crate's own.** A test pins what is persisted
  for each variant and records that it is the **variant index** under this
  crate's bincode configuration — `Unknown` is not stored as `255` — so nobody
  reads a number written by review-protocol's wire type as meaning the same
  thing (RFC-C §4).
- Core-component registry rows are keyed by `(component, host)`; **multiple
  `roxyd` rows** (one per host) coexist; **bootroot** rows carry
  `installer_managed = true`. The `(component, host)` key is a
  length-prefixed/serialized tuple (or validated-delimiter) so `("ab","c")`
  and `("a","bc")` are **distinct keys** — a test exercises exactly that
  collision case.
- `operation_attempt` enforces **one record per `idempotency_key`**: a second
  write with the same key and an **identical** request **returns that row,
  never a duplicate**, while the same key with a **different** `host`,
  `target` or payload is **refused** with a typed conflict rather than
  overwriting a live attempt's record (unique
  key / index, §4d) — a test drives the same key twice and asserts a single
  row. Records carry `host`, `instance`, `resolved_version`
  **and** `resolved_commit`, `idempotency_key`, and `cleanup_state`; two
  concurrent same-package applies to different hosts, and two commits of one
  version, are distinguishable.
- **The new CFs are created only with the format bump:** opening a `0.46.0`
  data dir with the pre-bump build does **not** create the CFs this change
  adds; they appear only once `COMPATIBLE_VERSION_REQ` names the new target. A
  test opens a `0.46.0` dir against the pre-bump `MAP_NAMES` and asserts
  **none of the five** CFs this change adds is created. (`core_component` and
  `operation_attempt` are **not** among them: they were registered by an
  earlier slice and are already in `MAP_NAMES` at `0.47.0-alpha.2`.)
- A data dir written at `0.46.0` migrates cleanly to the new format: every
  existing agent/external-service gains the defaults
  (`None` / `None` / `NotInstalled` / empty `bound_addrs`); no config/draft
  data is lost; migration is
  resumable/robust in the house style.
  **Two counts, and they are different — conflating them is the mistake this
  spells out.** This change adds **five** names to `MAP_NAMES` (39 → 44). But a
  `0.46.0` store is at 36 CFs, so migrating one **creates eight**: those five
  plus `core_component`, `operation_attempt` and **`customer deletion jobs`**,
  all three registered by earlier `0.47.0` alpha slices and none of them
  present at `0.46`. The migration therefore **opens a `0.46.0` dir that lacks
  all eight without failing** — the instance allocation table, the port
  allocation primary, its two indexes, the latest pointer, `core_component`,
  `operation_attempt` and `customer deletion jobs` —
  and
  creates every one of them (`create_missing_column_families(true)` for this
  migration —
  recommended — or `MAP_NAMES_V0_46` + `list_cf` + `create_cf`, §4f) — the
  complement of the "pre-bump open creates no new CF" test above.
- **Mid-migration crash is rerun-safe:** a fixture at **`0.46.0` VERSION with
  all eight CFs the migration creates already present and old-shape `Agent`/`ExternalService`
  values** (the state left by a crash after CF creation but before the version
  bump) re-migrates **idempotently** — no duplicate-CF or open failure, and
  already-new-shape records are skipped (the `already_current` house pattern,
  §4f) rather than re-converted or mis-deserialized.
- `COMPATIBLE_VERSION_REQ` reflects the new format; the migration test
  fixture (old data dir → migrated) passes.
- **The format-version markers round-trip through a rollback.** A test
  migrates a `0.46.0` dir to the new target (which rewrites **both**
  `data_dir/VERSION` and `backup_dir/VERSION`, `migration.rs:208`/`:209`),
  restores the pre-update snapshot, calls the new public version-writing entry
  point with the recorded `pre_update_version`, and asserts that a
  pre-target-compatible open **succeeds** — i.e. both markers read `0.46.0`
  and `migrate_data_dir`'s data/backup agreement check (`:155`) passes.
  Without the marker rewrite this test fails with
  `migration from <the new target> is not supported`,
  which is exactly the brick §4f exists to prevent.
- **Rollback-claimed migrations confine their writes to `states.db`.** The
  snapshot covers the states DB only (§4f), so this is a reviewable property of
  each migration, not a runtime check: the migration added in this slice writes
  only under `data_dir/states.db`, and the §4f constraint is recorded for
  future migrations.

## 6. Issue decomposition (AgentCoop)

- **Instance-number allocation** (§4g) — the instance row keyed
  `(host, component, instance)`, its column family, smallest-free selection
  by prefix scan, `get_for_update_cf` before the write, and
  `InstanceNumbersExhausted`. Lands before the port table, which keys its
  owner on the number this produces.
- **Port allocation** (§4g-bis) — the allocation row and its column family;
  the two secondary-index column families keyed
  `(idempotency_key, listener_key)` and
  `(host, component, instance, listener_key)`, written and deleted in the
  same transaction as the primary row; the `insert_with_transaction` +
  `get_for_update_cf` write path; and the three paired deletes, each in the
  same transaction as the record that justifies it. Depends on the instance
  row, and both join the `operation_attempt` write in **one** transaction.
- **Migration for both tables** (§4f) — the new column families created in
  the existing `0.46 → 0.47` step — **extended**, not joined by a sibling —
  with the target version and `COMPATIBLE_VERSION_REQ` advanced to the next
  alpha together with the shapes, the requirement's `<`-bound carrying that
  alpha so every earlier prerelease still reaches it in one step, and a new
  pinned `MAP_NAMES_V0_47_ALPHA_*` list for what this migration creates.

Each issue is self-contained (restate the relevant §3 contract inline).
Dependency order within this repo:

1. **`Lifecycle` value type** (§4a) — the enum + (de)serialization + tests. No
   dependencies; everything below uses it.
2. **`Agent`/`ExternalService` install fields** (§4b) — add the three fields,
   update impls + `update` diffs, unit tests.
3. **Core-component registry table** (§4c) — the table struct, CRUD, the
   collision-safe `(component, host)` tuple key, `installer_managed`, tests.
   **Does NOT add its CF to `MAP_NAMES`** (that is issue 5).
4. **`operation_attempt` ledger table** (§4d) — the table struct, CRUD, the
   full field set (including `backup_id` / `pre_update_version` for the REView
   core-update rollback, `install_intent` and `finalized_at`), the
   **`idempotency_key`-unique** key (one row per key), tests. **This issue
   also owns the latest pointer** (§4d): the pointer keyed
   `(host, target, instance)`; the pointer overwrite that rides the **same
   transaction** as the finalization write; the retention sweep as a scan over
   terminal rows that keeps the one the pointer names; and the **three-step
   latest lookup** — non-terminal, then the single cleanup-owed row, then the
   pointer — that RFC-D3 §5b's inline read uses. The pointer is part of this
   table's storage contract, not a separate store, so splitting it out would
   leave two issues able to write one invariant. **Does NOT add its CF to
   `MAP_NAMES`** (that is issue 5).
5. **Migration + format bump + CF registration** (§4f) — `migrate_0_46_to_0_47`,
   bump `COMPATIBLE_VERSION_REQ`, old-shape structs, migration test fixture,
   **AND register the FIVE CFs this amendment adds in `MAP_NAMES`** in this
   same slice (so no `0.46.0` dir gets a new CF without the bump — §4f): the
   **instance allocation** table (§4g), the **port allocation** primary
   (§4g-bis), its two indexes keyed `(idempotency_key, listener_key)` and
   `(host, component, instance, listener_key)`, and the **latest pointer**
   (§4d). All five are net-new key
   spaces that start empty, so they need CF creation and **no data
   migration** — but every one of them must be named here, because a CF
   created outside this slice is a CF created without a version change.
   **`core_component` and `operation_attempt` are NOT registered here**: they
   are already in `MAP_NAMES` at `0.47.0-alpha.2`, registered by the earlier
   slice that added them. They still appear in the **migration** — a `0.46.0`
   store has neither, nor `customer deletion jobs` — which is why the fixture
   above creates **eight** while this slice registers five. Must
   specify **how the
   migration opens a `0.46.0` dir that lacks the new CFs** —
   `create_missing_column_families(true)` for this migration (recommended,
   inherently rerun-safe) or `MAP_NAMES_V0_46` + `list_cf` + `create_cf` (§4f) —
   since the migration opens default to `create_missing_column_families(false)`.
   Must be **rerun-safe after a mid-migration crash** (new CFs already exist,
   version still `0.46.0`): the open creates nothing when the CFs exist and the
   walk skips already-new records (`already_current` house pattern). Test both a
   clean `0.46.0` dir **and** the crash-resume fixture. Depends on 1–4.

6. **Public format-version writer for rollback** (§4f) — one public entry point
   that writes a caller-supplied version string into **both**
   `data_dir/VERSION` and `backup_dir/VERSION`. `create_version_file`
   (`migration.rs:1313`) is private and always writes the crate's own
   `CARGO_PKG_VERSION`, so it cannot serve this. Without it, a rolled-back
   REView faces a `0.47.0` marker over restored `0.46.0` content and refuses to
   start (§4f). Includes the marker round-trip test in §5. Depends on 5.

Issues 3 and 4 build the table logic independently of each other and of 1–2,
but their **CF registration is deferred to issue 5**, which lands last (it
both migrates the shapes from 1–2 and turns on the new CFs atomically with the
version bump).

## 7. Non-goals

- **No `desired_version`** / reconcile state (immediate-action model).
- **No** store-layout, signature-verification, GraphQL, or roxyd-control logic
  — those are review (D2) and review-web (D3). This repo only defines and
  persists the **types**.
- `UpdateAvailable` is **computed by review** (D2), not stored here.
