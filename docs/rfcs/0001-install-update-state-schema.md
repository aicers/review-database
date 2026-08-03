# Implementation doc D1: review-database — install/update state schema

**Repo:** `aicers/review-database` · **Grounded on** `origin/main` @ `1285590`
(v0.46.0; DB format `COMPATIBLE_VERSION_REQ = ">=0.46.0,<0.47.0"`).
Re-verify before relying.

**Status:** `aicers/review-database` is an aicers repo (in-repo issue flow,
AgentCoop-decomposable; not draft-only, no external gate — the whole D set
now lives under `aicers`: `review-database` (this doc, D1), `review` (D2),
and `review-web` (D3)). This is the review-database slice of the RFC-D scope —
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
- **`Agent.key` already carries the instance, so multi-instance needs no
  new field.** review resolves an agent from its certificate as
  `agent_id = <instance>.<service>` and `host_id = <host>.<domain>`
  (`review/src/tls/certificate.rs`), then finds the node by `host_id` and
  the agent **within that node** by `a.key == agent_id`
  (`review/src/agent/requests.rs`); review-web composes the same pair
  (`gen_agent_lookup_key`, `graphql/node/crud.rs`). So `key` is
  `<instance>.<service>` and is unique **per node**, exactly matching the
  hierarchical identity (RFC-A §4) where an instance number is scoped by
  `{service_name}.{hostname}`. Two `piglet` instances on one node are two
  rows, `001.piglet` and `002.piglet`, under the same `node_id` and the
  same `kind` — **no schema change, no new key**. What this does invalidate
  is any assumption that a node holds at most one row per `AgentKind`.
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
    derived because roxyd **chooses** Giganto's addresses on a first install —
    its first bind precedes its first configuration, and only the host can
    see what is free (RFC-B §4). Two readers need it: the direct-to-Giganto
    config push, which otherwise has no destination (RFC-D2 §4b), and the UI
    form, which would otherwise keep offering the package default to an
    instance that is not on it (RFC-E §4).
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
    beside a surrogate `id`). REView generates a **distinct** `idempotency_key`
    per logical operation (a given host + target + operation gets its own key),
    so the key **alone** identifies the operation — `host` and `target` are
    **data on the row, not part of the uniqueness key**. Crash-safe resume
    depends on **one** record per logical operation: a re-drive/resume with the
    same key must **find or upsert the same row**, never create a duplicate.
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
    In v1 it is `Some(1)` for a module and `None` for a core component. The owed
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
- **[DECISION] A discharged attempt is FINALIZED IN PLACE and retained, not
  deleted — with a retention rule so the table does not grow without bound.**
  "Transient" describes the *obligation*, not the row. Deleting the row on
  completion would break the two readers that need it after the fact: RFC-D2
  §4b's "what did the operator last do here" display/audit, and RFC-E §5's
  self-update recovery, where reading the operation record is the **only** way
  the UI learns whether a REView / aice-web-next update succeeded (the response
  channel was torn down by the swap, RFC-C §4). So: keep the **most recent
  terminal attempt per `(host, target, instance)`** — the same triple the
  single-flight key uses (below), so a module running several instances keeps
  one record each rather than collapsing to one per `(host, target)` and
  masking a sibling's outcome — plus every attempt that is still
  non-terminal or still owes `cleanup_state` — and prune older terminal
  attempts beyond a bounded age/count. Without the prune, every install,
  update, remove, and onboard accumulates forever.
- **[DECISION] Secondary indexes — four orchestration guards need a durable
  "is there a live operation for X?" lookup.** The uniqueness key is
  `idempotency_key` alone (above), which deliberately gives no way to ask that
  question. But RFC-D3 §5a's single-flight per `(host, target, instance)`,
  and RFC-D2
  §4d's per-hostname onboard idempotency, `Register`/`Deregister` mutual
  exclusion, and "re-onboard blocked while a teardown is owed" **all** need it
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
    `cleanup_state` (the owed-teardown lookup);
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

- Introduce the format change under the next DB-format version (e.g.
  **`0.47.0`**): bump `COMPATIBLE_VERSION_REQ` (`migration.rs:111`) to
  `">=0.47.0,<0.48.0"` and append a `migrate_0_46_to_0_47` entry to the
  `Vec<Migration>` (`migration.rs:177`).
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
  "nothing reported yet", and the next status report fills it). Add
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
  the two names to `MAP_NAMES`) is part of the **same** change that bumps
  `COMPATIBLE_VERSION_REQ` to `0.47.0`; the type/CRUD work for those tables may
  precede it, but their CFs are **not registered/opened until the bump lands**.
- **[DECISION] How `migrate_0_46_to_0_47` opens a `0.46.0` dir (whose new CFs
  do not exist yet) — AND stays rerun-safe after a mid-migration crash.** The
  migration functions open the DB with `create_missing_column_families(false)`
  and `crate::tables::MAP_NAMES` (`migration.rs`, e.g. `:234`), whereas the
  **runtime** `StateDb::open` uses `create_missing_column_families(true)`
  (`tables.rs:499`, `:509`). So once the two new names are in `MAP_NAMES`, a
  migration that opens `MAP_NAMES` with `false` on a `0.46.0` dir (which lacks
  those CFs) **fails at open** — the migration must create the new CFs. And
  because the format-version bump is written only **after** the migration body,
  a crash between "CFs created" and "version written" leaves the dir at
  **`0.46.0` with the new CFs already present**; the rerun must tolerate that.
  - **(recommended) create-missing for this migration** — open
    `migrate_0_46_to_0_47` with `create_missing_column_families(true)` + the new
    `MAP_NAMES`, so the two CFs are created when absent and simply opened when
    present. This is **inherently rerun-safe** — a re-open never fails on "CF
    already exists" and creates nothing once both exist — and mirrors the
    existing CF-adding migration `migration.rs:627`. It matches this repo's
    idempotent-rerun convention (below) with the least machinery. (`:627` is
    `migrate_customer_specific_networks`, which opens with
    `create_missing_column_families(true)` while reformatting existing CFs
    rather than adding one — it is the precedent for the **open mode**, not
    for CF creation.)
  - **or a versioned CF list** — a **`MAP_NAMES_V0_46`** constant (`MAP_NAMES`
    without the two new names) opened under
    `create_missing_column_families(false)` (mirrors the versioned list
    `MAP_NAMES_V0_42`, `migration.rs:301`/`:342`/`:448` — the repo pins the
    names as literals there but documents no rationale, so treat it as
    precedent for the shape, not as a stated rule), then explicit
    `db.create_cf` for the two
    new CFs (`migration.rs:504`). **This variant is NOT rerun-safe as written**:
    after the crash above the DB already holds `core_component`/`operation_attempt`,
    so an old-only-list open fails (RocksDB requires every existing CF to be
    named) and a second `create_cf` fails ("CF already exists"). To use it, the
    migration MUST first read the **actual** on-disk CF set via
    `rocksdb::DB::list_cf` (a standard rocksdb API this repo does **not** yet
    use) and create only the **missing** CFs. The create-missing option avoids
    all of this, so it is preferred.
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
  `migrate_0_46_to_0_47` bumps `COMPATIBLE_VERSION_REQ` to `">=0.47.0,<0.48.0"`
  with **no** down-migration. So if a REView update whose binary carries this
  migration is rolled back to the `.previous` binary (RFC-D2 §4e / RFC-B §8),
  the old binary (`<0.47.0`) would face an already-migrated `0.47.0` dir and
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
    the snapshot alone yields `0.46` **content** under a `0.47` **marker**: the
    reverted `<0.47.0` binary reads `0.47.0`, matches no `VersionReq` in the
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

### 4g. One instance per `(component, host)` in v1

- **[DECISION] v1 stores at most one instance per `(component, host)`, and
  the number is always `1`; no allocation state exists.** RFC-A §4 pins the
  instance for v1 and defers allocating free numbers to a later release, so
  this schema needs **no counter, no reservation table, and no release
  rule** — the three things an allocator would require. A second install for
  a `(component, host)` that already has a row is refused at the mutation
  boundary (RFC-D3 §5a), not resolved by picking another number.
- **What this schema nevertheless carries, so that v2 is an extension and
  not a migration:** `Agent.key` is already `<instance>.<service>` (§2), so
  two instances are two rows under one `node_id` and one `kind` with **no
  schema change**; `operation_attempt` records the `instance` (§4d); and the
  non-terminal index is keyed `(host, target, instance)` (§4d), which with a
  pinned number behaves exactly like `(host, target)` but does not have to be
  rebuilt when the number varies. **No code path may assume one row per
  `(node_id, kind)`** — that assumption is what v2 would have to unpick, and
  §5 tests against it today.
- **What v2 adds here** is a source of free numbers for a
  `(component, host)`, a way to hold one across an in-flight install, and the
  rule that releases it. Deliberately unspecified: the release rule in
  particular has to agree with the compensation ledger (§4d) and the
  registrar's own binding (RFC-F §5.2), and specifying that agreement before
  the allocator exists is what this deferral avoids.

## 5. Acceptance criteria

- Adding, reading, and updating an `Agent`/`ExternalService` round-trips
  `installed_version`, `installed_commit`, and `lifecycle`; `lifecycle` is
  independent of `Status` (both readable from one status read).
- **The instance is recorded, not allocated (§4g).** A test asserts an
  `operation_attempt` for a module carries `instance = Some(1)` and one for
  a core component carries `None`, and that the non-terminal index is keyed
  `(host, target, instance)` — the shape v2 needs, exercised today with a
  pinned number. **No allocation, reservation or release path is
  implemented**, and a test asserts a second install for a
  `(component, host)` that already has a row is refused rather than given
  another number.
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
  write with the same key **upserts the same row, never a duplicate** (unique
  key / index, §4d) — a test drives the same key twice and asserts a single
  row. Records carry `host`, `instance`, `resolved_version`
  **and** `resolved_commit`, `idempotency_key`, and `cleanup_state`; two
  concurrent same-package applies to different hosts, and two commits of one
  version, are distinguishable.
- **The new CFs are created only with the format bump:** opening a `0.46.0`
  data dir with the pre-bump build does **not** create the
  `core_component`/`operation_attempt` CFs; they appear only once
  `COMPATIBLE_VERSION_REQ` is `0.47.0`. A test opens a `0.46.0` dir against the
  pre-bump `MAP_NAMES` and asserts no new CF is created.
- A data dir written at `0.46.0` migrates cleanly to the new format: every
  existing agent/external-service gains the defaults
  (`None`/`None`/`NotInstalled`); no config/draft data is lost; migration is
  resumable/robust in the house style. The migration **opens a `0.46.0` dir
  that lacks the `core_component`/`operation_attempt` CFs without failing** and
  creates them (`create_missing_column_families(true)` for this migration —
  recommended — or `MAP_NAMES_V0_46` + `list_cf` + `create_cf`, §4f) — the
  complement of the "pre-bump open creates no new CF" test above.
- **Mid-migration crash is rerun-safe:** a fixture at **`0.46.0` VERSION with
  the two new CFs already present and old-shape `Agent`/`ExternalService`
  values** (the state left by a crash after CF creation but before the version
  bump) re-migrates **idempotently** — no duplicate-CF or open failure, and
  already-new-shape records are skipped (the `already_current` house pattern,
  §4f) rather than re-converted or mis-deserialized.
- `COMPATIBLE_VERSION_REQ` reflects the new format; the migration test
  fixture (old data dir → migrated) passes.
- **The format-version markers round-trip through a rollback.** A test
  migrates a `0.46.0` dir to `0.47.0` (which rewrites **both**
  `data_dir/VERSION` and `backup_dir/VERSION`, `migration.rs:208`/`:209`),
  restores the pre-update snapshot, calls the new public version-writing entry
  point with the recorded `pre_update_version`, and asserts that a
  `<0.47.0`-compatible open **succeeds** — i.e. both markers read `0.46.0` and
  `migrate_data_dir`'s data/backup agreement check (`:155`) passes. Without the
  marker rewrite this test fails with `migration from 0.47.0 is not supported`,
  which is exactly the brick §4f exists to prevent.
- **Rollback-claimed migrations confine their writes to `states.db`.** The
  snapshot covers the states DB only (§4f), so this is a reviewable property of
  each migration, not a runtime check: the migration added in this slice writes
  only under `data_dir/states.db`, and the §4f constraint is recorded for
  future migrations.

## 6. Issue decomposition (AgentCoop)

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
   core-update rollback), the **`idempotency_key`-unique** key (one row per
   key), tests. **Does NOT add its CF to `MAP_NAMES`** (that is issue 5).
5. **Migration + format bump + CF registration** (§4f) — `migrate_0_46_to_0_47`,
   bump `COMPATIBLE_VERSION_REQ`, old-shape structs, migration test fixture,
   **AND register the two new CFs in `MAP_NAMES`** in this same slice (so no
   `0.46.0` dir gets a new CF without the bump — §4f). Must specify **how the
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
