# 04 - Permission calculation

## Scope

**Permission checks**
- `auth.has_permissions` `022_functions_auth_permission.sql:63`, `auth.has_permission` `022:144`
- `auth.is_owner` `048_update_permissions_v2-1.sql:102` (owner bypass)
- `internal.throw_no_permission` (4 overloads) `022:23-53`, `auth.throw_no_access` `022:13`
- `unsecure.recalculate_user_groups` `019_functions_unsecure.sql:2016`, `unsecure.recalculate_user_permissions` `019:2143`
- Views `auth.effective_permissions` `015_views.sql:30`, `auth.user_group_members` `015:47`

**Permission tree**
- `auth.create_permission` `022:257` -> `unsecure.create_permission` `019:1112`, `unsecure.create_permission_as_system` `019:1193`
- `auth.set_permission_as_assignable` `022:179` -> `unsecure.set_permission_as_assignable` `019:910`
- `unsecure.update_permission_full_code` `019:1016`, `unsecure.update_permission_full_title` `019:971`
- Short codes: `unsecure.compute_short_code` `019:1040`, `unsecure.update_permission_short_code` `019:1101`, `public.get_permissions_map` `022:976`
- `auth.ensure_permissions` `022:996`, `auth.get_all_permissions` `022:291`, `auth.search_permissions` `022:826`

**Permission sets**
- `auth.create_perm_set` `022:318` -> `unsecure.create_perm_set` `019:1244`; `unsecure.create_perm_set_as_system` `019:1297`
- `auth.update_perm_set` `022:347` -> `unsecure.update_perm_set` `019:1345`
- `auth.create_perm_set_permissions` `022:382` / `auth.delete_perm_set_permissions` `022:400` -> `019:1400` / `019:1444`
- `unsecure.copy_perm_set` `019:2423` (no `auth.*` wrapper exists), `auth.ensure_perm_sets` `022:1150`
- `auth.get_perm_sets` `022:303`, `auth.search_perm_sets` `022:899`

**Assignments**
- `auth.assign_permission` `022:204` -> `unsecure.assign_permission` `048:131`; `unsecure.assign_permission_as_system` `019:958`
- `auth.unassign_permission` `022:233` -> `unsecure.unassign_permission` `048:240`
- Readers: `auth.get_user_permissions` `022:418`, `auth.get_user_assigned_permissions` `022:812`, `auth.get_effective_group_permissions` `022:154`, `auth.get_assigned_group_permissions` `022:166`, `auth.ensure_groups_and_permissions` `022:752`, `auth.get_users_groups_and_permissions` `022:790`

**Cache**
- Table `auth.user_permission_cache` `013_tables_auth.sql:156` (unique `(user_id, tenant_id)` `013:560`)
- `unsecure.clear_permission_cache` `019:13` (hard), `unsecure.invalidate_group_members_permission_cache` `019:28`, `invalidate_perm_set_users_permission_cache` `019:229`, `invalidate_users_permission_cache` `019:264`, `invalidate_permission_users_cache` `019:280` (soft)
- Triggers in `033_triggers_cache_and_notify.sql`: `cache_user_group_member_delete` `:36`, `cache_user_group_status_change` `:49`, `cache_user_group_before_delete` `:66`, `cache_provider_before_delete` `:91`, `cache_provider_status_change` `:113`, plus `notify_*` (pg_notify only)

**Seeds / grants**
- `auth.seed_permission_data` `022:467`, `047_seed_permissions.sql`, `99_fix_permissions.sql` (configured post-update script), `099_fix_permissions.sql`

**Tables**: `auth.permission` `013:237`, `auth.perm_set` `013:259`, `auth.perm_set_perm` `013:282`, `auth.permission_assignment` `013:372` (unique indexes `013:584-591`).

## Actors & preconditions

| Actor | What they do here |
|---|---|
| System user (id 1) | Seeds/migrations only. Bypasses every check. Must never be used at runtime. |
| Tenant-wide owner (`auth.owner` row with `user_group_id is null`) | Bypasses every check in the owned tenant. |
| Group owner | No bypass in `has_permissions` (since v2.1). |
| Permission manager / Full admin (tenant 1) | Creates global permissions, perm sets, assignments. |
| Tenant admin (tenant N) | Manages perm sets and assignments in tenant N only. |
| Service accounts (ids 2-6, 800) and API-key technical users | Ordinary users for permission checks, get perm sets assigned by seed. |
| Any `auth.*` / `public.*` function | Calls `auth.has_permission(s)` with the caller's `_user_id` and `_tenant_id`. |

Preconditions: the user exists in `auth.user_info`. For non-cached checks the user must be active and unlocked. Permission codes are global `ltree` paths. Perm sets, groups and assignments belong to one tenant.

## Invariants

### A. Check semantics
- **I-04-01** `auth.has_permissions(_user, _corr, _codes[], _tenant, _throw_err)` returns `true` iff the user holds **at least one** of `_codes` in `_tenant` (ANY, not ALL). Source: docs concepts/permission-model.md "passes if user has ANY", reference/permissions.md; test test_permission_checks (T5-T7 only cover "all"/"none", so ANY is not tested).
- **I-04-02** `auth.has_permission` is exactly `has_permissions` with a one-element array. Source: docs reference/permissions.md; code `022:144`.
- **I-04-03** Matching is exact on the full code text. A short code passed as `_codes` never matches. Holding a parent code does not satisfy a check for a code that does not exist in the tree. Source: CHANGELOG.md:1698 ("server-side checks remain text-based"); code `022:118` **[confirm]**.
- **I-04-04** On denial with `_throw_err = true`, the function raises SQLSTATE `32001` (`err_no_permission`, via `raise_52109`). On denial with `_throw_err = false`, it returns `false` and raises nothing. Source: docs reference/permissions.md; error-codes.md; test test_permission_checks T3/T4.
- **I-04-05** A denial with `_throw_err = true` leaves a `32001` journal entry with the user id and requested codes in the caller's tenant, and that entry must survive the exception. Source: docs permission-model.md flowchart ("Log to journal + raise error"); code `022:129` **[confirm]** (see OQ-04).
- **I-04-06** The check is evaluated **only** against `_tenant_id`. Assignments, perm sets and groups of other tenants never contribute, and that includes tenant 1 (`_tenant_id = 1` gets no special treatment in `has_permissions`). Source: docs permission-matrix.md ("full tenant isolation"); code comment `022:86`.
- **I-04-07** `_tenant_id` defaults to `1`. A caller that omits it is checked against the admin tenant. Source: docs reference/permissions.md.

### B. Bypasses
- **I-04-08** `_target_user_id = 1` returns `true` without reading the cache or the user row. Source: docs permission-model.md "System user bypass"; test test_permission_checks T1.
- **I-04-09** A user with a tenant-wide owner row (`auth.owner.user_group_id is null`) for `_tenant_id` gets `true` for every code in that tenant. Source: docs permission-model.md "Tenant owner bypass", permission-matrix.md.
- **I-04-10** Owning a group (`auth.owner.user_group_id = G`) grants no bypass. Neither does owning another tenant. Source: CHANGELOG v2.1; docs reference/ownership.md; test test_tenant_scoping_security T1/T2.
- **I-04-11** The owner bypass must not let in a user who is disabled, locked or deleted, or a soft-deleted tenant. The owner path should respect the same state rules as I-04-12..14. Source: common sense; code `022:79` checks only `auth.owner` **[confirm]** (see OQ-01).

### C. User and tenant state
- **I-04-12** A disabled user (`is_active = false`) never passes a non-bypass check. When the cache has to be rebuilt, the check raises `33003`. Source: docs permission-model.md "Validates the user is active and not locked"; code `019:2166` **[confirm]** (raise vs return `false` under `_throw_err = false`, see OQ-05).
- **I-04-13** A locked user (`is_locked = true`) never passes a non-bypass check. Rebuild raises `33004`. Source: as I-04-12; code `019:2170`.
- **I-04-14** For a user id that does not exist, an uncached check raises `33001` (`raise_52103`). Source: code `022:94-99` **[confirm]**.
- **I-04-15** Disabling or locking a user hard-deletes all of their cache rows (every tenant) in the same transaction, so a valid cache row can never let them pass afterwards. Source: docs permission-model.md invalidation table; code `020_functions_auth_user.sql:70,141`, `037_functions_auto_lockout.sql:94`; test test_disabled_locked_users.
- **I-04-16** Permissions in a soft-deleted tenant (`auth.tenant.deleted_at is not null`) are not granted. A rebuilt cache must not restore them until the tenant is restored. Source: docs concepts/multi-tenancy.md "blocks access"; code `019:1970` only deletes the cache, and the rebuild does not filter deleted tenants **[confirm]** (see OQ-02).

### D. Effective permission resolution
- **I-04-17** Effective permissions of user U in tenant T are the union of (a) assignments with `user_id = U, tenant_id = T` and (b) assignments with `user_group_id = G, tenant_id = T` for every group G that U is a member of. Source: docs permission-model.md "Inheritance Model".
- **I-04-18** Only groups belonging to T contribute in T. A group assignment counts only when `group.tenant_id = assignment.tenant_id`. A perm set counts only when `perm_set.tenant_id = assignment.tenant_id`. Source: CHANGELOG v2.1; code `048:150` enforces this at write time, the rebuild at `019:2218-2243` does not re-check **[confirm]**.
- **I-04-19** Inactive groups (`user_group.is_active = false`) contribute nothing. Source: docs concepts/group-types.md:20 "Inactive groups are excluded from permission resolution". The code reads `auth.user_group_members` (`015:47`), which does not filter `is_active` (see OQ-03).
- **I-04-20** Membership from all three group types counts the same way: manual members (internal/hybrid) and mapped members (external/hybrid, written by `recalculate_user_groups` from the last-used identity's `provider_groups`/`provider_roles`). Source: docs permission-model.md note, group-types.md; CLAUDE.md "Example Flow".
- **I-04-21** Before an uncached check, group membership is recomputed from the user's `last_used_provider_code`. Mapped memberships no longer backed by a mapping are removed, and new ones are added. Source: docs permission-model.md "Stage 1".
- **I-04-22** Default groups (`is_default = true`) are joined automatically. They should only be joined in tenants the user belongs to. Source: docs permission-model.md Stage 1 step 3; code `019:2040-2045` inserts membership into every default group of every tenant **[confirm]** (see OQ-06).

### E. Hierarchy and assignability
- **I-04-23** Holding a permission P (directly or through a perm set) grants P and every descendant D with `D.node_path <@ P.node_path`. Source: docs permission-model.md "Hierarchical Structure".
- **I-04-24** Holding a child never grants its parent or its siblings. Source: ltree semantics; docs permission-model.md.
- **I-04-25** A permission with `is_assignable = false` never appears in the effective list. Its assignable descendants are still granted when an ancestor is held. Source: docs permission-model.md "Assignability"; code `019:2230,2242`.
- **I-04-26** A perm set with `is_assignable = false` contributes nothing to anyone, including existing assignments. Source: code `019:2230,2253` **[confirm]**.
- **I-04-27** `assign_permission` rejects a non-assignable permission (`32003`) and a non-assignable perm set (`32005`). `create_perm_set` rejects non-assignable permissions (`32008`). `create_perm_set_permissions` must apply the same rule (`32008`). Source: error-codes.md; code `048:173-198`, `019:1253`. `019:1400` does not check (see OQ-09) **[confirm]**.
- **I-04-28** Only `*_as_system` seed helpers may put non-assignable permissions (such as `resources`) into a perm set. Source: code comment `019:1305`.

### F. Permission tree and short codes
- **I-04-29** The permission tree is global: one row per `full_code` (unique). `full_code` is the dot-joined chain of ancestor codes. `node_path` is the chain of ids. Source: docs permission-model.md table; `013:569`.
- **I-04-30** Creating a child under a missing parent raises `32007`. Creating a child sets the parent's `has_children = true`. Source: error-codes.md; test test_permission_crud T2/T3.
- **I-04-31** Every permission has a `short_code`, either custom or auto-computed. Short codes are unique (`uq_permission_short_code`). Auto codes are two-digit ordinals per level (`01.02`), and their depth equals the tree depth. Source: CHANGELOG.md:1671-1696; test test_short_code T1-T9, T13.
- **I-04-32** Once issued, a permission's short code never changes, and creating or deleting permissions never produces a short code that collides with an existing one. Source: CHANGELOG.md:1671 ("download mapping once at startup") **[confirm]** (see OQ-10).
- **I-04-33** The cache stores `short_code_permissions` alongside the full codes, for the same set of permissions. Source: docs permission-model.md; test test_short_code T14/T15.
- **I-04-34** Changing the global tree (`create_permission`, `set_permission_as_assignable`, `ensure_permissions`) changes behaviour in every tenant. It should therefore require the permission in the admin tenant (1), not in an arbitrary caller tenant. Source: CLAUDE.md "Global across all tenants" **[confirm]** (see OQ-07).
- **I-04-35** `ensure_permissions(_is_final_state := true)` requires `permissions.delete_permission` and a non-null `_source`. It deletes only permissions with that `_source` that are missing from the input, and removes their `perm_set_perm` and assignment rows. Source: docs reference/permissions.md "Final state mode".

### G. Permission sets
- **I-04-36** A perm set belongs to exactly one tenant. `code` is unique per tenant. Every `auth.*` perm-set operation on a set of another tenant raises `32006`. Source: docs permission-model.md; reference/permissions.md (`update_perm_set`); code `022:367`, `019:1408,1452`.
- **I-04-37** Adding or removing perm-set permissions soft-invalidates the cache of every user who holds the set, directly or through a group, in the set's tenant. Source: CHANGELOG 2026-02-14; test test_permission_cache_invalidation T9/T10.
- **I-04-38** Changing a set's `is_assignable` invalidates the same users. Source: CHANGELOG "Cache Invalidation Gaps"; code `019:1383`.
- **I-04-39** `is_system` perm sets are protected from deletion, including `ensure_perm_sets(_is_final_state)`, and tenant callers cannot create them. Source: docs permission-model.md table ("protected from deletion") **[confirm]** (see OQ-08).
- **I-04-40** `copy_perm_set` creates a new set in the target tenant with the same permissions. Later changes to either set never affect the other. A missing source set raises `32004`. Source: docs permission-model.md; test test_permission_crud T14-T16.
- **I-04-41** A perm set's title and translations are per tenant. Renaming a set in tenant A never changes the title of the same-code set in tenant B. Source: common sense (tenant-specific sets) **[confirm]** (see OQ-11).
- **I-04-42** Deleting a perm set (`ensure_perm_sets` final state) removes its assignments and invalidates the cache of affected users before the rows disappear. Source: docs reference/permissions.md; code `022:1277`.

### H. Assignments
- **I-04-43** An assignment has exactly one target (user XOR group) and exactly one grant (perm set XOR permission). Errors: no target `31001`, no grant `31002`, both targets SQLSTATE `22023`. Source: docs reference/permissions.md "not both"; code `048:143-156`. Both grants supplied is not rejected **[confirm]** (see OQ-12).
- **I-04-44** The group must belong to `_tenant_id` (else `33011`). The perm set is looked up by code inside `_tenant_id` (else `32004`). The target user must exist (else `33001`). Source: docs reference/permissions.md; CHANGELOG v2.1; test test_tenant_scoping_security T3/T6.
- **I-04-45** `unassign_permission` removes only an assignment whose `tenant_id = _tenant_id`. An unknown id or another tenant's id raises `32009`. Source: CHANGELOG v2.1; test test_tenant_scoping_security T4/T5.
- **I-04-46** A duplicate assignment (same tenant, target and grant) is rejected with a defined error code, not a raw unique violation. Source: common sense; `013:584-591` raises 23505 **[confirm]**.
- **I-04-47** Assigning to a user who is not a member of `_tenant_id` (`auth.tenant_user`) should be rejected. Source: common sense; not enforced at `048:166` **[confirm]** (see OQ-13).
- **I-04-48** Assign and unassign journal `12010` / `12011` in `_tenant_id`, with `target_type`, `target_name`, `assignment_id`. They also emit `pg_notify('permission_changes', permission_assigned|permission_unassigned)`. Source: code `048:215-235`, `033:176` **[confirm]** event payload.
- **I-04-49** After an assign or unassign, the next check of every affected user in that tenant reflects the change: the user's cache is cleared, or all group members' caches are soft-invalidated. Source: test test_permission_cache_invalidation T5-T8.

### I. Cache
- **I-04-50** A cache row exists per (user, tenant) and holds `groups`, `permissions`, `short_code_permissions` and `expiration_date`. A row with `expiration_date > now()` is authoritative. Otherwise the check rebuilds the cache. Source: docs permission-model.md "Cache Lifecycle".
- **I-04-51** TTL = `const.sys_param(auth, perm_cache_timeout_in_s)`, 300 s if unset. Source: docs permission-model.md.
- **I-04-52** A rebuild writes rows for every tenant where the user has groups or assignments, not only the checked tenant. Source: code `019:2302-2322` **[confirm]**.
- **I-04-53** Every mutation that can change a user's effective permissions invalidates (soft or hard) the affected (user, tenant) rows before commit. Covered mutations: assignment insert/delete, perm_set_perm insert/delete, perm set `is_assignable`, permission `is_assignable`, group member insert/delete, group enable/disable/delete, provider disable/delete, user disable/lock, tenant soft-delete, `ensure_permissions`/`ensure_perm_sets` final-state deletes, and group mapping create/delete. Source: CHANGELOG "Cache Invalidation Gaps" ("All permission-relevant mutations now take effect immediately"). Gaps: see OQ-14.
- **I-04-54** Changing `is_assignable` of permission P invalidates every user who holds P **or any ancestor of P**, because ancestors expand to P. Source: I-04-23 + I-04-53 **[confirm]** (`019:280` matches only `permission_id = P`, see OQ-14).
- **I-04-55** `clear_permission_cache(_deleted_by, _user, null)` deletes all tenants' rows for the user. With a tenant, it deletes only that tenant's row. `_deleted_by` is required. Source: docs performance.md; test test_permission_cache_invalidation T4.
- **I-04-56** Soft invalidation only moves `expiration_date` to `now()` and never grants anything. A stale row read after invalidation in the same transaction must trigger a rebuild (`<= now()`). Source: CHANGELOG 2026-02-14 "Why this works".

### J. Seeds
- **I-04-57** The seed creates the core tree (roots `authentication`, `areas`, `tokens`, `permissions`, `resources` non-assignable) and the system perm sets in tenant 1, all with `source = 'core'` and `is_system = true`. Source: docs reference/permissions.md "Seed Data".
- **I-04-58** Every code listed in a seeded perm set exists in the tree. Unknown codes must fail the seed, not be silently dropped. Source: common sense; `019:1327` silently drops them **[confirm]** (see OQ-15).
- **I-04-59** `read_all_*` (cross-tenant) permissions are held only by the System admin and Full admin sets. Source: memory/CLAUDE.md "13 read_all_* permissions ... included in System admin and Full admin" **[confirm]** (see OQ-16).
- **I-04-60** Service accounts 2-6 and 800 get exactly their `svc_*` set in tenant 1, and nothing else. Source: `047_seed_permissions.sql:31-36`; CHANGELOG.md:1426-1434.

## Flows

**Check (`has_permissions`)**
1. `user_id = 1` -> `true`.
2. Tenant-wide owner of `_tenant_id` -> `true` (see I-04-11).
3. Read the cache row (user, `_tenant_id`). If valid -> go to step 6.
4. User missing -> `33001`. `recalculate_user_groups('permission_check', user, last_used_provider_code)`: unknown provider -> `22023`. Joins default groups. If the provider allows mapping, syncs mapped members and hard-clears the cache of tenants whose membership changed.
5. `recalculate_user_permissions(user, _tenant_id)`: disabled -> `33003`, locked -> `33004`. Computes all tenants and upserts cache rows with expiry `now() + TTL`.
6. Any requested code in `permissions[]` -> `true`. Otherwise: if `_throw_err`, journal `32001` and raise `32001`; else return `false`.

**Assign**: check `permissions.assign_permission` in T -> validate (I-04-43/44) -> insert `permission_assignment(tenant=T)` -> journal `12010` -> notify -> clear the user's cache for T, or soft-invalidate all group members for T.

**Unassign**: check `permissions.unassign_permission` in T -> find the assignment in T (else `32009`) -> delete -> journal `12011` -> notify -> invalidate as for assign.

**Create permission**: check `permissions.create_permission` -> insert -> title translation -> node_path (parent lookup, else `32007`) -> parent `has_children` -> full_title, full_code -> short code (custom or computed) -> journal `12001` (tenant 1).

**Create perm set**: check `permissions.create_permission_set` in T -> reject non-assignable codes (`32008`) -> insert (code = slug(title), tenant T) -> translation -> `perm_set_perm` rows -> journal `12020`.

**Modify perm set contents**: check `permissions.update_permission_set` in T -> set in T (else `32006`) -> insert/delete `perm_set_perm` -> journal `12021` -> soft-invalidate holders in T -> notify `perm_set_permissions_added/removed`.

**Set permission assignable**: check `permissions.update_permission` -> requires id or code (`31003`), unknown code `32002` -> update -> invalidate holders (I-04-54) -> journal `12002`.

## Failure behaviour

| Operation | Condition | Expected |
|---|---|---|
| any `auth.*` in this domain | caller lacks the required permission in `_tenant_id` | `32001` (journal `32001`) |
| `has_permission(s)` | `_throw_err=false`, not held | `false`, no exception |
| `has_permission(s)` | uncached, user missing / disabled / locked | `33001` / `33003` / `33004` (see OQ-05) |
| `has_permission(s)` | last-used provider code no longer exists | `22023` **[confirm]** |
| `assign_permission` | no target / no grant / both targets | `31001` / `31002` / `22023` |
| `assign_permission` | group not in tenant / user missing | `33011` / `33001` |
| `assign_permission` | perm set not in tenant / not assignable | `32004` / `32005` |
| `assign_permission` | permission missing / not assignable | `32002` / `32003` |
| `assign_permission` | duplicate | defined code (today 23505), see I-04-46 |
| `unassign_permission` | id unknown or other tenant | `32009` |
| `create_permission` | parent missing | `32007` |
| `create_permission` | duplicate full_code / short_code | defined code (today 23505) **[confirm]** |
| `set_permission_as_assignable` | neither id nor code / unknown code / unknown id | `31003` / `32002` / `32002` (today: silent no-op for unknown id) **[confirm]** |
| `create_perm_set` | contains non-assignable permission | `32008` |
| `create_perm_set` | contains unknown code | `32002` (today: silently dropped) **[confirm]** |
| `update_perm_set`, `create/delete_perm_set_permissions` | set not in tenant | `32006` |
| `copy_perm_set` | source not in source tenant | `32004` |
| `ensure_permissions` / `ensure_perm_sets` final state | `_source` null / missing delete permission | raw exception / `32001` |

## Open questions

- **OQ-01 Owner bypass ignores user and tenant state.** `022:79` returns `true` for a tenant-wide owner before any `is_active`/`is_locked` check or cache read, and `auth.is_owner` (`048:102`) does not look at `user_info` or `tenant.deleted_at`. A disabled or locked owner, or the owner of a soft-deleted tenant, still passes every check. The code comment `022:79` says "NOT REALLY SAFE FOR SOME INTERNAL/SYSTEM PERMISSIONS". Should owners bypass everything, including tenant-1 global operations such as `permissions.create_permission`?
- **OQ-02 Soft-deleted tenants regain permissions.** `unsecure.soft_delete_tenant` (`019:1955`) deletes the tenant's cache, but `recalculate_user_permissions` (`019:2214-2218`) joins `auth.tenant` without `deleted_at is null`, so the next `has_permission` rebuilds and grants. Docs say a soft delete "blocks access".
- **OQ-03 Disabled groups still grant permissions.** `recalculate_user_permissions` uses view `auth.user_group_members` (`015:47`), which has no `is_active` filter. `auth.active_user_groups` exists but is unused here. Docs (group-types.md:20) and the CHANGELOG "disabling a group invalidates members' cache" both imply exclusion. The trigger `033:49` invalidates the cache, but the rebuild re-adds the permissions.
- **OQ-04 The denial journal is rolled back.** `022:129` writes the `32001` journal and then raises in the same transaction. Unless the journal is written autonomously, the audit row is lost on every throwing denial. Is a persisted denial record required?
- **OQ-05 `_throw_err := false` still throws for disabled/locked users** (`019:2166-2170`) when the cache is missing. Should a silent check return `false` instead?
- **OQ-06 Default groups of every tenant.** `recalculate_user_groups` (`019:2040-2045`) adds the user to every `is_default` group in **all** tenants, including inactive ones, and without invalidating the cache of those other tenants. Combined with I-04-17, a default group with an assigned perm set in tenant X grants permissions in X to every user who runs any permission check. Intended? (Overlaps domain 03.)
- **OQ-07 Global tree mutated from any tenant.** `auth.create_permission`, `set_permission_as_assignable` and `ensure_permissions` check the permission in the caller-supplied `_tenant_id`. A tenant-N owner (bypass) or a tenant-N admin holding `permissions.*` can then alter the tree for every tenant. Should these require tenant 1?
- **OQ-08 `is_system` perm sets are not protected.** `auth.create_perm_set` lets any caller set `_is_system = true`. `ensure_perm_sets(_is_final_state)` (`022:1268`) and `update_perm_set` do not exclude system sets. There is no `auth.delete_perm_set` at all, and test_permission_crud T6 deletes through raw SQL.
- **OQ-09 `create_perm_set_permissions` skips the assignability check** (`019:1413`), unlike `create_perm_set` (`019:1253`), and silently ignores unknown codes. So `ensure_perm_sets` on an existing set can add non-assignable permissions.
- **OQ-10 Short code collisions after deletion.** `compute_short_code` (`019:1040`) counts siblings with `permission_id <=` self. After a sibling is deleted (`ensure_permissions` final state), a newly created sibling can compute an ordinal already held by an existing permission, which gives a unique violation. Existing codes are never recomputed, and a custom short code can also collide with a future auto code (`uq_permission_short_code`).
- **OQ-11 Translations keyed by `code`, not tenant or full path.** Perm set titles (`019:1268`, `2471`) use `data_object_code = code` with the default `tenant_id = 1`, so same-code sets in different tenants (for example `tenant_admin` copied by `023:488`) share one title row. Permission titles use `code` in `create_permission` but `full_code` in `ensure_permissions` (`022:1082`), so `groups.get_all_groups` and `tenants.get_all_groups` share a title.
- **OQ-12 Both grants allowed.** `assign_permission` accepts `_perm_set_code` and `_permission_full_code` together and stores both, although docs say "not both". `raise_52283` is called with `_permission_full_code` instead of the set code (`048:183`).
- **OQ-13 Tenant membership is not required.** Assignments can target a user with no `tenant_user` row in T, and the rebuild grants regardless. Docs (multi-tenancy.md:66) say group membership is the main access mechanism. Is a direct assignment enough to "belong" to a tenant?
- **OQ-14 Cache invalidation gaps against I-04-53.**
  (a) `ensure_permissions` final state deletes permissions, assignments and `perm_set_perm` rows (`022:1107-1111`) with no invalidation.
  (b) `invalidate_permission_users_cache` (`019:280`) misses users who hold an ancestor of the changed permission.
  (c) Group mapping create/delete (`033:283`) only notifies, so mapped members keep or lack group permissions until TTL.
  (d) `recalculate_user_groups` default-group inserts (OQ-06).
  (e) The perm set `is_assignable` change and perm-set content changes use the caller `_tenant_id`, but `unsecure.update_perm_set` (`019:1345`) updates by id without a tenant filter (the `auth.*` wrapper checks the tenant).
  (f) User assign/unassign uses a hard clear, while docs list it as soft. That is harmless, but the docs disagree.
- **OQ-15 Seed typo.** The `Tenant owner` set lists `journal.get_journal_payload` (`022:658`), but the permission is `journal.get_payload`, and it is silently dropped.
- **OQ-16 `read_all_*` leaks into non-admin sets.** `read_all_*` permissions are assignable children of `users`, `groups`, `tenants`, `api_keys`, `authentication`. So the `User manager` (`users`), `Group manager` (`groups`), `Tenant admin` (`tenants`, copied into every new tenant at `023:488`) and `Api key manager` sets also grant them. Tenant admin also gets `tenants.create_tenant`. Intended?
- **OQ-17 Which fix script runs.** `debee.env:18` runs `99_fix_permissions.sql` (grants and ownership). `099_fix_permissions.sql` contains only a partial grant, sits in the numbered migration range, and duplicates the name. Which one is authoritative?
- **OQ-18 Readers ignore the tenant.** `unsecure.get_effective_group_permissions` / `get_assigned_group_permissions` (`019:688,725`) do not filter by `_tenant_id` or by the group's tenant, so a caller with `groups.get_permissions` in tenant A can read any group's assignments (overlaps domain 05).
- **OQ-19 `has_permissions` is declared `stable`** (`022:64`) but rebuilds groups, inserts memberships and writes the cache through volatile callees, and creates a temp table (`019:2204`). Is that acceptable for planner caching and read replicas? (perf / domain 08)
- **OQ-20 Inconsistent grouping in `recalculate_user_permissions`.** The group branch pairs `pa.tenant_id` with the **group's** `tenant_uuid` (`019:2223`). With the v2.1 write-time rule they match, but rows that predate v2.1 or were inserted directly would produce a mismatched cache row.

## Known coverage

| Suite | Covers |
|---|---|
| `test_permission_checks` | I-04-04, 08, basic I-04-17 (direct perm set), default groups, `get_users_groups_and_permissions` |
| `test_permission_crud` | I-04-30, 36 (update), 40, 43-45 (happy paths), readers |
| `test_permission_cache_invalidation` | I-04-37, 49, 55, `recalculate_user_groups` parameter validation |
| `test_short_code` | I-04-31, 33 |
| `test_tenant_scoping_security` | I-04-10, 44, 45 |
| `test_disabled_locked_users` | I-04-15 (cache clear only, not `has_permission`) |

No test covers these invariants: I-04-01 (ANY semantics with one of two codes held), 03, 05, 06 (cross-tenant assignment does not leak into another tenant's check), 09 (positive owner bypass in the permission suite), 11, 12-14 through `has_permission`, 16, 18, 19, 20 (external mapping to permission end to end), 22, 23-26 (parent expansion, non-assignable child, non-assignable set), 27 (`create_perm_set_permissions`), 32, 34, 35, 38, 39, 41, 42, 46, 47, 48 (journal/notify payloads), 50-54 (TTL, multi-tenant rebuild, ancestor invalidation, final-state invalidation), 57-60.
Functions with no test at all (coverage.md): `auth.create_perm_set_permissions`, `auth.delete_perm_set_permissions`, `auth.set_permission_as_assignable`, `auth.get_all_permissions`, `auth.get_user_assigned_permissions`, `auth.ensure_groups_and_permissions`, `auth.seed_permission_data`, `internal.throw_no_permission`, `unsecure.invalidate_*` (direct), `unsecure.get_effective_group_permissions`, `unsecure.get_assigned_group_permissions`, `unsecure.update_permission_short_code`.
