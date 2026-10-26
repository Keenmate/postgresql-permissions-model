# Changelog

All notable changes to this project will be documented in this file.

The format is loosely based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/). Entries are date-tagged rather than semver-tagged: the project is pre-release and tracks DB-component versions (e.g. `postgresql_permissionmodel` v2) in `public.__version` instead of bumping a semver tag per change. See the **Component Versions** section at the bottom.

## 2026-10-26 — v2.1: tenant-scoping and ownership security fixes

From this release on, changes to an already-shipped v2 schema go into a numbered update script with its own `start/stop_version_update` record, not into the original `010`–`047` files. The first is **`048_update_permissions_v2-1.sql`** (`postgresql_permissionmodel` **2.1**). These bugs were found and fixed in the v1 line downstream (`gcp-documenthub-database` 110/v56). v2 had the same bugs, except where noted.

### Fixed (security)

- **Owning one group made a user a tenant-wide owner.** `auth.is_owner(_user_id, _correlation_id, null, _tenant_id)` asks "is this user a tenant-wide owner?". Its filter `(_user_group_id is null or user_group_id = _user_group_id)` matched every owner row, including group owners. Two places act on that answer:
  - `auth.has_permissions` lets tenant-wide owners through every check, so a group owner passed every permission check in the tenant.
  - `auth.has_resource_access` (and its siblings in `035`) do the same for resource access.

  A null group now matches only tenant-wide rows (`user_group_id is not distinct from _user_group_id`).
- **`auth.unassign_permission` deleted assignments in any tenant.** The delete was by id only, so holding `permissions.unassign_permission` in one tenant was enough to delete another tenant's assignments. `unsecure.unassign_permission` now works only on an assignment of `_tenant_id`. An assignment of another tenant, or an unknown id, raises the new **32009**.
- **`auth.assign_permission` accepted a group from another tenant.** `unsecure.assign_permission` now requires the group to be in `_tenant_id`, otherwise **33011**. All existing callers already pass the group's own tenant.
- **Group mapping writers ignored the tenant.**
  - `auth.create_user_group_mapping`:
    - the group must now be in `_tenant_id` (33011) and active (33012). The old inactive check never fired, because it selected `is_active, tenant_id` into a single variable.
    - a duplicate raises the new **33023** instead of a raw unique violation.
  - `auth.delete_user_group_mapping` deletes only a mapping of a group in `_tenant_id`. A foreign or unknown id raises the new **33022**. It used to delete in any tenant, and do nothing silently for an unknown id.
- **An expired API key still validated.** `auth.validate_api_key` now also requires `expire_at is null or expire_at > now()`. An expired key gets the same 30001 as a wrong key or secret.

### Fixed

- **`auth.get_tenant_groups` swapped two columns:** it returned the group title in `__group_code` and the code in `__group_title`.
- **`unsecure.create_user_group_as_system` / `create_user_group_member_as_system` returned no rows.** Each joined the new id back to the table in the same statement, which can't see the row the call just inserted. Both now read the row in a second statement. The member helper also looked the group up by title in every tenant, and every tenant has the same default group titles, so it could pick another tenant's group. It now looks only in `_tenant_id`.

### Not affected

- **`auth.can_manage_user_group`:** v1's bypass for non-members doesn't apply. v2 resolves membership through `unsecure.get_cached_group_ids`, which returns `'{}'` rather than null.
- **Cache clearing on assign/unassign:** v2's `unsecure.assign_permission` / `unassign_permission` already cleared the affected users' permission cache.

### Tests

- New suite **`tests/test_tenant_scoping_security`** (11 tests). It runs as a non-system `full_admin` user, because user 1 short-circuits every check, and uses a second tenant for the cross-tenant cases.
- **`test_ownership/002` TEST 12 asserted the `is_owner` bug as intended behaviour** ("null group_id matches any ownership"). It is inverted.
- **`test_api_keys/002` TEST 8 counted any exception as PASS.** It now expects SQLSTATE 30001.
- **Verified on a fresh `fullService` build:** 829/829 tests pass in 38 suites. On a build through `047` only, every new test fails except TEST 6, the same-tenant control that is meant to pass.

Why the suite missed these bugs:
- Most suites call as user 1, which skips every permission, tenant and owner check.
- No test passes a second tenant's ids to a mutating function.
- Results were barely asserted, e.g. `count(*) >= 1` on `get_tenant_groups`.
- The two `*_as_system` group helpers had no test callers at all.

## 2026-09-18

### Changed

- **Journal/storage config helpers are now native permissions-model code, not vendored `common_helpers`.** The old `013_update_common-helpers_v1-6.sql` becomes `012_functions_journal_helpers.sql`, with its `start/stop_version_update('1.6', … 'common_helpers')` wrapper removed. The four functions (`helpers.should_log_journal`, `helpers.is_event_read_only`, `helpers.should_store_locally`, `helpers.should_notify_storage`) read `const.sys_param` / `const.event_code`, so they were mis-tracked under the stateless `common_helpers` library. They were already inside the `postgresql_permissionmodel` v2 span (010→047), so the standalone version record was redundant double-tracking. As part of this, the migrations were renumbered to close the `011` gap and resolve a `013` collision: `const.*` tables move to `011_tables_const.sql` (still their sole definition), and the journal helpers take `012`. Upstream `../postgresql-common-helpers` drops its back-ported `009_update_common-helpers_v1-6.sql` (and the `test_journal_helpers` suite); the `common_helpers` version line now skips `1.6` (`1.5` → `1.7`) in both repos, keeping them in agreement.

## 2026-08-30

### Fixed

- **`auth.get_tenant_by_id` now exposes `__deleted_at` / `__purged_at`** — the single-fetch path was missing the two soft-delete columns that `auth.get_tenants` (the list path) gained in the 2026-08-17 tenant soft-delete work, so `get_by_id` could not signal that a tenant is soft-deleted or purged. Added both columns to its `returns table(...)` and select list in `023_functions_auth_tenant.sql`, matching `auth.get_tenants`. `tests/test_tenant_soft_delete/001_soft_delete_and_access.sql` gains an assertion that the by-id path reports `deleted_at` set / `purged_at` null after a soft delete.
- **`auth.create_service_user_info` stored `email` and `display_name` in each other's columns** — the wrapper passed `_email, _display_name` **positionally** into `unsecure.create_service_user_info`, whose parameter order is `(_username, _display_name, _email)`, so a service user created via the public API ended up with its email under `display_name` and vice-versa (e.g. `email = 'gordon cole'`). The underlying `unsecure` function and the seed-data callers were already correct and are unchanged; only the `auth` wrapper is fixed, now passing `_display_name := …, _email := …` by name (`020_functions_auth_user.sql`). New regression test `tests/test_service_user_info.sql` asserts each value lands in its own column. This escaped notice because callers rarely re-read the stored columns, and API keys (the main service-user path) don't set a display name.

## 2026-08-29

### Changed

- **Vendored common-helpers v1-7** from `../postgresql-common-helpers` as `045_update_common-helpers_v1-7.sql` (this repo was synced through v1-6). Four helper fixes: `helpers.normalize_text` gains a `_trim` mode parameter (`'both'` default / `'left'` / `'right'` / `'none'`) so it now trims by default in addition to unaccent+lower; `helpers.delete_jsonb_fields` drops `STRICT` (a single-arg call was silently returning `null` instead of the data unchanged); `helpers.get_code` fixes an unintended regex range in `[^a-z0-9\-_]` that let `\`, `]`, `^` pass through; `helpers.random_string` supports lengths beyond md5's 32 chars. The `nrm_search_data` triggers (`017_functions_triggers.sql`) that call `normalize_text` now get whitespace trimming for free. **Email storage is deliberately left on `lower(trim(...))`, not `normalize_text`** — `normalize_text` unaccents, which is wrong for email canonicalization (you don't want `café@x.com` folded to `cafe@x.com` for login lookups), and it matches how `username` is handled.

- **`auth.user_info` now keeps a normalized + original email pair**, mirroring the existing `username` / `original_username` split. New nullable `original_email` column stores the email exactly as supplied (trimmed only); the `email` column is now **consistently normalized** to `lower(trim(...))` on every write path. Previously `unsecure.update_user_info_basic_data` (the SSO re-login update path used by `auth.ensure_user_from_provider`) stored the raw email, so an existing user's `email` could drift to mixed-case/whitespaced values even though the login lookup key (`user_identity.uid`) stayed normalized. Both inserts (`unsecure.create_user_info`, `unsecure.create_service_user_info`) and the update now populate `email` (normalized) + `original_email` (original). `auth.ensure_user_from_provider`'s change-detection comparison was made case-insensitive and null-safe (`lower(trim(_email)) is distinct from` stored email) so a case-only difference no longer triggers a spurious update on every login. Added `tests/test_registration_login_events/008_email_normalization.sql` (3 assertions: register_user normalization + original_email preservation, and the SSO update path re-normalizing a changed email / never leaking a raw mixed-case email into the `email` column).

## 2026-08-26

### Changed

- **Examples reorganized into `examples/`** — the scratch `999-examples.sql` (a mix of working calls, raw table dumps, and a few syntactically broken statements) is replaced by seven topic-grouped scripts written to **showcase individual aspects** of the API: `01-user-provisioning`, `02-user-status`, `03-tenants-and-owners`, `04-groups-and-mappings`, `05-permissions-and-sets`, `06-tokens-and-events`, `07-api-keys`. They are **plain standalone SQL** — no psql meta-commands or `:'var'` interpolation, IDs looked up inline via sub-selects — so any single statement can be run on its own in any client (psql, DataGrip, DBeaver, …). Data **persists** (demo users are Twin Peaks characters on `@twinpeaks.com`); a new `examples/cleanup.sql` fully reverses everything (users, groups, perm sets, permissions, tenants — including tenant-seeded groups and the `tenant_identity` ledger row). Verified: all seven run error-free, then `cleanup.sql`, then all seven again (fully re-runnable). Added `examples/README.md`. The two resource-ACL demos moved too (`999-examples-icons*.sql` → `examples/resource-acl-icons*.sql`, `999-examples-organiogram.sql` → `examples/resource-roles-organiogram.sql`) with their internal `\i`/run-path references and `gen_icons_inserts.py` output path updated. `extract-db-objects.py` no longer special-cases the removed file; CLAUDE.md doc references updated.

## 2026-08-18

### Fixed

Three latent bugs surfaced by a full documentation-vs-source audit. All three shared the same reason they escaped the test suite: every affected test runs as the system user (`user_id = 1`), and `auth.has_permissions` short-circuits `return true` for user 1 (and for owners) **before** the permission code is ever looked up — so permission-string typos sit in a branch no test reaches with a scoped user, and same-user data paths mask the ID mix-up.

- **`auth.create_permission` / `auth.ensure_permissions` checked a non-existent permission** — both required `permissions.add_permission`, which is never seeded (the seeded node is `permissions.create_permission`). A user granted exactly `permissions.create_permission` would have been wrongly **denied**. Both checks now use `permissions.create_permission`.
- **`auth.get_provider_users` checked a non-existent permission** — required `manage_provider.get_users`; the seeded node is `providers.get_users` (title *"Get users"* under the `providers` parent). Corrected to `providers.get_users`.
- **`auth.create_user_tenant_preferences` wrote preferences under the wrong user** — the `insert` used `_user_id` (the acting caller) instead of `_target_user_id`, so an admin creating preferences for another user stored them under their own id. Now inserts `_target_user_id` (matching `auth.update_user_tenant_preferences`).

## 2026-08-17

### Added

- **Tenant soft delete, restore, and purge** — `auth.delete_tenant` is now a reversible **soft delete** (stamps `deleted_at`/`deleted_by` and clears the tenant's permission + group caches). `auth.restore_tenant` reverses it, and new `auth.purge_tenant` performs the permanent hard delete (the previous cascade) behind a **separate** `tenants.purge_tenant` permission. Purge requires the tenant to be soft-deleted first (two-step safety); the system tenant (id 1) and `is_removable = false` tenants are rejected from both delete and purge.
  - `auth.tenant` gains `deleted_at`, `deleted_by`, `purged_at`, `purged_by`.
  - Workers: new `unsecure.soft_delete_tenant` and `unsecure.restore_tenant`; the existing `unsecure.delete_tenant` is repurposed as the purge worker (stamps the identity ledger and emits `tenant_purged`).
  - **Block-at-boundary enforcement**: `auth.get_user_available_tenants` and `auth.update_user_last_selected_tenant` exclude/reject soft-deleted tenants. `auth.get_tenants` keeps them visible for management and exposes new `__deleted_at` / `__purged_at` columns.
  - `auth.delete_tenant_by_uuid` de-duplicated into a thin wrapper over `auth.delete_tenant`.
- **Permanent tenant identity ledger** — new append-only `auth.tenant_identity` table records every tenant `code` at creation time with a `unique(code)` constraint, making a code (or a title that derives the same code via `helpers.get_code`) **impossible to reuse even after a tenant is purged**. `auth.create_tenant` burns the code here first (raising the new `34004` on collision) and backfills uuid/tenant_id; purge stamps `purged_at` but never deletes the ledger row.
- New error codes: `34004` (code previously used), `34005` (already deleted), `34006` (not deleted — restore/purge require a soft-deleted tenant), `34007` (protected / non-removable). New events `11004 tenant_soft_deleted`, `11005 tenant_restored`, `11006 tenant_purged` (+ messages and en translations). New permission node `tenants.purge_tenant` (auto-covered by the `tenants` parent for admin roles).
- New test suite `tests/test_tenant_soft_delete` (16 assertions: soft-delete + access block, guards, restore, purge, identity ledger). `tests/test_tenant_crud` TEST 9 updated for the soft semantics.

### Changed

- **Removed the orphaned `11003 tenant_deleted` journal event** — superseded by `tenant_soft_deleted` / `tenant_purged`, and no longer emitted by any function. The `notify_tenant` trigger (and the `notify_tenant_users` view comment) that fire on physical row-delete were repointed `tenant_deleted` → `tenant_purged`, since a tenant row is now only physically removed via purge.
- **Consolidated 11 duplicate function definitions** left over from the in-flight resource-access/roles and translation-context reworks, restoring one-definition-per-function:
  - The role-aware resource-access functions (`has_resource_access`, `filter_accessible_resources`, `get_resource_access_flags`, `get_resource_access_matrix`, `get_resource_grants`, `get_user_accessible_resources`) now live solely in `035_functions_resource_access.sql`; the role tables and the shared `unsecure.ensure_resource_access_partition` helper moved into `034_tables_resource_access.sql` (before `035`, so the functions have in-order dependencies). `044_functions_resource_roles.sql` keeps only role management; `043_tables_resource_roles.sql` keeps role error functions + event/translation seeds.
  - The translation functions (`create_translation`, `copy_translations`, `get_group_translations`, `search_translations`) were folded back into `032_functions_translation.sql`; `045_translation_context.sql` is deleted (its `context` column already lived in `030`).
- **Permission-identifier naming unified to `_permission_full_code` / `__permission_full_code`** — the value passed to `auth.has_permission` is matched against `auth.permission.full_code` (the dotted ltree path), so the three prior spellings — `_perm_code`, `_permission_code`, and `can_manage_user_group`'s `_permission` — were unified to `_permission_full_code` for parameters and `__permission_full_code` for return columns, across all migration files. `_perm_set_code` (a distinct concept — permission *set* code) is deliberately untouched. `tests/test_api_keys/003_permissions.sql` updated for the renamed return column.
- **`_provider` → `_provider_code`** on `auth.create_external_user_group` and `auth.update_user_data` — the value is a provider code; `auth.create_user_group_mapping` already used `_provider_code`.
- **`create_journal_message*` calls schema-qualified** — all 127 unqualified `create_journal_message` / `create_journal_message_by_code` / `create_journal_message_for_entity` / `create_journal_message_for_entity_by_code` call sites across 16 files now carry an explicit `public.` schema to avoid `search_path` collisions.
- Verified end-to-end after every change: clean `fullService` rebuild + 812 tests across 37 suites passing.

## 2026-06-20

### Changed

- **Read-side validation for resource identifier** — `auth.has_resource_access`, `auth.get_resource_access_flags`, `auth.get_resource_access_matrix`, and `auth.get_resource_grants` now raise an exception when both `_resource_id` is empty/null **and** `_resource_path` is null, matching the existing rejection in the write-side functions. The check runs **before** the `user_id = 1` system-user shortcut and the owner shortcut, so a malformed call fails loudly regardless of caller identity (previously the system user silently got `true` while regular users silently got `false` — an asymmetry that could mask caller bugs by passing in tests but failing in production).
- The rule is centralized in new helper `unsecure.validate_resource_identifier(_resource_id jsonb, _resource_path text)`; all writers (`assign_resource_access`, `assign_resource_role`, `deny_resource_access`, `revoke_all_resource_access`, `revoke_all_resource_roles`) call it instead of inlining the check. Single source of truth for the "must supply an identifier" invariant.
- `_throw_err` on `has_resource_access` is unchanged and does **not** suppress this validation — the assert is about a malformed call, not a permission verdict.
- **New error code `35010 err_resource_identifier_required`** — disambiguates the "both null identifier" raise from the pre-existing `35005 err_resource_id_invalid` ("key not in schema") meaning. Previously both errors shared `35005`, making them indistinguishable downstream. `35005` now exclusively means "key not in schema"; `35010` means "no identifier supplied". The 35005 message template was also reworded to match what the code actually raises (was misleadingly "missing required key").
- **Eight previously-undocumented errcodes added to `const.event_code` + `const.event_message`** — `33016 err_provider_no_group_mapping`, `33017 err_provider_no_group_sync`, `33020 err_user_not_resolvable`, `33021 err_group_not_resolvable`, `34003 err_tenant_not_resolvable`, `35007 err_resource_role_not_found`, `35008 err_resource_role_invalid_flag`, `35009 err_resource_role_type_mismatch`. These were raised by code (in `016_functions_error.sql` and `043_tables_resource_roles.sql`) but had no corresponding metadata row, leaving UI/translation lookups with nothing to resolve.
- Tests: `tests/test_resource_access_path/008_invalid_input.sql` extended with 5 new cases (TEST 5–9) covering the new read-side raise for all four functions, including the system-user case. Existing TEST 1 updated to expect `35010` for the write-side both-null check. 796 tests across 36 suites pass.

## 2026-06-18

### Changed

- **Partial-key grants and denies** — `unsecure.validate_resource_id` no longer requires every key from the `key_schema` to be present in `_resource_id`. Any subset of the schema's keys is accepted; only unknown keys (not in the schema) are rejected. This lets a grant or deny be scoped at any level of the composite key (e.g. `{project_id: 42}` on `project.invoices` means "all invoices under project 42" — no `invoice_id` required). The `_allow_partial` parameter is **not** introduced; the relaxed validation applies uniformly.
- **`auth.has_resource_access` matching** — ancestor-level lookups now use containment (`_ancestor_key @> resource_id`) instead of exact equality (`resource_id = _ancestor_key`). Full-key stored grants/denies still match the exact resource; partial-key stored rows match every descendant resource under that key slice. Parent-grant cascade through ancestor key extraction is unchanged. Read semantics are otherwise identical.
- **Public-API ltree → text (API break)** — all `auth.*` resource-access and resource-role functions now accept `text` / `text[]` for path parameters and return `text` for path columns, never `ext.ltree` / `ext.ltree[]`. Conversion happens internally via `ext.text2ltree(...)`. Read-time semantics are unchanged.
  - Parameters changed: `auth.assign_resource_access`, `deny_resource_access`, `revoke_resource_access`, `revoke_all_resource_access`, `assign_resource_role`, `revoke_resource_role`, `revoke_all_resource_roles`, `has_resource_access`, `get_resource_access_flags`, `get_resource_access_matrix`, `get_resource_grants` — `_resource_path` is now `text default null`.
  - `auth.filter_accessible_resources` — `_resource_paths` is now `text[] default null` (was `ext.ltree[]`). This was the proximate cause: downstream code generators (Elixir, Go, TypeScript) cannot map the `_ltree` array type and failed with "dbType '_ltree' not found".
  - Return columns changed: `auth.create_resource_type`, `auth.update_resource_type`, `auth.ensure_resource_types`, `auth.get_resource_types` — `__path` is now `text` (was `ext.ltree`).
- **Variable naming convention tightened** — single underscore (`_`) is now reserved exclusively for input parameters; locals use `__` (and `___` on collision with `__`-prefixed return columns). See CLAUDE.md.
- **Codebase-wide locals sweep** — all PL/pgSQL local variables across the migration files were renamed from single `_` to `__` (or `___` where they would collide with `__`-prefixed return columns), bringing every existing function in line with the new naming rule. ~200 locals renamed across 12 files:
  - `004_create_helpers.sql` (3 locals in `helpers.path_to_ltree`)
  - `013_tables_auth.sql`, `014_tables_stage.sql`, `034_tables_resource_access.sql`, `043_tables_resource_roles.sql` (partition/setup helpers)
  - `019_functions_unsecure.sql` (5 locals; `_payload` scoped to `unsecure.notify_permission_change` since it's also a param of `unsecure.notify_journal_event`)
  - `021_functions_auth_group.sql` (22 locals across `auth.ensure_user_groups` + `auth.ensure_user_group_mappings`)
  - `022_functions_auth_permission.sql` (21 locals across `auth.ensure_permissions` + `auth.ensure_perm_sets`)
  - `033_triggers_cache_and_notify.sql` (23 locals across 11 trigger functions)
  - `035_functions_resource_access.sql` (50 locals; triple-underscore for locals colliding with `__path` / `__code` / `__title` / `__description` / `__key_schema` / `__access_flags` return columns in `auth.create_resource_type`, `auth.update_resource_type`, `auth.ensure_resource_types`, `auth.ensure_access_flags`)
  - `042_functions_invitation.sql` (4 locals; `_code` scoped to `unsecure.ensure_invitation_templates` since it's also a param elsewhere)
  - `044_functions_resource_roles.sql` (41 locals; triple-underscore for `___code`/`___title`/`___access_flags` in `auth.ensure_resource_roles`)
  - Done via word-boundary `sed` with per-function line ranges where local names overlapped with parameters in sibling functions in the same file. Each batch verified with `fullService` + the full 791-test suite.

### Notes

- Symmetric model: grants and denies share the same validation and matching semantics. A partial-key grant ("read on all invoices under project 42 for group X") and a partial-key deny ("no invoices under project 42 for user Y") are both expressible.
- New CLAUDE.md rule: **public `auth.*` / `public.*` signatures must use only stock PostgreSQL types + `jsonb`**. Extension types (`ext.ltree`, etc.) stay inside tables, `internal.*`, `unsecure.*`, and `helpers.*`. This unblocks code generation and keeps the callable surface portable.
- Tests, examples (`999-examples-icons.sql`), and `tests/test_resource_access_path/*` updated to pass plain text paths.
- All 791 tests across 36 suites pass after every step of the refactor.

## 2026-04-17

### Added

- **Path-based resource access** — instance-level inheritance via `ltree` paths. Filesystem-style ACL where a grant on an ancestor path cascades to all descendants, with deny-override semantics.
  - `auth.resource_access.resource_path ext.ltree` (nullable) — stored ancestor path
  - `auth.resource_role_assignment.resource_path ext.ltree` (nullable) — same for role assignments
  - Check constraint `ra_path_or_id` / `rra_path_or_id` — at least one of `resource_path` or non-empty `resource_id` must be present
  - GiST index `ix_ra_resource_path` / `ix_rra_resource_path` (partial, `where resource_path is not null`) — backs `_target <@ resource_path` ancestor walks
  - New partial unique indexes `uq_ra_user_flag_path` / `uq_ra_group_flag_path` (and `rra` equivalents) scoped to path-bearing rows; existing md5-based unique indexes now scoped to `where resource_path is null`
  - `helpers.path_to_ltree(text)` — default path sanitizer: splits on `/`, lowercases, replaces non-ltree chars with `_`, collapses underscores
- **Compositional match predicate** in check functions — a grant row matches the target if both the path component (`resource_path is null OR target_path <@ resource_path`) and the id component (`resource_id = '{}'::jsonb OR resource_id match`) are satisfied. Enables pure-id, pure-path, and hybrid grants to coexist uniformly.
- `test_resource_access_path` test suite (10 files, 35 assertions) — grant/inherit, deny-override, group grants, tenant isolation, composite coexistence, revoke cascade, role paths, invalid input, flags/grants queries, bulk filter
- **Worked example: `999-examples-icons.sql` + `gen_icons_inserts.py`** — loads the Material Design Icons filesystem (~27k paths) into a `demo.fs_item` table, registers two roles, creates 13 users with a mix of direct-flag, group-flag, user-role, group-role, hybrid, and deny grants spread across the tree, then runs single `has_resource_access` latency and 1000-candidate `filter_accessible_resources` bulk probes. Demonstrates the full check matrix at realistic scale.
- **`has_permissions` mirror pattern** — shown in the icons example: an app-side boolean column on the domain table kept in sync with `auth.resource_access` / `auth.resource_role_assignment` via triggers that filter on `root_type` and `resource_path`. Useful for UI badges ("lock icon") and admin queries ("find rows with custom ACL"). The flag reflects direct entries only; inheritance still goes through `has_resource_access`.

### Changed

- **`auth.assign_resource_access`, `deny_resource_access`, `revoke_resource_access`, `revoke_all_resource_access`** — added optional trailing `_resource_path ext.ltree default null` parameter. `_resource_id` gained default `'{}'::jsonb`. Callers pass either or both.
- **`auth.assign_resource_role`, `revoke_resource_role`, `revoke_all_resource_roles`** — same `_resource_path` addition.
- **`auth.has_resource_access`** — added `_resource_path` parameter; check uses compositional predicate across both constraints. Deny semantics unchanged: any ancestor-matching deny blocks.
- **`auth.filter_accessible_resources`** — now accepts either `_resource_ids jsonb[]` or `_resource_paths ext.ltree[]` (mutually exclusive). Returns matches as jsonb.
- **`auth.get_resource_access_flags`, `get_resource_access_matrix`, `get_resource_grants`** — added `_resource_path` parameter; flags and matrix walk ancestor paths, grants uses exact-path match.
- **`auth.get_user_accessible_resources`** — return signature grew a `__resource_path text` column so callers can tell which grants are path-based.
- **`unsecure.validate_resource_id`** — skips key_schema validation when `_resource_id` is null or `'{}'::jsonb` (path-only grants don't assert composite keys).
- **`auth.revoke_all_resource_access` / `revoke_all_resource_roles`** — path-cascade semantics: `resource_path <@ _resource_path` drops all descendant grants (parallel to the existing `resource_id @>` cascade for composite keys).

### Notes

- Changes landed in-place in the canonical migration files (034, 035, 043, 044) rather than as a separate migration — the project is still pre-release.
- `helpers.path_to_ltree(text)` lives in `004_create_helpers.sql`.
- Existing composite-key grants continue to work unchanged; path support is additive.
- Applications wanting path-based ACL can either: register a resource type with an empty `key_schema` and call grant functions with `_resource_path`, or use a non-empty `key_schema` and mix both dimensions on the same grant (hybrid).

## 2026-04-12

### Added

- **Resource roles** — named bundles of access flags scoped to a resource_type, replacing N-row flag grants with a single role assignment that expands to flags at check time
  - `const.resource_role` + `const.resource_role_flag` tables for role definitions
  - `auth.resource_role_assignment` (partitioned by root_type) for tenant-scoped role grants
  - Role CRUD: `create_resource_role`, `ensure_resource_roles`, `update_resource_role`, `delete_resource_role`, `ensure_resource_role_flags`, `get_resource_roles`, `get_resource_role_flags`
  - Role assignment: `assign_resource_role`, `revoke_resource_role`, `revoke_all_resource_roles`, `get_resource_role_assignments`
  - Role redefinition takes effect instantly — no cascade needed, roles expand at check time
  - Denies remain flag-level in `auth.resource_access` (roles are grant-only)
- **Translation `context` column** — `public.translation` now supports multiple translated values per object (e.g., `context='title'` and `context='description'` for the same entity)
- **`public.mv_translation`** — materialized view that pre-aggregates translations into one jsonb per object for single-index-probe reads. All read-path functions use the MV; write-path functions refresh it after mutations
- **Error codes**: 35007 (resource role not found), 35008 (role flag invalid for type), 35009 (role/type mismatch)
- **Event codes**: 18003-18005 (resource role created/updated/deleted), 18020-18021 (resource role assigned/revoked)
- **`auth.user_data` jsonb columns** — three new columns for extensible per-user configuration:
  - `settings jsonb` — app-level config (locale, timezone, notifications)
  - `preferences jsonb` — UI/UX preferences (theme, sidebar, default view)
  - `custom_data jsonb` — app-specific fields (employee_number, department)
- **`auth.update_user_data`** — partial-merge update function. Each jsonb param is shallow-merged (`||`) with existing value; null values remove keys via `jsonb_strip_nulls`. Self-update is free, cross-user requires `users.update_user_data` permission. Auto-creates the `user_data` row on first update.
- Example: `999-examples-organiogram.sql` — 30-node organization tree with 5 users and resource roles demo
- **665 tests across 35 suites** (81% auth function coverage, up from ~32%). New test suites:
  - `test_resource_roles` (8 files) — CRUD, assignment, has_resource_access with roles, deny override, role redefinition, tenant isolation, hierarchy cascade
  - `test_user_data` (13 tests) — auto-create, name coalesce, jsonb merge/remove, column independence, self-update, permission checks
  - `test_tokens` (15 tests) — create, validate, set_as_used, expiry, error cases
  - `test_api_keys` (19 tests) — create, update, delete, validate, secret rotation, permission assignment, search
  - `test_tenant_crud` (22 tests) — create, update, delete, search, get_tenant_users/groups, ownership
  - `test_permission_crud` (16 tests) — permission CRUD, perm_set CRUD, assign/unassign, copy_perm_set null title regression
  - `test_group_crud` (9 tests) — group CRUD, member/mapping CRUD, get_effective/assigned_group_permissions
  - `test_ownership` (15 tests) — tenant + group ownership CRUD, is_owner, has_owner
  - `test_permission_checks` (14 tests) — has_permission, has_permissions, assign_user_default_groups, delete_user_info, get_users_groups_and_permissions
  - `test_audit_and_user_ops` (10 tests) — create_user_event, audit trail, security events, password update, preferences, last_selected_tenant
  - `test_outbound_api_keys` (25 tests) — full CRUD, search, secret rotation
  - `test_group_types` (20 tests) — set_as_external/hybrid/internal, create_external_user_group, enable/disable/lock/unlock
  - `test_identity_and_providers` (14 tests) — enable/disable/verify identity, user lookups, provider reads

### Changed

- **Renamed `auth.grant_resource_access` → `auth.assign_resource_access`** for verb consistency with `assign_permission`, `assign_resource_role`, etc.
- **Updated check functions** to union role-derived access with direct flag grants:
  - `has_resource_access` — added user role and group role checks in the hierarchy walk
  - `filter_accessible_resources` — 4-way OR (direct user, user role, direct group, group role)
  - `get_resource_access_flags` — includes role-sourced flags with source `'role:<code>'`
  - `get_resource_access_matrix` — priority chain: direct > user_role > group > group_role
  - `get_resource_grants` — UNIONs role assignments expanded to individual flags
  - `get_user_accessible_resources` — includes role-derived resources
- **Removed inline `title`/`description` columns** from all const tables — display text now lives exclusively in `public.translation`:
  - `const.resource_type` (title, full_title, description)
  - `const.resource_access_flag` (title)
  - `const.resource_role` (title, description)
  - `const.event_category` (title)
  - `const.event_code` (title, description)
  - `const.mfa_type` (title)
  - `const.invitation_executor` (title)
  - `const.invitation_phase` (title)
  - `const.invitation_condition` (title, description)
  - `const.invitation_action_type` (title, description)
- All affected functions gain `_language_code text default 'en'` parameter
- `full_title` for resource_type precomputed into translations via `unsecure.update_resource_type_full_title_translations`
- Read functions use `coalesce(mv.values->>'title', <code>)` — missing translations fall back to the entity code
- Translation functions updated: `create_translation` (+context), `copy_translations` (context-aware), `get_group_translations` (reads from MV, returns nested jsonb), `search_translations` (+context filter)
- `get_event_message_template` changed from `language sql` to `language plpgsql` (deferred validation for file ordering)
- `unsecure.ensure_resource_access_partition` now creates both `resource_access` and `resource_role_assignment` partitions

### Fixed

- `auth.get_user_data` — missing `return query` and unqualified table reference (`user_data` → `auth.user_data`). Function was silently returning no rows.
- `unsecure.copy_perm_set` — used nullable `_new_title` instead of coalesced `__effective_title` for code generation, causing NULL code violation
- `triggers.notify_perm_set` — referenced dropped `OLD.title` column, changed to `OLD.code`
- `auth.get_api_key_permissions` — RETURNS TABLE had 8 columns but inner query returned 11
- `unsecure.get_effective_group_permissions` — referenced `ep.permission_title` from view that no longer has that column
- `unsecure.assign_user_default_groups` — ambiguous `user_group_id` in NOT-IN subquery, added alias qualification
- `auth.is_owner` / `auth.has_owner` — marked `IMMUTABLE` despite reading from table, changed to `STABLE`
- `auth.delete_owner` — `user_group_id = _user_group_id` never matches NULL rows, changed to `IS NOT DISTINCT FROM`
- `unsecure.delete_tenant` — was a bare `DELETE FROM auth.tenant` that failed on FK constraints; rewritten with explicit cleanup of all dependent data
- `auth.update_user_preferences` — returned `character varying` instead of `text`, causing structure mismatch
- System user (id=1) was not marked `is_system = true` in seed data
- Removed hardcoded `aad` provider from seed — apps register their own via `auth.ensure_provider`

## 2026-03-10

### Added

- `auth.get_user_assigned_groups` now returns `__tenant_id`, `__tenant_code`, `__tenant_title` columns for multi-tenant admin UI support
- `auth.search_user_groups` now returns `__tenant_id`, `__tenant_code`, `__tenant_title` columns for multi-tenant admin UI support
- `auth.get_user_permissions` now returns `__tenant_id`, `__tenant_code`, `__tenant_title` columns and supports cross-tenant queries via `_target_tenant_id` parameter (new permission: `users.get_all_permissions`)

### Changed

- **Unified search function signatures**: All 12 search/audit functions now use a single `_search_criteria jsonb` parameter instead of multiple domain-specific filter parameters. The standard signature is `(_user_id, _correlation_id, _search_criteria, _page, _page_size, _tenant_id, _target_tenant_id)` — 6-7 params regardless of domain complexity. Filter keys are passed as JSON properties (e.g. `'{"search_text": "foo", "is_active": true}'`). Functions refactored:
  - `auth.search_users` — criteria: `search_text`, `user_type_code`, `is_active`, `is_locked`
  - `auth.search_blacklist` — criteria: `search_text`, `reason`
  - `auth.search_user_group_mappings` — criteria: `search_text`, `provider_code`, `mapped_object_id`, `mapped_role`
  - `auth.search_user_groups` — criteria: `search_text`, `is_active`, `is_external`, `is_system`
  - `auth.search_permissions` — criteria: `search_text`, `is_assignable`, `parent_code`, `source`
  - `auth.search_perm_sets` — criteria: `search_text`, `is_assignable`, `is_system`, `source`
  - `auth.search_tenants` — criteria: `search_text`
  - `auth.search_api_keys` — criteria: `search_text`
  - `auth.search_outbound_api_keys` — criteria: `search_text`, `service_code`
  - `auth.search_user_events` — criteria: `event_type_code`, `target_user_id`, `request_context`, `correlation_id`, `from`, `to`
  - `auth.get_user_audit_trail` — criteria: `target_user_id`, `from`, `to`
  - `auth.get_security_events` — criteria: `from`, `to`

### Fixed

- `auth.search_user_events` — `_correlation_id` was used as both an auth tracing parameter and a WHERE filter, causing empty results when the app passed a real correlation_id. The filter is now a separate `correlation_id` key in `_search_criteria`.

## 2026-03-09

### Added

- `internal.resolve_cross_tenant_access()` — helper function that encapsulates the 3-branch cross-tenant permission check pattern (`_target_tenant_id` specified → admin-only with `read_all_*`; tenant 1 → `read_all_*` + see all; else → regular permission + own tenant). Replaces ~15 lines of boilerplate per function across 22 call sites in 7 files.
- `internal.resolve_user(_identifier text)` — resolves a user by bigint, uuid, or code to `user_id`. Raises error 33020 if not found.
- `internal.resolve_tenant(_identifier text)` — resolves a tenant by integer, uuid, or code to `tenant_id`. Raises error 34003 if not found.
- `internal.resolve_group(_identifier text, _tenant_id integer)` — resolves a group by integer or code (scoped to tenant) to `user_group_id`. Raises error 33021 if not found.
- Error functions: `error.raise_33020` (user not resolved), `error.raise_33021` (group not resolved), `error.raise_34003` (tenant not resolved).

### Changed

- Replaced cross-tenant if/elsif/else blocks in 22 functions with a single call to `internal.resolve_cross_tenant_access()`:
  - `020`: `search_users` (2)
  - `021`: `get_user_group_mappings`, `search_user_group_mappings`, `get_user_assigned_groups`, `search_user_groups` (4)
  - `022`: `get_perm_sets`, `search_perm_sets` (2)
  - `023`: `get_tenants`, `get_tenant_users`, `get_tenant_groups`, `get_tenant_members`, `search_tenants` (5)
  - `026`: `search_api_keys`, `get_outbound_api_key`, `get_outbound_api_key_by_id`, `get_outbound_api_key_secret`, `get_outbound_api_key_secret_by_id`, `search_outbound_api_keys` (6)
  - `028`: `search_user_events`, `get_user_audit_trail`, `get_security_events` (3)

### Renamed

- `auth.add_to_blacklist` → `auth.create_blacklist_user` — consistent create/delete naming
- `auth.remove_from_blacklist` → `auth.delete_blacklist_user` — consistent create/delete naming
- `auth.add_perm_set_permissions` → `auth.create_perm_set_permissions` (+ `unsecure.` counterpart)
- `auth.add_user_to_default_groups` → `auth.assign_user_default_groups` (+ `unsecure.` counterpart)

### Removed

- `users.search_all_blacklist` permission — blacklist data is app-wide (no `tenant_id` column), so cross-tenant access doesn't apply. `auth.search_blacklist` now uses a single `users.search_blacklist` permission check. Removed from System admin and Full admin permission sets.
- `_target_tenant_id` parameter from `auth.search_blacklist` — function no longer participates in cross-tenant pattern.

### Fixed

- `auth.create_blacklist_user` now prevents blacklisting system users (checks `is_system` by username and provider identity, raises error 33002).

## 2026-03-09

### Added

#### Tenant Isolation & Cross-Tenant Data Access

All `auth.*` search/get functions now enforce tenant-scoped data access with a consistent cross-tenant pattern:

- **`_tenant_id`** — caller's tenant, used for permission checking
- **`_target_tenant_id`** — optional, specifies which tenant's data to query (admin console only)

**Permission resolution:**

| Caller | `_target_tenant_id` | Permission | Data |
|--------|---------------------|------------|------|
| `_tenant_id = 1` | `null` | `read_all_*` | All tenants |
| `_tenant_id = 1` | `30` | `read_all_*` (checked against tenant 30) | Tenant 30 only |
| `_tenant_id ≠ 1` | `null` | `read_*` | Own tenant only |
| `_tenant_id ≠ 1` | any | Error 34002 | — |

**New `read_all_*` permissions (13 total):**
- `users.read_all_users`, `users.read_all_user_group_memberships`
- `groups.get_all_groups`, `groups.get_all_mappings`
- `permissions.get_all_perm_sets`, `permissions.read_all_perm_sets`
- `tenants.get_all_tenants`, `tenants.get_all_users`, `tenants.get_all_groups`, `tenants.read_all_tenants`
- `authentication.read_all_user_events`
- `api_keys.search_all`
- `invitations.get_all_invitations`

All `read_all_*` permissions are included in the **System admin** and **Full admin** permission sets.

**New error:**
- `34002` — Cross-tenant access requires admin tenant (tenant_id = 1)

**Functions updated (21 total across 10 files):**
- `020`: `search_users`
- `021`: `search_user_groups`, `get_user_assigned_groups`, `get_user_group_mappings`, **`search_user_group_mappings`** (new)
- `022`: `get_perm_sets`, `search_perm_sets`
- `023`: `get_tenants`, `get_tenant_users`, `get_tenant_groups`, `get_tenant_members`, `search_tenants`
- `026`: `search_api_keys`, `search_outbound_api_keys`, `get_outbound_api_key`, `get_outbound_api_key_by_id`, `get_outbound_api_key_secret`, `get_outbound_api_key_secret_by_id`
- `028`: `search_user_events`, `get_user_audit_trail`, `get_security_events`
- `042`: `get_invitations`

#### Tenant-Scoped Permission Checks

All `auth.*` functions that call `has_permission` now accept `_tenant_id integer default 1` and pass it through to the permission check. Previously, 69 out of 154 `has_permission` calls defaulted to tenant 1 regardless of caller context. This affects functions across 11 files (020–042).

### Changed

- `unsecure.get_perm_sets` and `unsecure.get_invitations` now accept `null` tenant_id (returns all tenants)
- Permission matrix documentation page added to docs site

## 2026-03-07

### Added

#### Invitation System

A generic invitation system that supports inviting users to tenants, groups, permission sets, individual permissions, and resource-access-controlled entities (projects, documents, etc.). Invitations carry ordered, typed actions that are executed when accepted — database actions run immediately, while backend/external actions are returned to the caller for async processing.

**New tables:**

| Table | Schema | Description |
|-------|--------|-------------|
| `const.invitation_status` | const | Invitation status codes (pending, accepted, rejected, revoked, expired, processing, completed, failed) |
| `const.invitation_action_status` | const | Action status codes (pending, processing, completed, failed, skipped) |
| `const.invitation_executor` | const | Executor types: `database`, `backend`, `external` |
| `const.invitation_phase` | const | Action phases: `on_create`, `on_accept`, `on_reject`, `on_expired` |
| `const.invitation_condition` | const | Pre-execution conditions: `always`, `user_not_in_tenant`, `user_not_in_group`, `user_has_no_perm_set`, `user_has_no_resource_access` |
| `const.invitation_action_type` | const | Registry of action types with executor binding and `payload_schema` (describes required fields and their sources for auto-population from invitation context) |
| `auth.invitation` | auth | Main invitation table with uuid, target_email, status, message, expires_at, template reference |
| `auth.invitation_action` | auth | 1:N ordered actions per invitation with phase_code, condition_code, sequence (ordering), is_required (failure handling), payload, result_data |
| `auth.invitation_template` | auth | Reusable named templates (tenant-scoped or global) |
| `auth.invitation_template_action` | auth | Template action definitions with phase_code, condition_code, payload_template |

**New functions:**

| Function | Layer | Description |
|----------|-------|-------------|
| `unsecure.create_invitation` | unsecure | Creates a new invitation |
| `unsecure.accept_invitation` | unsecure | Validates and accepts an invitation (pending → processing) |
| `unsecure.reject_invitation` | unsecure | Rejects an invitation, skips all actions |
| `unsecure.revoke_invitation` | unsecure | Revokes an invitation, skips all actions |
| `unsecure.complete_invitation_action` | unsecure | Marks an action as completed |
| `unsecure.fail_invitation_action` | unsecure | Marks an action as failed; if required, skips later sequences and fails invitation |
| `unsecure.check_invitation_completion` | unsecure | Helper: checks if all actions done, marks invitation completed |
| `unsecure.evaluate_invitation_condition` | unsecure | Evaluates a condition_code against current state (tenant membership, group membership, etc.) |
| `unsecure.resolve_action_payload` | unsecure | Resolves payload_schema for backend/external actions — auto-populates fields from invitation context based on `source` mappings |
| `unsecure.get_invitations` | unsecure | Lists invitations with filtering and action counts |
| `unsecure.get_invitation_actions` | unsecure | Lists actions for an invitation |
| `unsecure.create_invitation_from_template` | unsecure | Creates invitation from a template with payload overrides |
| `unsecure.execute_database_action` | unsecure | Executes a single database action (add_tenant_user, add_group_member, etc.) |
| `unsecure.process_invitation_actions` | unsecure | Processes all actions: executes database ones, returns backend/external as pending |
| `unsecure.create_invitation_template` | unsecure | Creates a template with actions |
| `unsecure.update_invitation_template` | unsecure | Updates template metadata |
| `unsecure.delete_invitation_template` | unsecure | Deletes a template (cascades actions) |
| `auth.create_invitation` | auth | Permission-checked invitation creation with inline action array |
| `auth.accept_invitation` | auth | Permission-checked accept + process actions |
| `auth.reject_invitation` | auth | Permission-checked reject |
| `auth.revoke_invitation` | auth | Permission-checked revoke |
| `auth.get_invitations` | auth | Permission-checked listing |
| `auth.get_invitation_actions` | auth | Permission-checked action listing |
| `auth.create_invitation_from_template` | auth | Permission-checked template-based creation |
| `auth.create_invitation_template` | auth | Permission-checked template creation |
| `auth.update_invitation_template` | auth | Permission-checked template update |
| `auth.delete_invitation_template` | auth | Permission-checked template deletion |

**New permissions:** `invitations` (parent), `invitations.create_invitation`, `invitations.accept_invitation`, `invitations.reject_invitation`, `invitations.revoke_invitation`, `invitations.get_invitations`, `invitations.manage_templates`

**New event category:** `invitation_event` (22001-22999), `invitation_error` (39001-39999)

**New event codes:** 22001-22012 (invitation lifecycle + template CRUD), 39001-39006 (invitation errors)

**New error functions:** `error.raise_39001` through `error.raise_39006`

**Execution model:**
- Each action has a `phase_code` determining **when** it fires: `on_create` (immediate), `on_accept`, `on_reject`, `on_expired`
- Each action has a `condition_code` evaluated at execution time: `always`, `user_not_in_tenant`, `user_not_in_group`, `user_has_no_perm_set`, `user_has_no_resource_access` — if condition is false, action is skipped
- Actions are grouped by `sequence` (integer) and processed in order within their phase
- `is_required = true`: failure stops processing of subsequent sequence groups and fails the invitation
- `is_required = false`: failure is recorded but processing continues
- `executor_code = 'database'`: executed immediately during phase processing
- `executor_code = 'backend'`/`'external'`: returned to caller as pending for async handling
- `auth.create_invitation` / `auth.create_invitation_from_template` process `on_create` actions immediately and return pending backend/external ones
- `auth.reject_invitation` processes `on_reject` phase actions (e.g. notify inviter of rejection)

**Files:** `041_tables_invitation.sql`, `042_functions_invitation.sql`

---

## 2026-03-07

### Added

#### Identity Verification (`is_verified`)

New `is_verified` column on `auth.user_identity` to track whether an identity (e.g., email) has been verified. Defaults to `false`. OAuth identities created via `auth.ensure_user_from_provider` are automatically marked `is_verified := true` since the external provider already verified the identity.

**Schema change:**
- `auth.user_identity` — new column `is_verified boolean default false not null`

**New functions:**

| Function | Layer | Description |
|----------|-------|-------------|
| `unsecure.verify_user_identity(_updated_by, _user_id, _correlation_id, _target_user_id, _provider_code)` | unsecure | Sets `is_verified = true` on the identity. Validates user exists (52001) and identity exists (33009). |
| `auth.verify_user_identity(_updated_by, _user_id, _correlation_id, _target_user_id, _provider_code, _request_context)` | auth | Permission-checked wrapper. Logs `identity_verified` user event. Permission: `users.verify_user_identity`. |

**New permission:** `users.verify_user_identity`

**New event code:** 10035 `identity_verified` — logged when an identity is marked as verified.

**Updated functions:**
- `unsecure.create_user_identity` — new optional parameter `_is_verified boolean default false`
- `auth.ensure_user_from_provider` — passes `_is_verified := true` (OAuth identities are pre-verified)
- `auth.register_user` — keeps default `_is_verified := false` (email needs verification)
- `auth.get_user_identity` / `auth.get_user_identity_by_email` — now return `__is_verified`

#### MFA Permissions Auto-Assignment

New MFA permissions created in migrations 036/039 are now automatically added to all existing assignable permission sets, so users don't lose MFA access after migration.

**Changes:**
- `036_tables_mfa.sql` — after creating MFA permissions, loops through all assignable `perm_set` entries and adds the 6 core MFA permissions
- `039_mfa_policy.sql` — same pattern for the 4 MFA policy permissions (`mfa.reset_mfa`, `mfa.mfa_policy.*`)

### Fixed

#### Test Fixes

- `test_user_blacklist/000_setup.sql` — removed `updated_by` from `tenant_user` and `permission_assignment` inserts (columns don't exist on those tables), fixed `clear_permission_cache` call signature
- `test_auto_lockout/006-008` — fixed test ordering issues: unlock user and clear failure events between lockout tests and verify_user_by_email tests; removed event checks from `BEGIN...EXCEPTION` blocks (PostgreSQL rolls back side effects on exception)

## 2026-03-05

### Added

#### Single-Call Email/Password Verification

New function `auth.verify_user_by_email` that combines email lookup, status validation, password hash comparison, failure recording, and auto-lockout into a single DB call. Symmetric with `auth.verify_mfa_challenge` which already handles everything in one call.

**New function:**

| Function | Layer | Description |
|----------|-------|-------------|
| `auth.verify_user_by_email(_user_id, _correlation_id, _email, _password_hash, _request_context)` | auth | Looks up user by email, validates status, compares password hash. Returns user data on success. On mismatch: logs `user_login_failed` (reason: `wrong_password`), triggers auto-lockout check. Raises 33004 if auto-locked, 52103 otherwise. Permission: `authentication.get_data`. |

**Key difference from `get_user_by_email_for_authentication`:** Only logs `user_logged_in` after a confirmed hash match (cleaner audit trail). Does not return `password_hash`/`password_salt` since the DB does the comparison. The existing two-step flow (`get_user_by_email_for_authentication` + `record_login_failure`) remains unchanged for apps that prefer it.

## 2026-03-04

### Changed

#### MFA Failures Count Toward Auto-Lockout

Failed MFA challenges now count toward the auto-lockout threshold alongside wrong password attempts. Previously, invalid TOTP codes only raised 38004 with no lockout consequence, making 6-digit TOTP codes a brute-force vector.

**Changes:**

- `unsecure.check_and_auto_lock_user` — now counts both `user_login_failed` and `mfa_challenge_failed` events within the lockout window
- `auth.verify_mfa_challenge` — on failure (Case 3), logs `mfa_challenge_failed` event and calls `check_and_auto_lock_user`. Raises 33004 (user locked) if threshold exceeded, otherwise raises 38004 (MFA challenge failed)

## 2026-03-04

### Added

#### MFA Recovery Code Reset

New function to regenerate recovery codes for a confirmed MFA enrollment, without requiring disable + re-enroll. Addresses the scenario where a user has lost their recovery codes but still has their TOTP authenticator.

**New function:**

| Function | Layer | Description |
|----------|-------|-------------|
| `auth.reset_mfa(_updated_by, _user_id, _correlation_id, _target_user_id, _mfa_type_code, _request_context)` | auth | Generates 10 new recovery codes, replaces existing hashes. Returns plaintext codes (shown once). Validates enrollment exists (38002) and is confirmed (38003). Permission: `mfa.reset_mfa`. |

**New permission:** `mfa.reset_mfa`

**New event code:** 10097 `mfa_recovery_reset` — logged when recovery codes are regenerated.

#### MFA Policy (Enforcement Rules)

Scope-based rules table (`auth.mfa_policy`) to signal whether MFA is required for specific users, groups, tenants, or globally. Resolution: most-specific scope wins (user > group > tenant > global). Without any rules, MFA remains optional (default: `false`).

**New table:** `auth.mfa_policy` — columns: `mfa_policy_id` (identity PK), `tenant_id` (FK → tenant, nullable), `user_group_id` (FK → user_group, nullable), `user_id` (FK → user_info, nullable), `mfa_required boolean`, audit columns. Unique index on `coalesce(tenant_id, -1), coalesce(user_group_id, -1), coalesce(user_id, -1)` for null-safe deduplication.

**New functions:**

| Function | Layer | Description |
|----------|-------|-------------|
| `auth.create_mfa_policy(...)` | auth | Creates an MFA enforcement rule. Scope determined by which params are null (all null = global). Permission: `mfa.mfa_policy.create_mfa_policy`. |
| `auth.delete_mfa_policy(...)` | auth | Deletes a policy rule. Validates existence (38007). Permission: `mfa.mfa_policy.delete_mfa_policy`. |
| `auth.get_mfa_policies(...)` | auth | Lists policies filtered by optional scope params. Permission: `mfa.mfa_policy.get_mfa_policies`. |
| `unsecure.is_mfa_required(_target_user_id, _tenant_id)` | unsecure | Resolves whether MFA is required. No permission check (login flow). Resolution: user-level → group-level (`bool_or` via `get_cached_group_ids`) → tenant-level → global → `false`. |
| `auth.is_mfa_required(_user_id, _correlation_id, _target_user_id, _tenant_id)` | auth | Permission-checked wrapper (reuses `mfa.get_mfa_status` permission). |

**New permissions** (hierarchy under `mfa.mfa_policy`):
- `mfa.mfa_policy` (parent, not assignable)
- `mfa.mfa_policy.create_mfa_policy`, `mfa.mfa_policy.delete_mfa_policy`, `mfa.mfa_policy.get_mfa_policies`

**New event codes:**

| Code | Event | Description |
|------|-------|-------------|
| 10095 | mfa_policy_created | MFA policy rule was created |
| 10096 | mfa_policy_deleted | MFA policy rule was deleted |

**New error code:**

| Code | Function | Description |
|------|----------|-------------|
| 38007 | error.raise_38007 | MFA policy does not exist |

**Tests:** `tests/test_mfa_policy/` — 10 test files covering reset MFA (happy path + error cases 38002/38003), global/tenant/group/user policy creation with scope resolution cascade, policy deletion with fallback verification, get_mfa_policies filtering, error cases (38007 not found, unique violation on duplicate scope).

**Files:** `039_mfa_policy.sql`, `040_functions_mfa_policy.sql`

## 2026-03-04

### Added

#### Auto-Lockout on Repeated Login Failures

Automatic account lockout after too many failed login attempts within a configurable time window. Previously, locking was manual-only via `auth.lock_user()`.

**New functions:**

| Function | Layer | Description |
|----------|-------|-------------|
| `unsecure.check_and_auto_lock_user(_updated_by, _correlation_id, _target_user_id, _request_context)` | unsecure | Counts recent `user_login_failed` events within the configured window. If threshold exceeded: sets `is_locked=true`, clears permission cache, logs `user_auto_locked` event. Returns true if locked, false otherwise. Skips if user already locked (no duplicate events). |
| `auth.record_login_failure(_user_id, _correlation_id, _target_user_id, _email, _request_context)` | auth | Called by app after password hash mismatch (DB never sees raw passwords). Logs `user_login_failed` event with reason `wrong_password`, then calls `check_and_auto_lock_user()`. Raises 33004 (user locked) if auto-locked, otherwise raises 52103 (invalid credentials). Requires `authentication.get_data` permission. |

**New system parameters** (`const.sys_param`):

| group_code | code | default | description |
|------------|------|---------|-------------|
| `login_lockout` | `max_failed_attempts` | `5` | Number of failures before auto-lock |
| `login_lockout` | `window_minutes` | `15` | Time window in minutes for counting failures |

**New event code:** 10083 `user_auto_locked` — logged when auto-lockout triggers.

**Login flow (app layer):**
1. App calls `auth.get_user_by_email_for_authentication(email)` → gets user + password hash
2. App verifies password hash
3. If wrong: app calls `auth.record_login_failure()` → DB counts failures, maybe auto-locks
4. If correct + MFA enabled: proceed to MFA challenge flow

**Tests:** `tests/test_auto_lockout/` — 5 tests covering sys_param verification, single failure (no lock), threshold triggers lock + event, no duplicate events on already-locked user, window expiry (old failures not counted).

**Files:** `036_tables_mfa.sql`, `037_functions_auto_lockout.sql`

#### Multi-Factor Authentication (TOTP)

Complete MFA implementation with two-step enrollment (enroll → confirm), TOTP verification, and one-time recovery codes. The DB stores app-encrypted TOTP secrets and SHA-256 hashed recovery codes — the DB never sees raw TOTP secrets or codes.

**New tables:**

| Table | Description |
|-------|-------------|
| `const.mfa_type` | MFA type lookup (currently `totp` only). Columns: `code` (PK), `title`, `is_active`. |
| `auth.user_mfa` | User MFA enrollment. Columns: `user_mfa_id` (identity PK), `user_id` (FK → user_info, cascade), `mfa_type_code` (FK → mfa_type), `secret_encrypted`, `is_enabled`, `is_confirmed`, `recovery_codes text[]` (SHA-256 hashes), `enrolled_at`, `confirmed_at`, audit columns. Unique on `(user_id, mfa_type_code)`. |

**New extension:** `pgcrypto` (schema `ext`) — used for `digest()` to hash recovery codes.

**New token state:** `'invalid'` added to `const.token_state` — used for invalidating previous MFA tokens.

**New functions:**

| Function | Layer | Description |
|----------|-------|-------------|
| `auth.enroll_mfa(...)` | auth | Initiates TOTP enrollment. App provides encrypted secret. Generates 10 recovery codes (returned plaintext once, stored as SHA-256 hashes). Rejects if already confirmed (38001), replaces pending enrollments. Permission: `mfa.enroll_mfa`. |
| `auth.confirm_mfa_enrollment(...)` | auth | Confirms enrollment. App verifies TOTP code externally, passes `_code_is_valid boolean`. Sets `is_enabled=true, is_confirmed=true`. Permission: `mfa.confirm_mfa_enrollment`. |
| `auth.disable_mfa(...)` | auth | Deletes MFA enrollment record. Logs `mfa_disabled` event. Permission: `mfa.disable_mfa`. |
| `auth.get_mfa_status(...)` | auth | Returns enrollment state + `recovery_codes_remaining`. Permission: `mfa.get_mfa_status`. |
| `auth.create_mfa_challenge(...)` | auth | Creates time-limited token (type=`mfa`, channel=`app`, 300s default). Invalidates previous valid MFA tokens. Validates MFA is enrolled + confirmed + enabled. Permission: `mfa.create_mfa_challenge`. |
| `auth.verify_mfa_challenge(...)` | auth | Three-way verification: (1) `_code_is_valid=true` → TOTP passed, (2) `_code_is_valid=false` + `_recovery_code` → hash-match against stored codes (consumed on use), (3) neither → token marked failed + error 38004. Permission: `mfa.verify_mfa_challenge`. |

**New permissions** (hierarchy under `mfa`):
- `mfa` (parent, not assignable)
- `mfa.enroll_mfa`, `mfa.confirm_mfa_enrollment`, `mfa.disable_mfa`, `mfa.get_mfa_status`, `mfa.create_mfa_challenge`, `mfa.verify_mfa_challenge`

**New event codes:**

| Code | Event | Description |
|------|-------|-------------|
| 10090 | mfa_enrolled | MFA enrollment was initiated |
| 10091 | mfa_enrollment_confirmed | MFA enrollment was confirmed with a valid code |
| 10092 | mfa_challenge_created | MFA challenge token was created |
| 10093 | mfa_challenge_passed | MFA challenge was successfully verified |
| 10094 | mfa_recovery_used | MFA recovery code was used to pass challenge |

**New error codes** (category `mfa_error`, range 38001-38999):

| Code | Function | Description |
|------|----------|-------------|
| 38001 | error.raise_38001 | MFA is already enrolled and confirmed for this type |
| 38002 | error.raise_38002 | MFA is not enrolled for this type |
| 38003 | error.raise_38003 | MFA enrollment is not confirmed |
| 38004 | error.raise_38004 | The provided MFA code is not valid |
| 38005 | error.raise_38005 | MFA verification is required |
| 38006 | error.raise_38006 | MFA type does not exist or is inactive |

**Tests:** `tests/test_mfa/` — 8 test files covering enrollment (recovery codes, pending state), re-enrollment blocking (38001), confirmation (valid + invalid code), status query, challenge + TOTP verification, recovery code verification (count decrement), disable (record deletion), error cases (non-existent token, invalid code, non-enrolled user, invalid MFA type).

**Files:** `036_tables_mfa.sql`, `038_functions_mfa.sql`

## 2026-03-02

### Added

#### User Blacklist for Deleted Users

New `auth.user_blacklist` table and supporting functions to prevent re-creation of deleted or banned users. Blocks re-registration by username (email/direct) and re-authentication by provider identity (OAuth/SAML). Supports both automatic blacklisting on deletion and manual blacklisting by admins.

**New table:** `auth.user_blacklist` — stores blacklisted usernames, provider UIDs/OIDs, original user_id for audit trail, reason, and admin notes. Constraint ensures at least one identifier (username, provider_uid, or provider_oid) is present.

**New functions:**

| Function | Layer | Description |
|----------|-------|-------------|
| `unsecure.check_user_blacklist(_username, _provider_code, _provider_uid, _provider_oid)` | unsecure | Core check — returns true if any identifier matches a blacklist entry |
| `unsecure.blacklist_user(...)` | unsecure | Inserts a single blacklist entry with journal event 10080 |
| `unsecure.blacklist_user_identities(_target_user_id, _reason)` | unsecure | Bulk: reads user_info + all user_identity rows, blacklists each. Must be called before deletion. |
| `auth.create_blacklist_user(...)` | auth | Permission-checked (`users.manage_blacklist`). Manual blacklisting with reason and notes. Prevents blacklisting system users. |
| `auth.delete_blacklist_user(_blacklist_id)` | auth | Permission-checked (`users.manage_blacklist`). Deletes entry, journals event 10081. |
| `auth.search_blacklist(_search_text, _reason, _page, _page_size)` | auth | Permission-checked (`users.search_blacklist`). Paginated search across username, provider_uid, provider_oid, notes. |
| `auth.is_blacklisted(...)` | auth | Public wrapper around `unsecure.check_user_blacklist`. No permission check (used in creation paths). |

**New permissions:** `users.manage_blacklist`, `users.search_blacklist`

**New event codes:** 10080 (user_blacklisted), 10081 (user_unblacklisted), 10082 (user_creation_blocked)

**New error codes:** 33018 (err_user_blacklisted), 33019 (err_identity_blacklisted). Legacy aliases: `error.raise_52115` → 33018, `error.raise_52116` → 33019.

**Blacklist checks added to existing functions:**

| Function | Check | Blocks |
|----------|-------|--------|
| `unsecure.create_user_info()` | Username blacklist | Email/direct registration |
| `unsecure.create_service_user_info()` | Username blacklist | Service user creation |
| `unsecure.create_user_identity()` | Provider uid/oid blacklist | Defense-in-depth for any identity creation path |
| `auth.ensure_user_from_provider()` | Provider uid/oid blacklist (before user creation) | OAuth/SAML re-authentication |

**Auto-blacklist on delete:** `unsecure.delete_user_by_id()` gains `_blacklist boolean default false` parameter. When true, calls `blacklist_user_identities()` before the DELETE (while FK data still exists). Function converted from `language sql` to `language plpgsql` to support this.

**Tests:** `tests/test_user_blacklist/` — 21 tests covering manual blacklisting, creation blocking (username + provider identity), auto-blacklist on delete, unblacklist + re-creation, search/pagination, edge cases (duplicates, service users, case-insensitive matching, default no-blacklist on delete).

**Files:** `013_tables_auth.sql`, `016_functions_error.sql`, `019_functions_unsecure.sql`, `020_functions_auth_user.sql`, `022_functions_auth_permission.sql`, `029_seed_data.sql`

### Fixed

#### `auth.delete_user_info()` — was deleting user groups instead of users

The function body was a copy-paste from `auth.delete_user_group` — it referenced `auth.user_group`, `_user_group_id`, and journaled event 13003 (group_deleted). Fixed to correctly reference `auth.user_info`, `_target_user_id`, use proper error checks (33001 user not found, 33002 user is system), call `unsecure.delete_user_by_id()`, and journal event 10003 (user_deleted). Also added `_blacklist boolean default false` parameter for the new blacklist feature.

## 2026-03-02

### Added

#### Bulk Ensure Functions for App Bootstrapping

Four new `auth.ensure_*` functions for idempotent bulk creation of permissions, permission sets, user groups, and group mappings. Designed for application startup — call them every time the app boots and they create only what's missing, skip what already exists, and optionally remove what's no longer defined.

| Function | Description |
|----------|-------------|
| `auth.ensure_permissions(_created_by, _user_id, _correlation_id, _permissions jsonb, _source, _is_final_state)` | Create/sync hierarchical permissions from JSONB array. Processes parents before children. |
| `auth.ensure_perm_sets(_created_by, _user_id, _correlation_id, _perm_sets jsonb, _source, _tenant_id, _is_final_state)` | Create/sync permission sets with their permissions. Adds missing permissions to existing sets. |
| `auth.ensure_user_groups(_created_by, _user_id, _correlation_id, _user_groups jsonb, _tenant_id, _source, _is_final_state)` | Create/sync user groups. Always sets `is_system=false`. |
| `auth.ensure_user_group_mappings(_created_by, _user_id, _correlation_id, _mappings jsonb, _tenant_id, _is_final_state)` | Create/sync group mappings. Supports both `user_group_id` and `user_group_title` for group resolution. |

All functions return the full set of processed entities (existing + newly created), not just the new ones.

**Example — app bootstrap:**
```sql
-- Define permissions (idempotent — safe to call every startup)
select * from auth.ensure_permissions('app', 1, null, '[
    {"title": "Documents", "is_assignable": false},
    {"title": "Read documents", "parent_code": "documents"},
    {"title": "Write documents", "parent_code": "documents"}
]', 'my_app');

-- Define permission sets
select * from auth.ensure_perm_sets('app', 1, null, '[
    {"title": "Document Viewer", "permissions": ["documents.read_documents"]},
    {"title": "Document Editor", "permissions": ["documents.read_documents", "documents.write_documents"]}
]', 'my_app');

-- Define groups
select * from auth.ensure_user_groups('app', 1, null, '[
    {"title": "Document Editors"},
    {"title": "Document Viewers", "is_external": true}
]', 1, 'my_app');
```

**Files:** `022_functions_auth_permission.sql`, `021_functions_auth_group.sql`

**Tests:** `tests/test_ensure_functions/` — 26 tests covering creation, idempotency, hierarchy, flags, mixed existing+new, return sets, error handling.

#### `_is_final_state` — Declarative State Sync for Ensure Functions

New `_is_final_state boolean default false` parameter on all 4 ensure functions. When `true`, the input represents the **complete desired state** — items not in the input are removed (scoped by `_source` to prevent cross-module interference).

**Scoping rules:**
- `_source` is **required** when `_is_final_state = true` (raises exception if null)
- Only items matching the same `_source` (+ `_tenant_id` where applicable) are candidates for removal
- Items with a different source or null source are never touched
- For `ensure_user_group_mappings`: scoped by `(user_group_id, provider_code)` pairs in the input — no `_source` needed

**What each function removes when `_is_final_state = true`:**

| Function | Removes |
|----------|---------|
| `ensure_permissions` | Permissions with same source not in input. Deepest-first (children before parents). Cleans up `perm_set_perm` and `permission_assignment` rows. Updates `has_children` flags. |
| `ensure_perm_sets` | **Within each set:** removes permissions not in that set's `permissions[]` array. **Whole sets:** removes perm sets with same source+tenant not in input. Cleans up `permission_assignment` rows, invalidates affected users' permission cache. |
| `ensure_user_groups` | Non-system groups with same source+tenant not in input. Cleans up `user_group_mapping` and `permission_assignment` rows. `trg_cache_user_group_before_delete` trigger handles cache invalidation. |
| `ensure_user_group_mappings` | For each `(group, provider)` combo in input, removes mappings not in the input set. Invalidates affected users' permission cache. |

**Example — remove "Write documents" permission on next deploy:**
```sql
-- Only list what should exist — "Write documents" will be removed
select * from auth.ensure_permissions('app', 1, null, '[
    {"title": "Documents", "is_assignable": false},
    {"title": "Read documents", "parent_code": "documents"}
]', 'my_app', _is_final_state := true);
```

All removals are journaled (events `12003` permission_deleted, `12022` perm_set_deleted, `13003` group_deleted, `13021` group_mapping_deleted).

**Additional permission checks:** `permissions.delete_permission` (ensure_permissions), `permissions.delete_permission_set` (ensure_perm_sets), `groups.delete_group` (ensure_user_groups), `groups.delete_mapping` (ensure_user_group_mappings).

**Tests:** 19 additional tests (27–45) covering null source error, default-no-remove, same-source removal, different-source safety, reference cleanup, within-set permission sync, (group,provider) scoping, role-based mappings.

#### `source` Column on `auth.user_group`

New `source text default null` column on `auth.user_group` table, matching the existing pattern on `auth.permission` and `auth.perm_set`. Used as the deletion boundary for `_is_final_state` scoping.

- `013_tables_auth.sql` — column added after `nrm_search_data`
- `017_functions_triggers.sql` — `source` included in search value calculation
- `019_functions_unsecure.sql` — `_source` parameter added to `unsecure.create_user_group`
- `021_functions_auth_group.sql` — `_source` parameter added to `auth.create_user_group`

## 2026-03-01

### Changed

#### Event ID reassignment — resolve collisions between modules

Language/translation events collided with maintenance and resource access events (both used ranges 17001-17999, 18001-18999, 35001-35999). Since `029_seed_data.sql` runs before `030_tables_language.sql`, the `ON CONFLICT DO NOTHING` silently skipped language/translation event inserts.

Reassigned to free ranges:

| Module | Old Range | New Range |
|--------|-----------|-----------|
| Language Events | 17001-17999 | 20001-20999 |
| Translation Events | 18001-18999 | 21001-21999 |
| Language/Translation Errors | 35001-35999 | 37001-37999 |

Error functions renamed: `error.raise_35001` → `error.raise_37001`, `error.raise_35002` → `error.raise_37002`.

Files updated: `030_tables_language.sql`, `031_functions_language.sql`, `032_functions_translation.sql`, `tests/test_language_translation/001_tables_and_seed_data.sql`, `tests/test_language_translation/006_constraints_journal_errors.sql`.

#### Column rename — `ua_*` → `nrm_*`

Renamed all `ua_` prefixed columns to `nrm_` (normalized) for consistency:
- `auth.user_info.ua_username` → `nrm_username`
- `public.translation.ua_search_data` → `nrm_search_data`
- Index `ix_translation_ua_search` → `ix_translation_nrm_search`

#### `unsecure.create_perm_set_as_system` — bypass `is_assignable` check

Converted from a thin SQL wrapper (that delegated to `unsecure.create_perm_set`) to a standalone plpgsql function that inserts directly, bypassing the `is_assignable` check on permissions. This allows system perm sets like `system_admin` to include non-assignable permissions (e.g., `resources`) without making them permanently assignable.

#### Makefile — all targets now use debee

Replaced `./tests/run-tests.sh` and `./exec-sql.sh` references with `debee.ps1` calls. Added `FILTER=` support to `make test`.

### Fixed

- `unsecure.recalculate_user_permissions` — added `drop table if exists` before creating temp table `__temp_users_groups_permissions` to prevent failure when called twice in the same transaction
- Resource access test suite — fixed column names, type mismatches, missing FK cleanup, and missing perm set creation for non-default tenants

## 2026-02-28

### Added

#### Resource Access (ACL) System

Resource-level authorization layered on top of RBAC. While RBAC controls what actions a user can perform globally, the ACL system controls which specific resources they can act on.

**Tables** (`034_tables_resource_access.sql`):
- `const.resource_type` — registry of valid resource types (e.g. `folder`, `document`)
- `const.resource_access_flag` — registry of access flags (`read`, `write`, `delete`, `share`); extensible with custom flags
- `auth.resource_access` — core ACL table, list-partitioned by `resource_type`. One row = one flag for one user/group on one resource. Supports both grants (`is_deny=false`) and explicit denies (`is_deny=true`)

**Functions** (`035_functions_resource_access.sql`):

| Function | Purpose |
|----------|---------|
| `auth.has_resource_access()` | Check if user has a flag on a resource (deny-overrides algorithm) |
| `auth.filter_accessible_resources()` | Bulk filter — returns subset of resource IDs user can access |
| `auth.get_resource_access_flags()` | Returns all effective flags + source (direct/group name) |
| `auth.assign_resource_access()` | Grant flags to user or group (idempotent upsert) |
| `auth.deny_resource_access()` | Explicit deny on user (overrides all group grants) |
| `auth.revoke_resource_access()` | Revoke specific flags or all flags |
| `auth.revoke_all_resource_access()` | Remove all ACL rows for a resource (cleanup on delete) |
| `auth.get_resource_grants()` | List all grants/denies on a resource |
| `auth.get_user_accessible_resources()` | List resources a user can access |
| `auth.create_resource_type()` | Register new resource type + auto-create partition |
| `unsecure.validate_resource_type()` | Validate resource type exists and is active |
| `unsecure.validate_access_flags()` | Validate all flags in array exist |
| `unsecure.ensure_resource_access_partition()` | Create partition for resource type if missing |

**Access check algorithm** (priority order):
1. System user (id=1) — always allowed
2. Tenant owner — always allowed
3. User-level deny — blocked, overrides everything
4. User-level grant — allowed
5. Group-level grant (via active group membership) — allowed
6. No matching row — denied

**Deny model**: User-level only. Cannot deny groups. Per-flag granularity. Explicit denies override all group grants for that user.

**RBAC permissions** (`022_functions_auth_permission.sql`):
- New parent: `Resources` (not assignable)
- Children: `resources.create_resource_type`, `resources.grant_access`, `resources.deny_access`, `resources.revoke_access`, `resources.update_access`, `resources.get_grants`
- New perm set: "Resource manager" (resources + journal read)
- Updated perm sets: "System admin" and "Full admin" now include `resources`

**Error codes** (`016_functions_error.sql`):
- `35001` — User has no access to resource
- `35002` — Neither user_id nor user_group_id provided
- `35003` — Resource type not found or inactive
- `35004` — Access flag not found

**Event codes** (`029_seed_data.sql`):
- `18001` resource_type_created, `18010` resource_access_granted, `18011` resource_access_revoked, `18012` resource_access_denied, `18013` resource_access_bulk_revoked

**Test suite** (`tests/test_resource_access/`):
- 8 test files covering grant/revoke, has_resource_access, deny-overrides, bulk filter, effective flags/grants, tenant isolation, cascade deletes
- Transaction isolation mode

#### Provider Capability Flags

New columns on `auth.provider` to control group mapping and sync behavior per provider (`013_tables_auth.sql`, `024_functions_auth_provider.sql`):

- `allows_group_mapping` (boolean, default false) — whether provider supports group mapping
- `allows_group_sync` (boolean, default false) — whether provider supports group sync
- Constraint: `allows_group_sync` requires `allows_group_mapping`
- New validation functions: `auth.validate_provider_allows_group_mapping()`, `auth.validate_provider_allows_group_sync()`
- `auth.create_provider()`, `auth.update_provider()`, `auth.ensure_provider()` updated with new parameters
- `auth.create_user_group_mapping()` now validates provider allows group mapping
- `auth.sync_user_group_members()` now validates provider allows group sync
- `unsecure.resolve_user_groups_from_provider()` skips mapping resolution when provider doesn't allow it
- New error codes: `33016` (provider does not allow group mapping), `33017` (provider does not allow group sync)

### Changed

- Reset `auth.tenant` and `auth.user_group` identity sequences to start at 1000 (IDs 1-999 reserved for system use) (`029_seed_data.sql`)

## 2026-02-28

### Changed

#### Debee Integration — execSql and runTests

Replaced standalone `exec-sql.sh` and `tests/run-tests.sh` with debee's built-in `execSql` and `runTests` operations. All three debee implementations (PowerShell, Bash, Python) now handle SQL execution and test running natively.

- **`execSql`** — Execute SQL files, inline commands, or open interactive psql sessions directly through debee
- **`runTests`** — Full test framework with suite directories, `test.json` manifests, isolation modes, shared setup scripts, and `--test-filter` filtering

#### Test Suite Restructure

Converted all 11 flat test files (`test_*.sql`) into suite directories following the debee test framework conventions:

| Suite | Tests | Description |
|-------|-------|-------------|
| `test_connection/` | 1 | Basic database connectivity |
| `test_connectivity/` | 3 | Connectivity with temp table operations |
| `test_provider_crud/` | 19 | Provider CRUD, journaling, capability flags |
| `test_registration_login_events/` | 21 | Registration, login events, request_context |
| `test_disabled_locked_users/` | 9 | Disabled/locked user blocking, cache clearing |
| `test_permission_cache_invalidation/` | 12 | Cache invalidation (soft/hard), owner functions |
| `test_short_code/` | 16 | Hierarchical permission short codes |
| `test_correlation_id/` | 5 | Correlation ID flow and search filtering |
| `test_event_code_management/` | 20 | Event category/code/message CRUD, system protection |
| `test_language_translation/` | 25 | Language CRUD, translations, copy/overwrite |
| `test_group_members_and_delete_tenant/` | 5 | Group member queries, tenant deletion |
| `test_auth_group_member_tenant/` | 11 | Auth-layer group/tenant with permission checks |
| `test_search_functions/` | 14 | All search functions: pagination, filtering |

Each suite directory contains:
- `test.json` — Manifest with name, description, `isolation: "transaction"`
- `000_setup.sql` — Search path and test data setup
- `001_*.sql` – `008_*.sql` — Grouped test files
- `900_cleanup.sql` — Cleanup (transaction rollback handles data automatically)

Global test ordering controlled by `tests/tests.json`.

### Removed

- `exec-sql.sh` — Replaced by `debee execSql`
- `tests/run-tests.sh` — Replaced by `debee runTests`
- All flat `tests/test_*.sql` files — Replaced by suite directories

## 2026-02-26

### Added

#### Storage Mode Switch — Offload Journal & User Events via pg_notify

Journal messages and user events can now be routed to an external system (e.g., ClickHouse) via PostgreSQL's LISTEN/NOTIFY instead of (or in addition to) being stored locally. This is controlled independently for each subsystem via `const.sys_param`.

**New sys_param entries:**

| group_code | code | default | values |
|------------|------|---------|--------|
| `journal` | `storage_mode` | `local` | `local`, `notify`, `both` |
| `user_event` | `storage_mode` | `local` | `local`, `notify`, `both` |

**Storage modes:**

| Mode | Behavior |
|------|----------|
| `local` | INSERT into PostgreSQL only (current default, no behavior change) |
| `notify` | Fire `pg_notify` only, skip INSERT — data goes to external listener |
| `both` | INSERT into PostgreSQL AND fire `pg_notify` |

**New functions:**

| Function | Description |
|----------|-------------|
| `helpers.should_store_locally(_group_code)` | Returns true when storage_mode is `local` or `both` |
| `helpers.should_notify_storage(_group_code)` | Returns true when storage_mode is `notify` or `both` |
| `unsecure.notify_journal_event(...)` | Sends journal entry as JSON on `journal_events` channel |
| `unsecure.notify_user_event(...)` | Sends user event as JSON on `user_events` channel |

**Modified functions:**

- `public.create_journal_message()` — checks storage mode, fires notify if needed, skips INSERT in `notify` mode
- `unsecure.create_user_event()` — same pattern

**Notify channels:** `journal_events`, `user_events` (separate from existing `permission_changes`)

**Payload truncation:** pg_notify has an 8000 byte limit. If a payload exceeds ~7900 bytes, `data_payload`/`request_context` (or `event_data`/`request_context` for user events) are stripped and `"truncated": true` is added. Most payloads are well under 1KB.

**Note:** When mode is `notify`, search/query functions (`search_journal`, `get_journal_entry`, `search_user_events`, `get_user_audit_trail`, `get_security_events`) return empty results since data is not in PostgreSQL. The app should query the external store directly.

## 2026-02-26

### Changed

#### Request Context Consolidation

Replaced three separate text parameters (`_ip_address`, `_user_agent`, `_origin`) with a single `_request_context jsonb` parameter across all functions that accept request metadata. The same replacement applies to the corresponding table columns. This makes the system extensible — callers can pass any context fields (e.g., `device_id`, `geo_location`, `session_id`) without modifying function signatures.

#### Schema Changes

| Table | Change |
|-------|--------|
| `auth.user_event` | Replaced `ip_address text`, `user_agent text`, `origin text` columns with `request_context jsonb` |
| `auth.token` | Replaced `ip_address text`, `user_agent text`, `origin text` columns with `request_context jsonb` |
| `public.journal` | Added `request_context jsonb` column |

#### Function Signature Changes (22 functions)

All functions that previously accepted `_ip_address text, _user_agent text, _origin text` now accept `_request_context jsonb` instead:

**Core event functions:**
- `unsecure.create_user_event` — `_request_context jsonb default null` replaces three text params
- `auth.create_user_event` — same replacement, pass-through to unsecure

**User management (10 functions):**
- `auth.enable_user`, `auth.disable_user`, `auth.unlock_user`, `auth.lock_user`
- `auth.enable_user_identity`, `auth.disable_user_identity`
- `auth.update_user_password` (required, no default)
- `auth.register_user`
- `auth.get_user_by_email_for_authentication`
- `auth.ensure_user_from_provider`

**Token functions (6 functions):**
- `auth.set_token_as_used`, `auth.set_token_as_used_by_token`
- `auth.set_token_as_failed`, `auth.set_token_as_failed_by_token`
- `auth.validate_token`
- `public.validate_token`

**API key validation:**
- `auth.validate_api_key`

**Query/reporting return types updated:**
- `auth.search_user_events` — returns `__request_context jsonb` instead of three text columns
- `auth.get_user_audit_trail` — same replacement
- `auth.get_security_events` — same replacement

#### Journal Functions Extended

All journal creation functions now accept an optional `_request_context jsonb` parameter and store it in the new `public.journal.request_context` column:

- `public.create_journal_message`
- `public.create_journal_message_by_code`
- `public.create_journal_message_for_entity`
- `public.create_journal_message_for_entity_by_code`
- `public.get_journal_entry` — return type includes `__request_context jsonb`

#### Calling Convention

```sql
-- Standard usage
select auth.enable_user('admin', 1, 'corr-123', 42,
    _request_context := '{"ip_address": "192.168.1.1", "user_agent": "Mozilla/5.0", "origin": "https://app.example.com"}'::jsonb);

-- With custom fields (the whole point of this refactor)
select auth.register_user('admin', 1, 'corr-123', 'user@example.com', '$hash$', 'User Name',
    _request_context := jsonb_build_object(
        'ip_address', '192.168.1.1',
        'user_agent', 'Mozilla/5.0',
        'device_id', 'abc-123',
        'geo_location', 'Prague, CZ'
    ));

-- Without context (optional — defaults to null)
select auth.enable_user('admin', 1, 'corr-123', 42);
```

### Breaking Changes

- **Column renames on `auth.user_event` and `auth.token`**: `ip_address`, `user_agent`, `origin` columns replaced by `request_context jsonb`. Queries that read these columns must be updated.
- **Function signatures**: All 22 functions listed above have changed parameter lists. Callers passing positional arguments for the old three-param pattern must switch to the new `_request_context` parameter.
- **Return type changes**: `auth.search_user_events`, `auth.get_user_audit_trail`, `auth.get_security_events` now return `__request_context jsonb` instead of separate text columns.

**Files modified:** `013_tables_auth.sql`, `014_tables_stage.sql`, `018_functions_public.sql`, `019_functions_unsecure.sql`, `020_functions_auth_user.sql`, `025_functions_auth_token.sql`, `026_functions_auth_apikey.sql`, `028_functions_auth_event.sql`, `tests/test_registration_login_events.sql`

---

## 2026-02-23

### Added

#### Range Partitioning for Audit Tables

Both `public.journal` and `auth.user_event` are now range-partitioned by `created_at` (monthly). On busy systems these tables grow indefinitely; the old `DELETE WHERE created_at < threshold` purge was slow (row-by-row deletion, WAL bloat, index maintenance). Partitioning solves this with instant `DROP PARTITION` purges, automatic partition pruning on all date-filtered queries, and smaller per-partition indexes for faster inserts.

#### Schema Changes

| Change | Description |
|--------|-------------|
| `public.journal` PK | `journal_id` -> composite `(journal_id, created_at)` |
| `public.journal` | Added `partition by range (created_at)` |
| `auth.user_event` PK | `user_event_id` -> composite `(user_event_id, created_at)` |
| `auth.user_event` | Added `partition by range (created_at)` |
| `auth.token.user_event_id` FK | Dropped (partitioned tables require partition key in FK target; the FK also had `ON DELETE CASCADE` which would cascade-delete tokens when old event partitions are dropped) |
| New index `ix_user_event_created` | `auth.user_event (created_at desc)` |
| New index `ix_user_event_target_user` | `auth.user_event (target_user_id, created_at desc)` |
| Default partitions | `public.journal_default`, `auth.user_event_default` (safety net) |
| Initial partitions | 5 monthly partitions created at setup (-1 to +3 months from now) |

#### New Functions

| Function | Description |
|----------|-------------|
| `unsecure.ensure_audit_partitions(_months_ahead)` | Creates monthly partitions N months ahead for both tables. Idempotent. Reads default from `const.sys_param` (`partition.months_ahead`). |

#### New Seed Data

| Parameter | Value | Description |
|-----------|-------|-------------|
| `partition.months_ahead` | `3` | Default number of months to pre-create partitions |

### Changed

#### Purge Functions Rewritten for Partition Drops

`unsecure.purge_journal()` and `unsecure.purge_user_events()` now:
1. Calculate cutoff month from retention days
2. Find and drop partitions named `journal_YYYY_MM` / `user_event_YYYY_MM` older than cutoff
3. Fall back to `DELETE` on the default partition for safety
4. Call `ensure_audit_partitions()` to pre-create future months

#### Search Functions Optimized for Partition Pruning

`public.search_journal()` and `auth.search_user_events()` now pass `created_at` through the CTE to the join condition, enabling the planner to prune partitions on the re-join instead of scanning all partitions.

**Files modified:** `013_tables_auth.sql`, `014_tables_stage.sql`, `018_functions_public.sql`, `019_functions_unsecure.sql`, `028_functions_auth_event.sql`, `029_seed_data.sql`

---

## 2026-02-22

### Added

#### Source Tracking for Permissions, Permission Sets, Event Codes, and Event Categories

When inspecting `auth.permission` or `const.event_code` in a production system, there was no way to tell which rows came from the core permissions model vs. the application vs. a plugin. The new `source` column solves this.

#### Schema Changes

Added `source text default null` to four tables:

| Table | Description |
|-------|-------------|
| `auth.permission` | Track which module defined each permission |
| `auth.perm_set` | Track which module defined each permission set |
| `const.event_code` | Track which module defined each event code |
| `const.event_category` | Track which module defined each event category |

All core seed data is marked `source = 'core'`. Existing applications that don't specify a source get `null` — fully non-breaking.

**Files modified:** `012_tables_const.sql`, `013_tables_auth.sql`

#### Function Changes — Creation Chain

All permission and perm set creation functions now accept `_source text default null`, passed down through the chain:

| Function | File |
|----------|------|
| `unsecure.create_permission()` | `019_functions_unsecure.sql` |
| `unsecure.create_permission_as_system()` | `019_functions_unsecure.sql` |
| `auth.create_permission()` | `022_functions_auth_permission.sql` |
| `unsecure.create_perm_set()` | `019_functions_unsecure.sql` |
| `unsecure.create_perm_set_as_system()` | `019_functions_unsecure.sql` |
| `auth.create_perm_set()` | `022_functions_auth_permission.sql` |
| `public.create_event_code()` | `018_functions_public.sql` |
| `public.create_event_category()` | `018_functions_public.sql` |

`unsecure.copy_perm_set()` propagates `source` from the source perm set to the copy.

#### Function Changes — Query and Search

All query/search functions now return `__source text`:

| Function | File | Also added `_source` filter? |
|----------|------|------------------------------|
| `unsecure.get_all_permissions()` | `019_functions_unsecure.sql` | No |
| `auth.get_all_permissions()` | `022_functions_auth_permission.sql` | No |
| `unsecure.get_perm_sets()` | `019_functions_unsecure.sql` | No |
| `auth.get_perm_sets()` | `022_functions_auth_permission.sql` | No |
| `auth.search_permissions()` | `022_functions_auth_permission.sql` | Yes |
| `auth.search_perm_sets()` | `022_functions_auth_permission.sql` | Yes |
| `public.get_permissions_map()` | `022_functions_auth_permission.sql` | No |

#### View Changes

`auth.effective_permissions` — added `perm_set_source` and `permission_source` columns.

**Files modified:** `015_views.sql`

#### Search Trigger Changes

`triggers.calculate_permission_search_values()` and `triggers.calculate_perm_set_search_values()` now include `source` in `nrm_search_data`, so full-text search picks up source values.

**Files modified:** `017_functions_triggers.sql`

#### Seed Data

- All ~90 `create_permission_as_system()` calls in `seed_permission_data()` now pass `_source := 'core'`
- All ~19 `create_perm_set_as_system()` calls in `seed_permission_data()` now pass `_source := 'core'`
- All `INSERT INTO const.event_category` rows (15) now include `source = 'core'`
- All `INSERT INTO const.event_code` rows (~80) now include `source = 'core'`

**Files modified:** `022_functions_auth_permission.sql`, `029_seed_data.sql`

#### Usage Examples

```sql
-- All core permissions grouped by source
select source, count(*) from auth.permission group by source;

-- Application creates its own permission
select auth.create_permission('admin', 1, null, 'Export data', 'areas.admin',
    _source := 'myapp');

-- Search by source
select * from auth.search_permissions(1, null, _source := 'core');
select * from auth.search_perm_sets(1, null, _source := 'core');

-- Event codes by source
select source, count(*) from const.event_code group by source;
```

---

## 2026-02-21

### Added

#### Audit Infrastructure Improvements
Comprehensive improvements to the audit and logging subsystems: plugging journal gaps, adding admin action context tracking, data retention, and higher-level audit query functions.

#### 1. Journal Gaps Filled

**Group sync operations** — `auth.process_external_group_member_sync_by_mapping()` and `auth.process_external_group_member_sync()` performed bulk INSERT/UPDATE/DELETE on `auth.user_group_member` with zero audit trail. A scheduled sync job could add/remove dozens of users invisibly.

- `process_external_group_member_sync_by_mapping()` now creates a summary journal entry (event 13030 `group_members_synced`) recording `members_created`, `users_ensured`, `provider_code`, and `user_group_mapping_id`
- `process_external_group_member_sync()` now journals per-mapping deletions (event 13011 `group_member_removed`) with `members_deleted` count and `action: sync_cleanup` / `sync_cleanup_missing_mappings`

**Token batch expiration** — `unsecure.expire_tokens()` silently expired tokens with no audit trail.

- Rewritten from `language sql` to `language plpgsql` with `get diagnostics` to capture row count
- Now journals batch expirations (event 15003 `token_expired`) with `expired_count` and `action: batch_expiration`

**New event code:**

| ID | Code | Category | Description |
|----|------|----------|-------------|
| 13030 | `group_members_synced` | `group_event` | External group members synchronized from provider |

**Files modified:** `019_functions_unsecure.sql`, `021_functions_auth_group.sql`, `029_seed_data.sql`

#### 2. Admin Action Context (IP/User-Agent/Origin)

Six admin user management functions created journal entries but lacked IP/user-agent/origin tracking in `auth.user_event`. Each function now:
- Accepts optional `_ip_address text`, `_user_agent text`, `_origin text` parameters (all `DEFAULT NULL` — non-breaking change)
- Creates a `user_event` entry alongside the existing journal entry

| Function | user_event type |
|----------|----------------|
| `auth.enable_user()` | `user_enabled` |
| `auth.disable_user()` | `user_disabled` |
| `auth.unlock_user()` | `user_unlocked` |
| `auth.lock_user()` | `user_locked` |
| `auth.enable_user_identity()` | `identity_enabled` |
| `auth.disable_user_identity()` | `identity_disabled` |

**Files modified:** `020_functions_auth_user.sql`

#### 3. Data Retention & Cleanup

No mechanism existed for purging old audit data — both `journal` and `user_event` grew indefinitely.

**Configuration** — retention defaults added to `const.sys_param`:

| group_code | code | text_value |
|------------|------|------------|
| `journal` | `retention_days` | `365` |
| `user_event` | `retention_days` | `365` |

**New functions:**

| Function | Schema | Description |
|----------|--------|-------------|
| `unsecure.purge_journal()` | unsecure | Deletes journal entries older than specified/configured days |
| `unsecure.purge_user_events()` | unsecure | Deletes user events older than specified/configured days |
| `public.purge_audit_data()` | public | Permission-checked wrapper calling both purge functions, self-journals the purge action |

- `purge_audit_data()` requires `journal.purge_journal` permission
- If `_older_than_days` is null, reads from `const.sys_param` retention config
- The purge itself is journaled (event 17001 `audit_data_purged`) recording `journal_deleted` and `user_events_deleted` counts

**New permission:**

| Permission Code | Description |
|-----------------|-------------|
| `journal.purge_journal` | Purge old audit data |

Added to `system_admin` permission set.

**New event category and code:**

| ID | Code | Category | Description |
|----|------|----------|-------------|
| — | `maintenance_event` | — | New category (17001-17999) for system maintenance events |
| 17001 | `audit_data_purged` | `maintenance_event` | Old audit data was purged |

**Files modified:** `019_functions_unsecure.sql`, `018_functions_public.sql`, `022_functions_auth_permission.sql`, `029_seed_data.sql`

#### 4. Audit Summary Query Functions

Two new higher-level query functions for common audit needs:

**`auth.get_user_audit_trail()`** — Combined, paginated view of all audit activity for a specific user. UNIONs journal entries (matched via `keys @> {"user": target_user_id}`) with user events (matched via `target_user_id`). Returns unified rows with `__source` ('journal' or 'user_event'), resolved messages for journal entries, and IP/user-agent/origin for user events.

**`auth.get_security_events()`** — Aggregated, paginated view of security-relevant events across the system. Includes failed logins (`user_login_failed`), lockouts (`user_locked`, `user_disabled`), unlock/enable events, identity changes, and permission denials (journal event 32001). Returns source, requester/target user info, IP/user-agent, and event data.

Both functions require `authentication.read_user_events` permission and support date range filtering and pagination.

**Files modified:** `028_functions_auth_event.sql`

#### 5. Ensure Provider Function

New `auth.ensure_provider()` — idempotent provider creation following the same "ensure" pattern as `auth.ensure_user_info()`. Returns existing provider if found (no permission check), or creates a new one (requires `providers.create_provider`). Returns `__provider_id` and `__is_new` flag.

**Files modified:** `024_functions_auth_provider.sql`

#### 6. Composable Human Admin Permission Sets

Eight new permission sets that break down the monolithic `system_admin` into composable, human-facing roles. Each set grants only the permissions needed for a specific administrative function — assign multiple sets to a user or group for composite roles.

| Permission Set | Permissions | Use Case |
|---------------|-------------|----------|
| `User manager` | `users`, `authentication.read_user_events`, `journal.read_journal`, `journal.get_payload` | User CRUD, view user audit events |
| `Group manager` | `groups`, `journal.read_journal`, `journal.get_payload` | Group and membership management |
| `Permission manager` | `permissions`, `journal.read_journal`, `journal.get_payload` | Permission and perm set management |
| `Provider manager` | `providers`, `journal.read_journal`, `journal.get_payload` | Identity provider management |
| `Token manager` | `tokens.create_token`, `tokens.validate_token`, `tokens.set_as_used`, `token_configuration`, `journal.read_journal`, `journal.get_payload` | Token lifecycle and token type config |
| `Api key manager` | `api_keys`, `journal.read_journal`, `journal.get_payload` | API key management |
| `Auditor` | `journal`, `authentication.read_user_events`, `users.read_users`, `groups.get_group`, `groups.get_groups`, `tenants.read_tenants` | Read-only audit access across all entities |
| `Full admin` | All of the above combined + `tenants`, `journal.purge_journal`, `languages`, `translations`, `authentication.create_auth_event` | Complete administrative access |

All sets are `is_assignable = true` so they can be assigned to users or groups via `auth.assign_permission()`.

**New group:**

| Group ID | Name | Permission Set |
|----------|------|---------------|
| 3 | `Full admins` | `full_admin` |

Add users to the "Full admins" group for complete administrative access without using the `system_admin` perm set (which is reserved for the system superuser).

**Files modified:** `022_functions_auth_permission.sql`

### Fixed

#### Bug: Duplicate Email Check Bypassed in `auth.register_user()`
`__normalized_email` was declared but never assigned — stayed NULL. The duplicate check `ui.uid = lower(NULL)` always evaluated to false, so registering the same email twice bypassed the friendly error and hit a raw unique constraint violation instead.

Fix: added `__normalized_email := lower(trim(_email))` before the duplicate check.

**Files modified:** `020_functions_auth_user.sql`

#### Bug: `ON CONFLICT` Mismatch in `recalculate_user_groups()`
`ON CONFLICT (user_group_id, user_id)` didn't match the actual unique index `uq_user_group_member (user_group_id, user_id, coalesce(mapping_id, 0))`. PostgreSQL requires an exact match. Any `has_permission` call that triggered `recalculate_user_groups` for a user already in a default group would fail with `invalid_column_reference`.

Fix: changed to `ON CONFLICT (user_group_id, user_id, coalesce(mapping_id, 0))`.

**Files modified:** `019_functions_unsecure.sql`

---

## 2026-02-21

### Added

#### Dedicated Service Accounts (Least-Privilege System Users)
Previously the backend used `user_id:1` (system superuser) for all operations — registration, login, token ops, API key validation, etc. This user has a hardcoded bypass in `auth.has_permissions()` that returns `true` unconditionally. If a backend endpoint leaks this context, it has godmode over the entire system.

The system now ships with purpose-specific service accounts, each with only the permissions needed for its job. The user_id range 1-999 is reserved for system/service users (sequence starts at 1000).

**Service Accounts:**

| ID | Username | Display Name | Purpose | Key Permissions |
|----|----------|-------------|---------|-----------------|
| 1 | `system` | System | Seed/migration only (keeps `has_permissions` bypass, never used at runtime) | *(bypass)* |
| 2 | `svc_registrator` | Registrator | User registration flow | `users.register_user`, `users.add_to_default_groups`, `tokens.create_token` |
| 3 | `svc_authenticator` | Authenticator | Login & authentication flow | `authentication.get_data`, `authentication.ensure_permissions`, `authentication.get_users_groups_and_permissions`, `authentication.create_auth_event`, `tokens.validate_token`, `tokens.set_as_used` |
| 4 | `svc_token_manager` | Token Manager | Token lifecycle (password reset, email verification, etc.) | `tokens.create_token`, `tokens.validate_token`, `tokens.set_as_used` |
| 5 | `svc_api_gateway` | API Gateway | API key validation at the gateway/middleware level | `api_keys.validate_api_key` |
| 6 | `svc_group_syncer` | Group Syncer | Background external group member synchronization | `groups.get_groups`, `groups.get_members`, `groups.create_member`, `groups.delete_member`, `groups.get_mapping`, `users.register_user`, `users.add_to_default_groups` |
| 800 | `svc_data_processor` | Data Processor | Generic app-level data processing (recommended alternative to user_id 1) | *(none — app adds its own)* |

All service accounts: `user_type_code = 'service'`, `can_login = false`, `is_system = true`.

**Permission Sets:**

| Permission Set | Assigned To |
|----------------|-------------|
| `svc_registrator_permissions` | `svc_registrator` (2) |
| `svc_authenticator_permissions` | `svc_authenticator` (3) |
| `svc_token_permissions` | `svc_token_manager` (4) |
| `svc_api_gateway_permissions` | `svc_api_gateway` (5) |
| `svc_group_syncer_permissions` | `svc_group_syncer` (6) |
| `svc_data_processor_permissions` | `svc_data_processor` (800) |

**Design decisions:**
- `svc_registrator` also gets `tokens.create_token` — registration flows typically create email/phone verification tokens
- `svc_authenticator` also gets `tokens.validate_token` + `tokens.set_as_used` — verification link clicks go through the auth flow
- `svc_data_processor` (ID 800) ships with an empty permission set — applications add their own permissions to it. Recommended as the default backend service account instead of `user_id:1`
- Admin operations (enable/disable/lock users, manage groups, etc.) are done by human admins with permissions through group membership — no service account needed
- `auth.ensure_user_from_provider()` has no permission check by design (provider validation serves as authorization), so the authenticator doesn't need extra permissions for provider login

**Files modified:** `022_functions_auth_permission.sql`, `029_seed_data.sql`

### Fixed

#### Missing Permissions in Seed Data
Two authentication permissions were checked by existing functions but never created in `seed_permission_data()`:
- `authentication.ensure_permissions` — checked by `auth.ensure_groups_and_permissions()` but never seeded
- `authentication.get_users_groups_and_permissions` — checked by `auth.get_users_groups_and_permissions()` but never seeded (only `users.get_users_groups_and_permissions` existed under a different parent)

#### `system_admin` Permission Set Missing Token & Authentication Permissions
The `system_admin` perm set didn't include `tokens` or `authentication` parent permissions. Regular System Admin group members (not user_id:1) couldn't perform token or authentication operations. Added both to the permission set.

---

## 2026-02-20

### Added

#### Real-Time Permission Change Notifications (LISTEN/NOTIFY)
PostgreSQL pub/sub notifications for permission-relevant changes. Backends can `LISTEN permission_changes` to receive JSON notifications and push "refetch permissions" events to clients via SSE/WebSocket.

**New Functions:**

| Function | Schema | Description |
|----------|--------|-------------|
| `unsecure.notify_permission_change(_event, _tenant_id, _target_type, _target_id, _detail)` | unsecure | Builds JSON payload and calls `pg_notify('permission_changes', ...)` |
| `unsecure.invalidate_permission_users_cache(_updated_by, _permission_id)` | unsecure | Invalidates cache for all users affected by a permission change (direct, via perm_set, via group) |
| `unsecure.invalidate_users_permission_cache(_updated_by, _user_ids, _tenant_id)` | unsecure | Bulk cache invalidation for an array of user IDs |

**Notification Payload Format:**
```json
{
    "event": "group_member_added",
    "tenant_id": 1,
    "target_type": "user",
    "target_id": 42,
    "detail": { "group_id": 7 },
    "at": "2026-02-20T14:30:00Z"
}
```

**Notification Trigger Functions (triggers schema):**

| Trigger Function | Table | Events | Notification Events |
|-----------------|-------|--------|---------------------|
| `triggers.notify_permission_assignment` | `auth.permission_assignment` | INSERT, DELETE | `permission_assigned`, `permission_unassigned` |
| `triggers.notify_perm_set_perm` | `auth.perm_set_perm` | INSERT, DELETE | `perm_set_permissions_added`, `perm_set_permissions_removed` |
| `triggers.notify_user_group_member` | `auth.user_group_member` | INSERT, DELETE | `group_member_added`, `group_member_removed` |
| `triggers.notify_user_group` | `auth.user_group` | UPDATE, DELETE | `group_disabled`, `group_enabled`, `group_type_changed`, `group_deleted` |
| `triggers.notify_user_group_mapping` | `auth.user_group_mapping` | INSERT, DELETE | `group_mapping_created`, `group_mapping_deleted` |
| `triggers.notify_user_status` | `auth.user_info` | UPDATE, DELETE | `user_disabled`, `user_enabled`, `user_locked`, `user_unlocked`, `user_deleted` |
| `triggers.notify_owner` | `auth.owner` | INSERT, DELETE | `owner_created`, `owner_deleted` |
| `triggers.notify_provider` | `auth.provider` | UPDATE, DELETE | `provider_disabled`, `provider_enabled`, `provider_deleted` |
| `triggers.notify_perm_set` | `auth.perm_set` | UPDATE | `perm_set_updated` |
| `triggers.notify_permission` | `auth.permission` | UPDATE | `permission_assignability_changed` |
| `triggers.notify_tenant` | `auth.tenant` | DELETE | `tenant_deleted` |
| `triggers.notify_api_key` | `auth.api_key` | INSERT, DELETE | `api_key_created`, `api_key_deleted` |

**Backend Integration:**
```
1. Maintain a dedicated LISTEN connection (not from connection pool — PgBouncer transaction mode doesn't support LISTEN)
2. On notification: parse JSON, route by target_type (user/group/perm_set/tenant/provider/system)
3. Send SSE/WebSocket "REFETCH_PERMISSIONS" event to affected clients
4. Debounce: collect notifications for 100-200ms before broadcasting (bulk operations fire multiple triggers)
```

**Notification Resolution Views:**

Backend receives a notification with `target_type` + `target_id`, then queries the matching view to get affected user IDs:

| View | Query Pattern | Used For |
|------|--------------|----------|
| `auth.notify_group_users` | `WHERE user_group_id = $1` | `group_*` events, `permission_assigned` to group |
| `auth.notify_perm_set_users` | `WHERE perm_set_id = $1` | `perm_set_*` events |
| `auth.notify_permission_users` | `WHERE permission_id = $1` | `permission_assignability_changed` |
| `auth.notify_provider_users` | `WHERE provider_code = $1` | `provider_disabled`, `provider_deleted` |
| `auth.notify_tenant_users` | `WHERE tenant_id = $1` | `tenant_deleted` |
| *(no view needed)* | user_id is in the payload | `user_*`, `owner_*`, `group_member_*` events |

**Design Decisions:**
- Notifications are trigger-based (not embedded in `auth.*` functions) to preserve db-gen compatibility
- `auth.*` functions remain untouched — all new logic is in `triggers.*` and `unsecure.*` schemas
- Notifications are fire-and-forget (no persistence) — if nobody is listening, messages are discarded
- Cache invalidation is the correctness mechanism; notifications are an optimization for client freshness

**New File:** `033_triggers_cache_and_notify.sql`

### Fixed

#### Critical: Cache Invalidation Gaps
Multiple mutation points changed effective permissions but did NOT invalidate the permission cache, causing users to retain revoked permissions (or miss granted ones) for up to `perm_cache_timeout_in_s` seconds.

**Gaps fixed via trigger functions (in `triggers` schema):**

| Trigger Function | Table | Gap Fixed |
|-----------------|-------|-----------|
| `triggers.cache_user_group_member_delete` | `auth.user_group_member` AFTER DELETE | Removing user from group didn't clear cache — user retained group permissions |
| `triggers.cache_user_group_status_change` | `auth.user_group` AFTER UPDATE | Disabling/enabling a group didn't invalidate members' cache |
| `triggers.cache_user_group_before_delete` | `auth.user_group` BEFORE DELETE | Deleting a group cascade-deleted members but cached permissions persisted |
| `triggers.cache_provider_before_delete` | `auth.provider` BEFORE DELETE | Deleting provider cascade-deleted identities but cached permissions persisted |
| `triggers.cache_provider_status_change` | `auth.provider` AFTER UPDATE | Disabling provider didn't invalidate affected users' cache |

**Gaps fixed via direct changes in `unsecure.*` functions:**

| Function | Gap Fixed |
|----------|-----------|
| `unsecure.create_user_group_member()` | Adding user to group didn't clear cache — user didn't get group permissions until cache expired |
| `unsecure.set_permission_as_assignable()` | Making permission non-assignable didn't invalidate affected users — they kept the permission |
| `unsecure.update_perm_set()` | Changing perm_set `is_assignable` didn't invalidate affected users |

**Impact:** All permission-relevant mutations now take effect immediately instead of being delayed by cache timeout.

---

## 2026-02-14

### Added

#### User Events for Registration and Login
Added audit trail events for user registration and login flows:
- `user_registered` (10008) — new event code, fired on `auth.register_user` and `auth.ensure_user_from_provider` (new user)
- `user_logged_in` (10010) — fired on successful `auth.get_user_by_email_for_authentication` and `auth.ensure_user_from_provider` (returning user)
- `user_login_failed` (10012) — fired on all authentication failures (user not found, disabled, locked, identity disabled, login disabled)

Added `_ip_address`, `_user_agent`, `_origin` parameters to `auth.register_user`, `auth.get_user_by_email_for_authentication`, and `auth.ensure_user_from_provider` for client metadata in audit events.

### Changed

#### Code Generator Compatibility: Unique Journal Function Names
Split `public.create_journal_message` from 4 overloads sharing the same name into 4 distinctly named functions. PostgreSQL handles overloading natively, but external code generators (Elixir, C#) cannot distinguish functions that differ only by parameter types. Each overload now has a unique name that describes its purpose.

**Renamed functions:**

| Old Name (all `create_journal_message`) | New Name | Key Parameters | Usage |
|---|---|---|---|
| Overload 1 — event ID + keys | `create_journal_message` | `_event_id integer, _keys jsonb, _payload jsonb` | Unchanged — base function for arbitrary key journaling |
| Overload 2 — event code + keys | `create_journal_message_by_code` | `_event_code text, _keys jsonb, _payload jsonb` | Resolves event code to ID, then delegates to overload 1 |
| Overload 3 — entity shorthand | `create_journal_message_for_entity` | `_event_id integer, _entity_type text, _entity_id bigint` | Builds `{entity_type: entity_id}` keys automatically — most common pattern (~70+ call sites) |
| Overload 4 — entity + code | `create_journal_message_for_entity_by_code` | `_event_code text, _entity_type text, _entity_id bigint` | Resolves event code, then delegates to `_by_code` |

**Internal delegation chain:**
```
create_journal_message_for_entity_by_code → create_journal_message_by_code → create_journal_message
create_journal_message_for_entity → create_journal_message
```

**Callers updated across 15 files:**

| File | Calls | New Function |
|------|-------|-------------|
| `019_functions_unsecure.sql` | 22 | `create_journal_message_for_entity` |
| `021_functions_auth_group.sql` | 13 | `create_journal_message_for_entity` |
| `026_functions_auth_apikey.sql` | 10 | `create_journal_message_for_entity` |
| `020_functions_auth_user.sql` | 7 | `create_journal_message_for_entity` |
| `025_functions_auth_token.sql` | 7 | `create_journal_message_for_entity` |
| `024_functions_auth_provider.sql` | 5 | `create_journal_message_for_entity` |
| `023_functions_auth_tenant.sql` | 3 | `create_journal_message_for_entity` |
| `027_functions_auth_owner.sql` | 2 | `create_journal_message_for_entity` |
| `022_functions_auth_permission.sql` | 1 | `create_journal_message_for_entity` |
| `032_functions_translation.sql` | 2 | `create_journal_message_for_entity` |
| `018_functions_public.sql` | 1 | `create_journal_message_for_entity` |
| `031_functions_language.sql` | 3 | `create_journal_message` (unchanged — uses keys jsonb pattern) |
| `032_functions_translation.sql` | 2 | `create_journal_message` (unchanged — uses keys jsonb pattern) |
| `018_functions_public.sql` | 1 | `create_journal_message_by_code` |
| `tests/test_event_code_management.sql` | 1 | `create_journal_message_by_code` |
| `tests/test_correlation_id.sql` | 4 | `create_journal_message_for_entity` |

**Note:** `031_functions_language.sql` (3 calls) and `032_functions_translation.sql` (2 calls for `create_translation` and `copy_translations`) continue using `create_journal_message` — these calls pass `null::jsonb` as keys and a jsonb payload directly, matching overload 1's signature.

#### Code Generator Compatibility: Moved `throw_no_permission` to `internal` Schema
Moved all 4 overloads of `auth.throw_no_permission` → `internal.throw_no_permission`. This function is an internal helper used by `auth.has_permissions()` and a few other places to raise permission-denied exceptions. It was in the `auth` schema, which meant code generators would include it in auto-generated client code — but it should never be called directly from application code.

**Moved overloads:**

| Signature | Purpose |
|-----------|---------|
| `internal.throw_no_permission(_user_id bigint, _perm_codes text[], _tenant_id integer DEFAULT 1)` | Primary implementation — logs denial to journal, raises exception with all failed permission codes |
| `internal.throw_no_permission(_user_id bigint, _perm_codes text[])` | Convenience — delegates to primary with `_tenant_id := 1` |
| `internal.throw_no_permission(_user_id bigint, _perm_code text, _tenant_id integer DEFAULT 1)` | Single permission code — wraps into array, delegates to primary |
| `internal.throw_no_permission(_user_id bigint, _perm_code text)` | Single permission code — wraps into array, delegates to primary with `_tenant_id := 1` |

**Callers updated:**

| File | Context |
|------|---------|
| `022_functions_auth_permission.sql` | `has_permissions()` — calls `internal.throw_no_permission` on permission check failure |
| `018_functions_public.sql` | `search_journal()` — calls `internal.throw_no_permission` for global journal access check |
| `023_functions_auth_tenant.sql` | `assign_tenant_owner()` — calls `internal.throw_no_permission` for owner permission check |
| `999-examples.sql` | Updated examples |

**Impact:** The `internal` schema is excluded from code generation by convention (it contains business logic that's already permission-checked at a higher level). No behavior change at runtime — only the schema qualifier changes.

### Fixed

#### Bug: Email Registration Creates Inactive Identity
`auth.register_user()` called `unsecure.create_user_identity()` without passing `_is_active := true`,
so the identity defaulted to inactive. Login immediately failed with "identity disabled" error.
The provider-based flow (`auth.ensure_user_from_provider()`) was not affected.

#### Bug: Email Registration Stores Password Hash in Wrong Column
`auth.register_user()` passed `_password_hash` as the 7th positional argument to `unsecure.create_user_identity()`, which mapped to `_provider_oid` instead of `_password_hash`. Result: `password_hash` was null and `provider_oid` contained the hash — login always failed. Fixed by passing `lower(trim(_email))` as `_provider_oid` (7th arg) and the hash as `_password_hash` (8th arg).

---

## 2026-02-14

### Added

#### Hierarchical Short Permission Codes
Added compact hierarchical `short_code` to permissions for wire-format optimization. Instead of sending full permission codes like `token_configuration.create_token_type` (42 chars), services can download the mapping once at startup and send short codes like `05.01` over the wire.

**Schema Changes:**
- `auth.permission` - Added `short_code text` column with unique partial index
- `auth.user_permission_cache` - Added `short_code_permissions text[]` column

**New Functions:**

| Function | Description |
|----------|-------------|
| `unsecure.compute_short_code(_permission_id)` | Computes hierarchical short code (e.g., `03.01`) by counting sibling ordinals at each tree level |
| `unsecure.update_permission_short_code(_perm_path)` | Batch-updates short codes for all permissions in a subtree |
| `public.get_permissions_map()` | Returns `(permission_id, full_code, short_code, title)` for all assignable permissions - no permission check required |

**Optional Custom Short Code:** `unsecure.create_permission()`, `unsecure.create_permission_as_system()`, and `auth.create_permission()` accept an optional `_short_code text` parameter. When provided, the custom value is used instead of the auto-computed hierarchical code. This allows consumers to use custom codes (e.g., random tokens like `x7f9k2`) for specific permissions.

**Extended Return Types:**
- `unsecure.recalculate_user_permissions()` - Returns `__short_code_permissions text[]` as 5th column
- `auth.ensure_groups_and_permissions()` - Returns `__short_code_permissions text[]` as 5th column
- `auth.get_users_groups_and_permissions()` - Returns `__short_code_permissions text[]` as 5th column
- `auth.get_all_permissions()` - Returns `__short_code text` column
- `auth.search_permissions()` - Returns `__short_code text` column
- `unsecure.get_all_permissions()` - Returns `__short_code text` column
- `auth.effective_permissions` view - Added `permission_short_code` column

**Automatic Assignment:** `short_code` is computed automatically when permissions are created via `unsecure.create_permission()` (unless a custom `_short_code` is provided). Existing permissions are backfilled during seed data execution.

**Design:** Server-side `has_permissions()` checks remain text-based for readability/auditability. Short codes are purely for wire-format optimization in client-server communication.

#### Language & Translation System
Merged the standalone `postgresql-languages-model` into the permissions model. All functions now have direct access to a single language/translation system without duplicating infrastructure.

**New Tables:**

| Table | Description |
|-------|-------------|
| `const.language` | Language registry (PK: `code text`) with frontend/backend/communication flags, logical ordering, default flags, and custom_data jsonb |
| `public.translation` | Translation storage with full-text search (tsvector + gin_trgm_ops), supports both `data_object_code` (text key) and `data_object_id` (numeric key) lookups |

**New Language Functions (public schema):**

| Function | Permission | Description |
|----------|-----------|-------------|
| `create_language()` | `languages.create_language` | Create language, auto-unsets other defaults when setting `is_default_*=true` |
| `update_language()` | `languages.update_language` | Update language with same default enforcement |
| `delete_language()` | `languages.delete_language` | Delete language, CASCADE removes translations |
| `get_language()` | none | Get single language by code |
| `get_languages()` | none | Get all languages with optional frontend/backend/communication filters, LEFT JOIN translation for display name |
| `get_frontend_languages()` | none | Frontend languages ordered by `frontend_logical_order` |
| `get_backend_languages()` | none | Backend languages ordered by `backend_logical_order` |
| `get_communication_languages()` | none | Communication languages ordered by `communication_logical_order` |
| `get_default_language()` | none | Get default language for a category |

**New Translation Functions (public schema):**

| Function | Permission | Description |
|----------|-----------|-------------|
| `create_translation()` | `translations.create_translation` | Create translation, trigger auto-calculates search fields |
| `update_translation()` | `translations.update_translation` | Update translation value |
| `delete_translation()` | `translations.delete_translation` | Delete translation |
| `copy_translations()` | `translations.copy_translations` | Two-phase copy: update existing (if overwrite) then insert missing. Returns `(operation, count)` |
| `get_group_translations()` | none | Returns `jsonb_object_agg(data_object_code, value)` for a data_group |
| `search_translations()` | `translations.read_translations` | Paginated search with accent-insensitive matching via `normalize_text` |

**Trigger Infrastructure:**
- `helpers.calculate_ts_regconfig()` - Maps language code to PostgreSQL regconfig (en→english, de→german, fr→french, etc.)
- `triggers.calculate_translation_fields()` - BEFORE INSERT/UPDATE trigger auto-populates `ua_search_data` (normalized) and `ts_search_data` (tsvector)

**New Permissions:**

| Permission Code | Description |
|-----------------|-------------|
| `languages.create_language` | Create new languages |
| `languages.update_language` | Update existing languages |
| `languages.delete_language` | Delete languages |
| `languages.read_languages` | Read language list |
| `translations.create_translation` | Create translations |
| `translations.update_translation` | Update translations |
| `translations.delete_translation` | Delete translations |
| `translations.read_translations` | Search/read translations |
| `translations.copy_translations` | Copy translations between languages |

Added to `system_admin` and `tenant_admin` permission sets.

**New Event Codes:**

| Range | Category | Codes |
|-------|----------|-------|
| 17001-17999 | `language_event` | 17001 language_created, 17002 language_updated, 17003 language_deleted |
| 18001-18999 | `translation_event` | 18001-18003 CRUD, 18004 translations_copied |
| 35001-35999 | `language_error` | 35001 err_language_not_found, 35002 err_translation_not_found |

**New Error Functions:**
- `error.raise_35001(_language_code)` - Language not found
- `error.raise_35002(_translation_id)` - Translation not found

**FK Constraint:**
- `const.event_message.language_code` → `const.language.code` - Ensures event messages reference valid languages

**Seed Data:**
- Default 'en' (English) language with all flags set

**Design Decision:** `const.event_message` stays separate from `public.translation`. Event messages are templates with `{placeholder}` syntax and `is_active` versioning, tightly coupled to event codes. Translations are for plain UI text. Both share `const.language` as the language registry via FK.

**New Files:**

| File | Description |
|------|-------------|
| `030_tables_language.sql` | Tables, trigger, seed, FK, errors, events |
| `031_functions_language.sql` | 9 language functions |
| `032_functions_translation.sql` | 6 translation functions |
| `tests/test_language_translation.sql` | 25 test cases |

#### Test Runner Improvements
- Colored output in `tests/run-tests.sh`: green for PASS, red for FAIL/ERROR
- Colors auto-disable when output is piped (not a terminal)

#### Token Type CRUD Management
Runtime management of `const.token_type` entries, following the same pattern as event code CRUD.

**New Functions (public schema):**

| Function | Permission | Description |
|----------|-----------|-------------|
| `create_token_type()` | `token_configuration.create_token_type` | Create custom token type with optional expiration |
| `update_token_type()` | `token_configuration.update_token_type` | Update token type expiration (non-system only) |
| `delete_token_type()` | `token_configuration.delete_token_type` | Delete token type (non-system only) |
| `get_token_types()` | none | List all token types |

**Schema Changes:**
- Added `is_system boolean` column to `const.token_type` — protects seeded types from modification/deletion

**New Permissions:**

| Permission Code | Description |
|-----------------|-------------|
| `token_configuration.create_token_type` | Create new token types |
| `token_configuration.update_token_type` | Update existing token types |
| `token_configuration.delete_token_type` | Delete token types |
| `token_configuration.read_token_types` | Read token type list |

Added to `system_admin` permission set.

**New Event Codes:**

| Range | Category | Codes |
|-------|----------|-------|
| 19001-19999 | `token_config_event` | 19001 token_type_created, 19002 token_type_updated, 19003 token_type_deleted |
| 36001-36999 | `token_config_error` | 36001 err_token_type_not_found, 36002 err_token_type_is_system |

**New Error Functions:**
- `error.raise_36001(_token_type_code)` — Token type not found
- `error.raise_36002(_token_type_code)` — Token type is system

### Fixed

#### Bug: Missing `validation_failed` Token State
`auth.set_token_as_failed()` writes `'validation_failed'` to `token_state_code`, but seed data only included `'valid'`, `'used'`, `'expired'`, `'failed'`. This would cause an FK violation at runtime. Added `'validation_failed'` to `const.token_state` seed data.

#### Ambiguous Column References in Auth-Layer Functions
- `auth.can_manage_user_group` (`021_functions_auth_group.sql`) - Qualified `user_group_id` as `ug.user_group_id`; moved `ugm.user_id` filter from WHERE to JOIN ON so the LEFT JOIN works correctly (previously always returned no rows for non-members)
- `auth.get_user_available_tenants` (`023_functions_auth_tenant.sql`) - Qualified `tenant_id` and `user_group_id` with `ug.` prefix in CTE

#### Other Fixes
- `tests/test_event_code_management.sql` - TEST 18 now cleans up journal entries before deleting event code (FK constraint prevented deletion)

#### New Test Coverage
- `tests/test_auth_group_member_tenant.sql` - 11 tests for auth-layer group member & tenant functions (`auth.create_user_group_member`, `auth.delete_user_group_member`, `auth.get_user_group_members`, `auth.get_user_assigned_groups`, `auth.get_user_available_tenants`), covering happy paths, error cases (inactive/external/nonexistent groups), and full round-trip
- `tests/test_short_code.sql` - 16 tests for permission short codes: auto-computed hierarchical codes (format, depth, root vs child), custom `_short_code` parameter (override, pass-through via `create_permission_as_system`), unique constraint enforcement, schema validation (`effective_permissions` view, `user_permission_cache` column), return type verification (`get_permissions_map`, `get_all_permissions`), and `recalculate_user_permissions` cache population

### Changed
- **CLAUDE.md** - Added variable naming convention: `_` for parameters, `__` for return columns, `___` for local variables that clash with return columns

---

## 2026-02-12

### Added

#### Correlation ID Support for End-to-End Request Tracing
Added `_correlation_id text` parameter to all auth/public functions, enabling end-to-end request tracing from backend through the entire call chain down to audit tables.

**Schema changes:**
- Added `correlation_id text` column to `auth.user_event` table
- Added `correlation_id text` column to `public.journal` table
- Added partial indexes on both tables (`WHERE correlation_id IS NOT NULL`)

**New function:**
- `auth.search_user_events()` - Paginated search of user events with filters (correlation_id, event_type, target_user, date range)

**New permission:**
- `authentication.read_user_events` - Required for `auth.search_user_events()`

**Updated functions (~150 signatures):**
- All `auth.*` functions with `_user_id bigint` now accept `_correlation_id text` as the next parameter
- All `unsecure.*` functions forward `_correlation_id` to audit calls
- `auth.has_permission()` / `auth.has_permissions()` accept `_correlation_id` after `_target_user_id`
- `create_journal_message()` overloads forward `_correlation_id` to journal INSERT
- `search_journal()` / `search_journal_msgs()` support filtering by `_correlation_id`

**Call chain flow:**
```
Backend (generates correlation_id)
  → auth.*(... _correlation_id ...)
    → auth.has_permission(... _correlation_id ...) → journal on denial
    → unsecure.*(... _correlation_id ...)
      → create_journal_message(... _correlation_id ...) → public.journal
      → unsecure.create_user_event(... _correlation_id ...) → auth.user_event
```

**Files modified:** 018, 019, 020, 021, 022, 023, 024, 025, 026, 027, 028 (function files), 013, 014 (table files)

---

## 2026-02-11

### Fixed

#### Critical: Cache Invalidation on Permission Changes
Permission cache is now properly invalidated when permissions are assigned, unassigned, or when permission set contents change:

- `unsecure.assign_permission()` - Now clears cache for affected user or group members
- `unsecure.unassign_permission()` - Now clears cache for affected user or group members
- `unsecure.create_perm_set_permissions()` - Now clears cache for all users with this perm_set
- `unsecure.delete_perm_set_permissions()` - Now clears cache for all users with this perm_set

**Impact:** Users now see permission changes immediately instead of waiting 15-300 seconds for cache expiry.

### Changed

#### Soft Invalidation Strategy for Group/PermSet Operations
For large-scale cache invalidation (groups and permission sets), the system now uses "soft invalidation" instead of DELETE:

```sql
-- Before: Hard DELETE (caused index rebalancing, slow for large datasets)
DELETE FROM auth.user_permission_cache WHERE user_id IN (SELECT ...);

-- After: Soft invalidation (UPDATE expiration_date, ~5-10x faster)
UPDATE auth.user_permission_cache
SET expiration_date = now(), updated_by = _deleted_by, updated_at = now()
WHERE user_id IN (SELECT ...);
```

**Functions using soft invalidation:**
- `unsecure.invalidate_group_members_permission_cache()` - For group membership changes
- `unsecure.invalidate_perm_set_users_permission_cache()` - For permission set changes

**Why this works:** `has_permissions()` checks `expiration_date > now()` before using cache. If expired, it calls `recalculate_user_permissions()`. The next permission check triggers immediate recalculation.

**Benefits:**
- ~5-10x faster than DELETE (no index rebalancing)
- No transaction blocking from mass row deletions
- Cache rows ready for reuse (no INSERT overhead on recalc)
- Scales well for large deployments (100+ groups × 1000+ members)

**Individual user cache** (`clear_permission_cache`) still uses DELETE since it only affects one user's rows where the performance difference is negligible.

#### Disabled/Locked Users Now Blocked from Permission Checks
- `unsecure.recalculate_user_permissions()` now validates user is active and not locked
- `auth.disable_user()` and `auth.lock_user()` now clear permission cache for all tenants
- Previously, disabled/locked users could still pass permission checks until cache expired

**Impact:** Disabled or locked users are immediately blocked from all permission-protected operations.

### Added

#### Outbound API Key Support
New capability to store credentials for calling external services (SendGrid, Slack, Azure, etc.):

**Table Changes (`auth.api_key`):**
| Column | Type | Description |
|--------|------|-------------|
| `key_type` | text | `'inbound'` (default) or `'outbound'` |
| `encrypted_secret` | bytea | Pre-encrypted secret (application-side encryption) |
| `service_code` | text | Service identifier (e.g., `'sendgrid'`, `'slack'`) |
| `service_url` | text | Service endpoint URL |
| `extra_data` | jsonb | Extra headers, config, etc. |

**Security Model:**
- Encryption/decryption handled by application layer
- Database stores pre-encrypted `bytea` data (no pg_crypto required)
- Separate permission `api_keys.read_outbound_secret` for retrieving secrets

**New Functions:**
| Function | Description |
|----------|-------------|
| `auth.create_outbound_api_key` | Create outbound key with encrypted secret |
| `auth.get_outbound_api_key` | Get outbound key by service code |
| `auth.get_outbound_api_key_by_id` | Get outbound key by ID |
| `auth.get_outbound_api_key_secret` | Retrieve encrypted secret (requires special permission) |
| `auth.get_outbound_api_key_secret_by_id` | Retrieve encrypted secret by ID |
| `auth.update_outbound_api_key` | Update metadata (not secret) |
| `auth.update_outbound_api_key_secret` | Rotate encrypted secret |
| `auth.search_outbound_api_keys` | Search outbound keys |
| `auth.delete_outbound_api_key` | Delete outbound key |

**Example Usage:**
```sql
-- Create outbound key (app encrypts 'my-sendgrid-key' → bytea)
SELECT auth.create_outbound_api_key(
    'admin', 1, 'SendGrid API', 'Email service',
    _service_code := 'sendgrid',
    _encrypted_secret := '\x...'::bytea,  -- Pre-encrypted by app
    _service_url := 'https://api.sendgrid.com',
    _extra_data := '{"headers": {"X-Custom": "value"}}'::jsonb,
    _tenant_id := 1
);

-- Retrieve encrypted secret (app decrypts result)
SELECT auth.get_outbound_api_key_secret('admin', 1, 'sendgrid', 1);
```

#### New Helper Functions
| Function | Description |
|----------|-------------|
| `unsecure.invalidate_group_members_permission_cache` | Invalidates permission cache for all members of a group |
| `unsecure.invalidate_perm_set_users_permission_cache` | Invalidates permission cache for all users with a specific perm_set |
| `unsecure.verify_owner_or_permission` | Validates user is owner or has appropriate permission (consolidates duplicate code) |
| `error.raise_33004(bigint)` | Overload for locked user error that accepts user_id instead of email |

#### New Permissions
| Permission Code | Description |
|-----------------|-------------|
| `api_keys.read_outbound_secret` | Required to retrieve encrypted secrets for outbound API keys |

### Changed

#### Enhanced clear_permission_cache
- `unsecure.clear_permission_cache()` now accepts NULL for `_tenant_id` parameter
- When NULL, clears cache for ALL tenants (used when user is locked/disabled)
- Default changed from 1 to NULL for broader utility

#### Parameter Validation in assign_permission
- `unsecure.assign_permission()` now throws error `22023` (invalid_parameter_value) if both `_user_group_id` AND `_target_user_id` are provided
- Previously the function silently used whichever parameter was non-null first, which was ambiguous

#### Provider Validation in recalculate_user_groups
- `unsecure.recalculate_user_groups()` now validates that `_provider_code` exists before proceeding
- Previously a non-existent provider code would silently result in NULL arrays, which would incorrectly clear all external group memberships

#### Refactored Owner Functions
- `auth.create_owner()` and `auth.delete_owner()` now use `unsecure.verify_owner_or_permission()` helper
- Eliminates code duplication between these functions

---

## 2026-02-11

### Added

#### Search/Paging Functions
New search functions with offset-based pagination for all auth entities:

| Function | Description |
|----------|-------------|
| `auth.search_users` | Search users with filters for user_type, is_active, is_locked |
| `auth.search_user_groups` | Search groups with member counts |
| `auth.search_tenants` | Search tenants |
| `auth.search_permissions` | Search permissions with parent_code filtering |
| `auth.search_perm_sets` | Search permission sets with permission counts |

All search functions support:
- Text search on `nrm_search_data` column using LIKE pattern matching
- Pagination via `_page` and `_page_size` parameters
- `total_items` count via window function

#### New Group Function
- `auth.set_user_group_as_internal` - Convert hybrid/external group back to internal-only (complement to `set_user_group_as_external` and `set_user_group_as_hybrid`)

#### New Permissions
| Permission Code | Description |
|-----------------|-------------|
| `users.read_users` | Required for `search_users` |
| `tenants.read_tenants` | Required for `search_tenants` |
| `tenants.delete_tenant` | Required for tenant deletion |
| `permissions.read_permissions` | Required for `search_permissions` |
| `permissions.read_perm_sets` | Required for `search_perm_sets` |

#### Schema Updates
Added `nrm_search_data` columns with GIN indexes for trigram search to:
- `auth.tenant`
- `auth.user_group`
- `auth.permission`
- `auth.perm_set`
- `auth.api_key`

Added trigger functions in `017_functions_triggers.sql` to auto-populate search data on INSERT/UPDATE.

### Changed

#### Parameter Naming Fix
- `auth.delete_user_group_mapping`: renamed `_ug_mapping_id` → `_user_group_mapping_id` for consistency

---

## 2026-02-10

### Breaking Changes

#### Removed Template Table Inheritance
- **Removed** `public._template_created` and `public._template_timestamps` template tables
- **Removed** PostgreSQL table inheritance (`INHERITS` clause) from all tables
- Tables now have explicit `created_at`, `created_by`, `updated_at`, `updated_by` columns
- **Reason**: PostgreSQL table inheritance caused slow DELETE operations due to engine scanning all child tables

#### Column Renames
- `created` → `created_at` (timestamp column, for clarity)
- `modified` → `updated_at` (timestamp column, consistent naming)
- `modified_by` → `updated_by` (text column, consistent naming)
- `created_by` remains unchanged

#### Journal Table Restructure
- **Removed** columns: `message`, `nrm_search_data`, `data_group`, `data_object_id`, `data_object_code`
- **Added** `keys` JSONB column for multi-key support
- **Added** `data_payload` JSONB column for template values and extra data
- **Added** foreign key from `event_id` to `const.event_code`
- **Added** `primary key` constraint to `journal_id`

Messages are no longer stored directly - they're resolved at display time from templates:
```sql
-- Store entry with template values
INSERT INTO journal (tenant_id, event_id, keys, data_payload)
VALUES (1, 10001, '{"user": 123}', '{"username": "john", "actor": "admin"}');

-- Query by any key
SELECT * FROM journal WHERE keys @> '{"user": 123}';

-- Message resolved at display time:
-- Template: 'User "{username}" was created by {actor}'
-- Result:   'User "john" was created by admin'
```

#### Message Template System
- **Added** `const.event_message` table for i18n message templates
- Messages use `{placeholder}` syntax filled from `data_payload` at display time
- Supports multiple languages per event code
- Eliminates redundant storage of identical messages

#### New Journal Functions
Replaced `add_journal_msg` with new `create_journal_message` functions (no `_msg` parameter - messages come from templates):

```sql
-- Option 1: Using event_id with keys and payload
SELECT * FROM create_journal_message(
    'admin',                                    -- created_by
    1,                                          -- user_id
    10001,                                      -- event_id (user_created)
    '{"user": 123}'::jsonb,                     -- keys
    '{"username": "john", "actor": "admin"}'::jsonb,  -- payload for template
    1                                           -- tenant_id
);

-- Option 2: Using event code string
SELECT * FROM create_journal_message(
    'admin', 1, 'user_created',
    _keys := '{"user": 123}'::jsonb,
    _payload := '{"username": "john"}'::jsonb
);

-- Option 3: Single entity convenience
SELECT * FROM create_journal_message(
    'admin', 1, 'group_created',
    'group', 456,  -- entity_type, entity_id -> keys: {"group": 456}
    '{"group_title": "Admins"}'::jsonb
);

-- Search by event category (for UI filtering)
SELECT * FROM search_journal(
    _user_id := 1,
    _event_category := 'user_event',
    _keys_criteria := '{"user": 123}'::jsonb
);

-- Get entry with resolved message
SELECT * FROM get_journal_entry(1, 1, 123);
-- Returns __message: 'User "john" was created by admin'
```

**New functions:**
- `create_journal_message()` - Core function with multiple overloads (no message param)
- `journal_keys()` - Helper to build keys JSONB from variadic pairs
- `format_journal_message()` - Resolve template placeholders from payload
- `get_event_message_template()` - Get template for event in specified language
- `search_journal()` - Search with event category support, returns resolved messages
- `get_journal_entry()` - Get single entry with resolved message

**Legacy compatibility:** `add_journal_msg` and `add_journal_msg_jsonb` still work as wrappers.

#### New Event/Error Code Ranges
Old 50xxx/52xxx codes have been reorganized into clear ranges:

| Range | Category | Description |
|-------|----------|-------------|
| 10001-10999 | User Events | Login, logout, password change, identity management |
| 11001-11999 | Tenant Events | Created, updated, deleted, user access changes |
| 12001-12999 | Permission Events | Assigned, revoked, permission set management |
| 13001-13999 | Group Events | Member added/removed, mapping changes |
| 14001-14999 | API Key Events | Created, updated, deleted, validation |
| 15001-15999 | Token Events | Created, used, expired, failed |
| 30001-30999 | Security Errors | API key/token validation failures |
| 31001-31999 | Validation Errors | Missing required parameters |
| 32001-32999 | Permission Errors | Permission not found, not assignable |
| 33001-33999 | User/Group Errors | User/group not found, not active, system entity |
| 34001-34999 | Tenant Errors | No tenant access |
| 50000+ | Reserved | Application-specific events and errors |

**Backwards Compatibility**: Old `error.raise_52xxx()` functions are preserved as aliases to new `error.raise_3xxxx()` functions.

### Added

#### New Event Code Tables
- `const.event_category` - Event category definitions with ranges
- `const.event_code` - Individual event/error code definitions
- `const.event_message` - Message templates per event_id and language_code

#### New Error Functions (30xxx series)
Security/Auth Errors:
- `error.raise_30001` - API key/secret invalid
- `error.raise_30002` - Token invalid or expired
- `error.raise_30003` - Token belongs to different user
- `error.raise_30004` - Token already used
- `error.raise_30005` - Token not found

Validation Errors:
- `error.raise_31001` - Either group or user required
- `error.raise_31002` - Either perm set or permission required
- `error.raise_31003` - Either permission id or code required
- `error.raise_31004` - Either mapping id or role required

Permission Errors:
- `error.raise_32001` - No permission
- `error.raise_32002` - Permission not found
- `error.raise_32003` - Permission not assignable
- `error.raise_32004` - Permission set not found
- `error.raise_32005` - Permission set not assignable
- `error.raise_32006` - Permission set wrong tenant
- `error.raise_32007` - Parent permission not found
- `error.raise_32008` - Some permissions not assignable

User/Group Errors:
- `error.raise_33001` - User not found
- `error.raise_33002` - User is system
- `error.raise_33003` - User not active
- `error.raise_33004` - User locked
- `error.raise_33005` - User cannot login
- `error.raise_33006` - User no email provider
- `error.raise_33007` - Identity already used
- `error.raise_33008` - Identity not active
- `error.raise_33009` - Identity not found
- `error.raise_33010` - Provider not active
- `error.raise_33011` - Group not found
- `error.raise_33012` - Group not active
- `error.raise_33013` - Group not assignable
- `error.raise_33014` - Group is system
- `error.raise_33015` - Not owner

Tenant Errors:
- `error.raise_34001` - No tenant access

### Changed

#### File Structure Reorganization
Consolidated migration files into modular structure:

| File | Contents |
|------|----------|
| `001_create_basic_structure.sql` | Schemas and extensions |
| `002_create_version_management.sql` | Version tracking system |
| `004_create_helpers.sql` | Helper functions |
| `005-009_update_common-helpers_v1-x.sql` | Helper updates |
| `010_functions_auth_prereq.sql` | Auth prerequisite functions |
| `012_tables_const.sql` | Constant/lookup tables |
| `013_tables_auth.sql` | Auth schema tables |
| `014_tables_stage.sql` | Stage tables and journal |
| `015_views.sql` | Database views |
| `016_functions_error.sql` | Error functions |
| `017_functions_triggers.sql` | Trigger functions |
| `018_functions_public.sql` | Public schema functions |
| `019_functions_unsecure.sql` | Unsecure schema functions |
| `020-028_functions_auth_*.sql` | Auth schema functions |
| `029_seed_data.sql` | Initial data inserts |
| `099_fix_permissions.sql` | Permission grants |

#### Schema Resolution
- All SQL files now include `set search_path = public, const, ext, stage, helpers, internal, unsecure, auth, triggers;`
- Enables each file to be executed independently by debee
- Removes need for `ext.` prefix on ltree, uuid_generate_v4(), etc.

### Fixed

- **tenant uuid unique index** - Moved to immediately after tenant table creation (before user_permission_cache references it)
- **Journal table dependencies** - Moved journal table to after auth tables are created
- **COST 0 error** - Changed `cost 0` to `cost 1` in helper functions (COST must be positive)

### Migration Guide

#### From v1.x to v2.0

1. **Database Recreation Required**: v2 is not an incremental update. Backup data and recreate:
   ```powershell
   ./debee.ps1 -Operations fullService
   ```

2. **Error Code Updates** (if using directly):
   - Old: `error.raise_52103(_user_id)`
   - New: `error.raise_33001(_user_id, _email)`
   - Aliases are provided for backwards compatibility

3. **Event Code Updates** (if querying journal):
   - Old event codes (50xxx) mapped to new codes (10xxx)
   - Query `const.event_code` for new event definitions

4. **Column Renames** (if accessing tables directly):
   - `created` → `created_at`
   - `modified` → `updated_at`
   - `modified_by` → `updated_by`
   - `created_by` remains unchanged

5. **Journal Function Updates**:
   - Old: `add_journal_msg(_created_by, _user_id, _msg, 'group', 123, _event_id := 50123)`
   - New: `create_journal_message(_created_by, _user_id, 13001, 'group', 123, '{"group_title": "Admins"}'::jsonb)`
   - Messages no longer stored - resolved from `const.event_message` templates at display time
   - Legacy `add_journal_msg` functions still work (message stored in `data_payload._legacy_msg`)

---

## Pre-v2 (legacy)

See git history for v1.x changes.

---

## Version History

Rows marked 2.0.0 are work inside `postgresql_permissionmodel` **v2**, recorded as a single row in `public.__version` dated 2026-02-10 (see `010_functions_auth_prereq.sql`). From 2.1 on, each update ships as its own numbered update script (`048_update_permissions_v2-1.sql`, …) with its own `public.__version` row. The table is a quick chronological glance over what shipped when; full detail lives in the date-tagged sections above.

| Version | Date | Description |
|---------|------|-------------|
| 2.1 | 2026-10-26 | Security: `is_owner` null-group, tenant-scoped assign/unassign_permission and group mapping writers, API key expiry; `get_tenant_groups` columns; `*_as_system` group helpers (`048_update_permissions_v2-1.sql`) |
| 2.0.0 | 2026-06-18 | Partial-key grants/denies on resource_access (subset key validation, containment-based matching in `has_resource_access`) |
| 2.0.0 | 2026-04-17 | Path-based resource access (ltree) with cascading grants and deny-overrides; icons example demo |
| 2.0.0 | 2026-04-12 | Resource roles (named flag bundles); translation `context` column + `mv_translation` materialized view; `user_data` jsonb columns (`settings`, `preferences`, `custom_data`) |
| 2.0.0 | 2026-03-10 | Unified `_search_criteria jsonb` across 12 search/audit functions; multi-tenant columns on group queries |
| 2.0.0 | 2026-03-09 | `resolve_cross_tenant_access` + `resolve_user/tenant/group` helpers; `add_*` → `create_*`/`assign_*` renames |
| 2.0.0 | 2026-03-09 | Tenant isolation + cross-tenant data access pattern; 13 new `read_all_*` permissions; 21 functions updated |
| 2.0.0 | 2026-03-07 | Invitation system (generic, templated, phased actions with conditional execution) |
| 2.0.0 | 2026-03-07 | `is_verified` on `user_identity`; MFA permissions auto-assigned to existing perm sets |
| 2.0.0 | 2026-03-05 | Single-call email/password verification (`auth.verify_user_by_email`) |
| 2.0.0 | 2026-03-04 | MFA challenge failures now count toward auto-lockout |
| 2.0.0 | 2026-03-04 | MFA recovery code reset (`auth.reset_mfa`); MFA policy (`auth.mfa_policy`) with scope-based resolution |
| 2.0.0 | 2026-03-04 | Auto-lockout on repeated login failures; Multi-Factor Authentication (TOTP) |
| 2.0.0 | 2026-03-02 | User blacklist for deleted users (`auth.user_blacklist`) |
| 2.0.0 | 2026-03-02 | Bulk ensure functions for app bootstrapping, `_is_final_state` declarative sync, `source` column on user_group |
| 2.0.0 | 2026-03-01 | Event ID collision fix, column renames, Makefile debee migration |
| 2.0.0 | 2026-02-28 | Resource access (ACL) system, provider capability flags |
| 2.0.0 | 2026-02-28 | User group caching, hierarchical resource access |
| 2.0.0 | 2026-02-26 | Search function fixes, group member tenant functions |
| 2.0.0 | 2026-02-26 | Event code management, audit partitioning, storage modes |
| 2.0.0 | 2026-02-23 | Request context tracking, user events for registration/login |
| 2.0.0 | 2026-02-22 | User event system, registration/login bug fixes |
| 2.0.0 | 2026-02-21 | Audit infrastructure, composable admin permission sets, ensure_provider, bug fixes |
| 2.0.0 | 2026-02-21 | Dedicated service accounts with least-privilege permissions, missing permission seed fixes |
| 2.0.0 | 2026-02-20 | Real-time LISTEN/NOTIFY notifications, cache invalidation gap fixes |
| 2.0.0 | 2026-02-14 | Code generator compatibility: unique journal function names, throw_no_permission moved to internal |
| 2.0.0 | 2026-02-14 | Hierarchical numeric permission codes, language & translation system, colored test output |
| 2.0.0 | 2026-02-12 | Correlation ID tracing, consolidate seed data |
| 2.0.0 | 2026-02-11 | Cache invalidation fixes, soft invalidation strategy, parameter validation |
| 2.0.0 | 2026-02-11 | Search/paging functions, set_user_group_as_internal |
| 2.0.0 | 2026-02-10 | Major restructure: removed inheritance, new event codes |
| 1.16  | —          | API key tenant_id fix (legacy) |
| 1.0–1.15 | —       | Incremental feature additions (legacy) |

Other component tracks recorded in `public.__version`: `common_helpers` 1.0–1.6 (per file in `004`–`013`); historic `keen_auth_permissions` 1.0–1.15 and `versions_management` 1.0–1.2 (folded into canonical files; scripts live in `old/`).
