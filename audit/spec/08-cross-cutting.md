# 08 - Cross-cutting

Rules that apply to every domain: the trust model and schema boundaries, privileges and
`search_path`, the user-1 shortcut, the error model, the audit trail, real-time notifications,
the public API contract, version management, null/empty input and concurrency.

Rules marked **[confirm]** come from the code (or from common sense where code and docs are
silent) rather than from docs, tests or the changelog. The owner must confirm or rewrite them.

## Scope

| Area | Objects (latest definition, per db-objects.md) |
|---|---|
| Schemas, roles, grants | `001_create_basic_structure.sql` (schemas, extensions in `ext`), `000_create_database.sql` (app role = DB owner), `99_fix_permissions.sql` (post-update script from `debee.env` `DBPOSTUPDATESCRIPTS`: DB/role `search_path`, table/sequence/schema grants, `REASSIGN OWNED`), `099_fix_permissions.sql` (older, partial copy picked up as a migration) |
| Permission check entry points | `auth.has_permissions` `022:63`, `auth.has_permission` `022:144`, `internal.throw_no_permission` `022:23-60` (4 overloads), `auth.throw_no_access` `022:13`, `internal.resolve_cross_tenant_access` `019:48` |
| Error model | `error.raise_3xxxx` `016_functions_error.sql` (+ `030`, `036`, `039`, `041`, `043`, `048:57-79`), legacy aliases `error.raise_52xxx` `016:688-743`, `const.event_category` `011:91`, `const.event_code` `011:100`, `const.event_message` `030:198`, `public.create/delete_event_category/code/message` `018:657-873` |
| Audit | `public.journal` `014:49`, `auth.user_event` `013:397`, `public.create_journal_message*` `018:202-334`, `unsecure.create_user_event` `019:518`, `auth.create_user_event` `028:13`, `auth.search_user_events` `028:34`, `auth.get_user_audit_trail` `028:125`, `auth.get_security_events` `028:236`, `public.search_journal` `018:552`, `public.get_journal_entry` `018:368`, `public.purge_audit_data` `018:986`, `helpers.should_log_journal` `012:39`, `helpers.is_event_read_only` `012:59`, `helpers.should_store_locally/should_notify_storage` `012:84/97` |
| Notifications | `unsecure.notify_permission_change` `019:327`, `unsecure.notify_journal_event` `019:359`, `unsecure.notify_user_event` `019:401`, `triggers.notify_*` + `trg_notify_*` `033:176-568`, resolution views `auth.notify_*_users` `015:94-175` |
| Version management | `public.__version` + `uq_version` `002:12/23`, `public.start_version_update` `018:13`, `public.stop_version_update` `018:32`, `public.check_version` `049:23` (2-arg overload dropped in v2.2), `public.get_version` `018:525` |
| System params | `auth.get_sys_param` `018:63`, `auth.update_sys_param` `018:80`, `const.sys_param` |

## Actors & preconditions

- **Application role** (`postgresql_permissionmodel`): the only non-superuser role that connects. It
  owns every object and has full DML on every table. It passes `_user_id`, `_tenant_id`,
  `_correlation_id` and `_request_context` on each call. The database does not authenticate
  these values; it trusts the application to pass the real caller.
- **System user** (`user_id = 1`): seed data and migrations only.
- **Service accounts** (`user_id` 2-6, 800): what the backend passes at runtime (registrator,
  authenticator, token manager, API gateway, group syncer, data processor).
- **End users / admins** (`user_id >= 1000`), acting in their own tenant or in tenant 1 (admin console).
- **API key technical users**: same as end users for every check.
- **Migration runner** (`debee`, as `postgres` or the app role): runs `NNN_*.sql` and the post-update script.
- **Backend listener**: a dedicated connection that LISTENs on `permission_changes`, `journal_events` and `user_events`.

## Invariants

### A. Trust model and schema boundaries

- **I-08-01** The database trusts the caller-supplied `_user_id`/`_tenant_id`. Permission checks guard against a buggy or misrouted application call. They do not guard against a compromised application role, which has direct DML on every table. Source: docs/concepts/schemas.md ("application layer where authorization is handled externally"), `99_fix_permissions.sql:16` **[confirm]**
- **I-08-02** Every `auth.*` and `public.*` function that returns tenant, user or security data, or changes any state, checks authorization first through `auth.has_permission(s)`, `internal.resolve_cross_tenant_access`, `unsecure.verify_owner_or_permission` or a documented self-service rule. Source: CLAUDE.md "Key Security Principle", docs/concepts/schemas.md "Key Principles" #1
- **I-08-03** The only `auth.*`/`public.*` functions allowed to skip a permission check are the documented ones:
  - core checks (`has_permission(s)`, `has_resource_access`, `filter_accessible_resources`)
  - the provider login flow (`ensure_user_info`, `ensure_user_from_provider`, `get_user_by_provider_oid`)
  - audit writes (`create_user_event`, `create_journal_message*`)
  - read-only utilities (`is_group_member`, `can_manage_user_group`, `has_owner`, `is_owner`, `is_blacklisted`, resource metadata getters)
  - pure utilities (`throw_no_access`, `generate_api_key*`, `seed_permission_data`)
  - external group sync (`process_external_group_member_sync*`)
  - version management (`start/stop_version_update`, `check_version`, `get_version`)
  - `get_tenant_by_id`, `get_all_tenants`, `get_user_by_id`
  - event-code management (`public.create/delete_event_*`)
  - journal formatting helpers (`journal_keys`, `format_journal_message`, `get_event_message_template`)

  Any other unchecked function is a finding. Source: docs/reference/permission-matrix.md "Unchecked Functions" + rows marked None, docs/reference/audit-events.md "Permission Summary", docs/reference/tenants.md:170-190
- **I-08-04** The unchecked functions without a documented rationale must be justified or given a check: `public.get_permissions_map`, `public.get_token_types`, `public.get_language(s)`, `public.get_*_languages`, `public.get_default_language`, `public.get_group_translations`, `auth.get_sys_param`, `auth.ensure_provider`, `auth.ensure_user_group_mapping`, `auth.set_token_as_used_by_token`, `auth.set_token_as_failed_by_token`, `auth.get_api_key_permissions`. The last five reach a check only through a function they delegate to. Source: code (pg_proc scan) **[confirm]**
- **I-08-05** The check runs before any side effect: no row write, journal entry, `pg_notify` or cache write happens before an unauthorized call is rejected. One exception: a cache recalculation for the caller. Source: docs/concepts/schemas.md example (check first, then delegate) **[confirm]**
- **I-08-06** `internal.*` functions contain no permission checks. They are called only from `auth/public` functions after the check, or from app code that authorized the request itself. Source: docs/concepts/schemas.md "internal"
- **I-08-07** `unsecure.*` holds only security-system internals (cache, notify, permission/user/group CRUD internals, bootstrap). No business logic goes there. Outside the model's own `auth.*` functions it is called only by seed/migration scripts and maintenance (`unsecure.clear_permission_cache`). Source: docs/concepts/schemas.md "unsecure"
- **I-08-08** `helpers`, `error`, `const`, `ext`, `stage` and `triggers` make no authorization decisions. Source: docs/concepts/schemas.md "Utility schemas are neutral"

### B. Privileges, SECURITY DEFINER, search_path

- **I-08-09** No model function is `SECURITY DEFINER`. All run as the invoker (the app role), so no function can be used to gain privileges the calling role lacks. Source: code (no `security definer` in `001`-`050`; pg_proc `prosecdef` = 0) **[confirm]**
- **I-08-10** If a `SECURITY DEFINER` function is ever added, it must pin `set search_path` to trusted schemas, schema-qualify every reference, and `revoke execute ... from public`. Source: PostgreSQL security guidance **[confirm]**
- **I-08-11** Only the app role (and superusers) has `USAGE` on `auth`, `internal`, `unsecure`, `const`, `error`, `helpers`, `ext`, `stage` and `triggers`. `PUBLIC` has none of them. Because `EXECUTE` on functions defaults to `PUBLIC`, schema `USAGE` is the only barrier in front of `unsecure.*`/`internal.*`. Source: `99_fix_permissions.sql:18`, live `pg_namespace.nspacl` **[confirm]**
- **I-08-12** No role other than the owner has `CREATE` on any schema in the configured `search_path` (`public, const, ext, stage, helpers, internal, unsecure, auth, triggers`). Otherwise a role could shadow an unqualified function or table name. Source: `99_fix_permissions.sql:1-3`, PostgreSQL security guidance **[confirm]**
- **I-08-13** Every function either pins `set search_path` or schema-qualifies every model object it references. Correctness must not depend on the session `search_path`. Source: CLAUDE.md "Always use fully qualified schema names", CHANGELOG (`create_journal_message*` calls schema-qualified)
- **I-08-14** There is one authoritative post-update grant/ownership script. Running migrations must leave every model object owned by the app role, and the app role must have `select/insert/update/delete` on all model tables and `usage/select` on all sequences. Source: `debee.env` `DBPOSTUPDATESCRIPTS=./99_fix_permissions.sql`, `99_fix_permissions.sql:16-67` **[confirm]**

### C. The user-1 shortcut and owner bypass

- **I-08-15** `user_id = 1` is the `system` user: `user_type_code = 'system'`, `is_system = true`, `can_login = false`. Source: docs/concepts/service-accounts.md, CHANGELOG ("System user (id=1) was not marked is_system")
- **I-08-16** `auth.has_permission(s)` returns `true` for `user_id = 1` without looking at tenant, permission code, cache or ownership. Source: docs/concepts/service-accounts.md, docs/concepts/permission-model.md:217
- **I-08-17** The resource-access checks also grant user 1 everything, but only after input validation: a missing identifier still raises 35010 for user 1. Source: CHANGELOG (read-side validation runs before the user-1 shortcut), error-codes.md 35010
- **I-08-18** The only places that branch on `_user_id = 1` are `auth.has_permissions`, the resource-access check functions (`035`) and the `auth.update_sys_param` restriction. No other function grants anything because the caller is user 1. Source: code `022:74`, `035:176/339/519/658`, `018:94` **[confirm]**
- **I-08-19** User 1 can't be locked, disabled, deleted or blacklisted, and can't sign in through any provider. Attempts raise 33002. Source: error-codes.md 33002, CHANGELOG (blacklist prevents system users), service-accounts.md (`can_login = false`) **[confirm]** for lock/disable/delete
- **I-08-20** User IDs 1-999 are reserved for system and service accounts. The `user_info` sequence starts regular users at 1000. Source: docs/concepts/service-accounts.md:3,27
- **I-08-21** Runtime callers never pass `_user_id = 1`. Backends use the service accounts. Source: docs/concepts/service-accounts.md "Never use user_id 1 at runtime"
- **I-08-22** Tenant owners pass every permission check, but only in the tenant they own. A group owner is not a tenant owner (fixed in v2.1). Ownership of tenant X grants nothing in tenant Y or in tenant 1. Source: docs/reference/permission-matrix.md tip, CHANGELOG v2.1 (`is_owner` null group). Details are in specs 04/05.
- **I-08-23** Security tests run as a dedicated non-system user with an explicit perm set, include a second tenant, and assert returned column values. Source: CLAUDE.md "Test-writing rule"

### D. Error model

- **I-08-24** Code ranges:
  - 10000-29999: informational events (journal and user_event)
  - 30000-39999: library errors, raised as SQLSTATE
  - 50000+: application codes

  The "50001-52999" ranges in CLAUDE.md and the "30xxx-37xxx" statement in docs/concepts/schemas.md are out of date. Source: error-codes.md, `011_tables_const.sql:60-87`
- **I-08-25** Every library error is raised with its 5-digit code as SQLSTATE through `error.raise_NNNNN`, or through a documented inline raise (35005-35010). Generic SQLSTATEs (`P0001`, `22000`, `22023`, `02000`, `42501`) are not used for conditions a caller must tell apart. Source: error-codes.md intro **[confirm]** for the generic-SQLSTATE part
- **I-08-26** Every error code that can be raised exists in `const.event_code` (`is_system = true`, in a category with `is_error = true` whose range contains it) and has an active `'en'` row in `const.event_message`. Source: error-codes.md ("All errors are seeded in const.event_code with matching templates in const.event_message")
- **I-08-27** Each legacy `error.raise_52xxx` alias raises exactly the current code given in the legacy mapping table. No alias raises a 52xxx SQLSTATE. Source: docs/codes.md:379-424, `016:688-743`
- **I-08-28** Canonical codes:
  - permission denied: 32001
  - unknown user: 33001
  - user is system: 33002
  - cross-tenant filter from a non-admin tenant: 34002
  - no tenant access: 34001
  - either-or parameter missing: 31001-31004

  Source: error-codes.md
- **I-08-29** Event codes are protected by:
  - `is_system` codes and messages can't be changed or deleted (31010)
  - a category that still has codes can't be deleted (31012)
  - an event id must fall inside its category's range (31013)
  - unknown code: 31011; unknown category: 31014
  - deleting a code cascades to its messages

  Source: test `test_event_code_management`
- **I-08-30** An update script that adds an error code inserts the `const.event_code` and `const.event_message` rows (`on conflict do nothing`), creates the `error.raise_*` function and documents the code in error-codes.md. Source: CLAUDE.md "SQL Migration Files"

### E. Audit trail

- **I-08-31** Every state-changing `auth/public` operation writes, in the same transaction, a journal entry with:
  - `created_by`
  - `user_id` = the actor
  - `correlation_id`
  - `tenant_id` = the tenant acted in
  - an informational `event_id`
  - `keys` that reference the affected entity

  Source: docs/codes.md:19 ("recorded whenever a state-changing operation occurs"), docs/concepts/audit-notifications.md
- **I-08-32** Authentication and account-security operations also write `auth.user_event`, with `event_type_code`, `requester_user_id`, `target_user_id`, `correlation_id` and `request_context`. These operations are: login success/failure, lock/unlock, enable/disable of user or identity, password change, API key validation, MFA and token use. Source: docs/concepts/audit-notifications.md "User Events", docs/reference/api-keys.md:282
- **I-08-33** The `_correlation_id` a function receives is stored unchanged on every journal and user_event row the call creates, including rows from nested calls. `null` is stored as `null`. Source: test `test_correlation_id`, docs/concepts/audit-notifications.md "Correlation IDs"
- **I-08-34** The `_request_context` a function receives is stored unchanged in `request_context` on the rows the call creates. Source: docs/concepts/audit-notifications.md "Request Context", test `test_audit_and_user_ops`
- **I-08-35** If `requester_username`/`target_username` are not supplied, they are resolved from `user_info` at write time. They are not overwritten when the user changes or is deleted later. Source: docs/concepts/audit-notifications.md table, `013:397` (`on delete set null` for ids)
- **I-08-36** A permission denial (32001) leaves a durable record with the actor, the requested codes and the tenant, and `auth.get_security_events` can return it. Source: `auth.get_security_events` reads journal 32001 (`028:296-310`), docs/concepts/audit-notifications.md ("permission denials") **[confirm]**. See open question Q-01.
- **I-08-37** The audit write functions (`auth.create_user_event`, `public.create_journal_message*`) never fail for permission reasons. Source: docs/reference/permission-matrix.md ("Audit logging must always succeed")
- **I-08-38** Journal level:
  - `none` writes nothing
  - `update` writes only events with `is_read_only = false`
  - `all`, unset or an unknown value writes everything

  The seeded default is `update`. Source: `012:17-48`, `029_seed_data.sql:61` **[confirm]**. See Q-07 on security events under `none`.
- **I-08-39** Storage mode (`journal.storage_mode`, `user_event.storage_mode`):
  - `local`: insert only
  - `notify`: `pg_notify` only
  - `both`: insert and `pg_notify`

  Notify payloads over 7900 bytes drop `data_payload`/`event_data` and `request_context` and add `"truncated": true`. Source: docs/concepts/audit-notifications.md "Storage Modes"
- **I-08-40** Audit reads follow tenant isolation:
  - from tenant ≠ 1, only rows of the caller's tenant
  - from tenant 1, all tenants only with `read_all_*` / `journal.read_global_journal`

  This applies to `auth.user_event` rows as much as to journal rows. Source: CLAUDE.md multi-tenancy rules, docs/reference/permission-matrix.md (search_user_events / get_user_audit_trail / get_security_events marked "Cross-tenant")
- **I-08-41** `public.get_journal_entry`/`get_journal_payload` return an entry only if it belongs to `_tenant_id`. Source: code `018:406` **[confirm]**
- **I-08-42** No API function updates or deletes individual journal or user_event rows. The only removal path is `public.purge_audit_data`. It needs `journal.purge_journal` (checked in tenant 1) and journals itself as 17001 `audit_data_purged` with the deleted counts. Source: docs/concepts/audit-notifications.md "Purging Old Data" **[confirm]** for append-only

### F. Real-time notifications

- **I-08-43** Each permission-relevant mutation listed in docs/concepts/audit-notifications.md "Notification Events by Category" sends one `pg_notify('permission_changes', …)` per affected row. The payload is `{event, tenant_id, target_type, target_id, detail?, at}`. Source: docs/concepts/audit-notifications.md
- **I-08-44** Notifications come from row triggers on the `auth.*` tables, so every write path sends them: `auth.*` functions, `unsecure.*` functions, cascades and direct DML. Source: `033:1-25` header
- **I-08-45** Payload `tenant_id` is the affected tenant, or `null` when the change is global: user status, provider and permission-tree events. `target_type` is one of `user`, `group`, `perm_set`, `system`, `provider`, `tenant`, `api_key`. Source: docs/concepts/audit-notifications.md "Payload Format"
- **I-08-46** Payloads carry only IDs and codes, never secrets (password hashes, API secrets, token values) or personal data, and stay under 8000 bytes. Source: docs/concepts/audit-notifications.md "Payload size limit"
- **I-08-47** Notifications and audit rows are transactional: they appear if and only if the mutation commits. Source: docs/concepts/audit-notifications.md tip, PostgreSQL NOTIFY semantics
- **I-08-48** Any change that removes access must notify the affected users, or have an explicit documented reason not to. Such changes include identity disable, removal from a tenant, tenant soft delete, perm set delete, permission delete and API key expiry. Source: docs/concepts/audit-notifications.md purpose ("whenever a permission-relevant mutation occurs") **[confirm]**. See Q-08.

### G. Public API contract

- **I-08-49** `auth.*`/`public.*` parameters and return columns use only stock PostgreSQL types and `jsonb`, never `ext.ltree`, `ext.uuid` and the like. UUIDs and paths cross the boundary as `text`. Source: CLAUDE.md "Public API Types". Currently holds (pg_proc scan).
- **I-08-50** `auth/public/internal` functions declare an explicit `returns table(...)`, never `returns setof <table>`, and never expose `nrm_search_data`/`ts_search_data`. Source: CLAUDE.md "No returns setof <table>". Currently holds for `setof`; see Q-10 for whole-row composite returns.
- **I-08-51** Naming:
  - input parameters: `_`
  - locals and return columns: `__`
  - locals that clash with a return column: `___`

  Source: CLAUDE.md "Variable Naming Convention"
- **I-08-52** Mutating functions take `(_created_by|_updated_by|_deleted_by text, _user_id bigint, _correlation_id text, …, _tenant_id integer default 1 [, _request_context jsonb])`. Search functions take `(_user_id, _correlation_id, _search_criteria jsonb, _page, _page_size, _tenant_id, _target_tenant_id)` and return `__total_items` on each row. Source: CHANGELOG ("Unified search function signatures"), docs examples
- **I-08-53** No two overloads of one `auth/public` function may be ambiguous for any documented call shape (the v2.2 `check_version` lesson). Source: CHANGELOG v2.2

### H. Version management

- **I-08-54** `public.__version` has at most one row per `(component, version)` (`uq_version`). `start_version_update` inserts it with `execution_started = now()` and `execution_finished = null`. `stop_version_update` sets `execution_finished`. Source: CLAUDE.md "Version Management", `002:12-23`
- **I-08-55** Re-running an update script that is already applied fails at `start_version_update` before it changes anything. It does not re-apply silently. Source: `uq_version` **[confirm]**
- **I-08-56** `stop_version_update` for a version that was never started raises an error instead of returning an empty set. Source: common sense **[confirm]**
- **I-08-57** Exactly one `public.check_version(_version, _component default 'main', _throw_err default false)` exists. It returns whether the row exists and raises when `_throw_err` is set and the row is missing. Source: CHANGELOG v2.2, `049:23`
- **I-08-58** `public.get_version(_component, _version)` returns only that version when `_version` is given, otherwise only the latest row of the component by `execution_started`. Source: CHANGELOG v2.2 ("Get version detail, by component and by version (or the last one)")
- **I-08-59** Each update script is `NNN_update_permissions_v2-N.sql`, wrapped in `start/stop_version_update('2.N', _component := 'postgresql_permissionmodel')`. Baseline files `010`-`047` and released scripts are never edited. Source: CLAUDE.md

### I. Null and empty input

- **I-08-60** A `null` `_user_id` or `_tenant_id` passed to a permission-checked function is rejected or denied. It is never treated as the system user, tenant 1 or "all tenants". Source: common sense **[confirm]**
- **I-08-61** For optional text filters, an empty or whitespace-only string means the same as `null` (`helpers.is_empty_string`). Source: docs/reference/helpers.md **[confirm]**
- **I-08-62** Paging: `null` `_page` means 1 and `null` `_page_size` means the function default. `_page_size` is capped at 100. `_page < 1` or `_page_size < 1` gives a clean validation error or is clamped, never a raw SQL error. Source: code `028:80-81` **[confirm]**
- **I-08-63** Usernames and emails are stored as `lower(trim(…))`, with the originals in `original_*`. Codes are derived with `helpers.get_code`. Source: CHANGELOG (email normalization)
- **I-08-64** "Either A or B" parameters raise 31001-31004 when both are null or empty. Source: docs/codes.md:245-248

### J. Concurrency

- **I-08-65** Business-key uniqueness is enforced by unique constraints or indexes, not only by a check-then-insert in code. Source: `013:554-660` **[confirm]**
- **I-08-66** Two concurrent calls of the same `ensure_*`/`create_*` either both succeed with one resulting row (idempotent ensure) or one gets a mapped model error code (e.g. 33023). Neither gets a raw `23505`. Source: CHANGELOG v2.1 ("a duplicate raises the new 33023 instead of a raw unique violation") **[confirm]** as a general rule
- **I-08-67** A unique key that has a nullable column treats `null` as a value whenever uniqueness is intended, through `coalesce` or `nulls not distinct`. For example, one tenant-wide owner row per `(user_id, tenant_id)`. Source: code pattern in `uq_permission_assignment`/`uq_user_group_mapping` **[confirm]**
- **I-08-68** Once a revoking transaction commits, no later `has_permission` call returns `true` from a cache computed before the revoke. Source: CLAUDE.md permission cache. Details are in spec 04.

## Flows

**Permission-checked call** (`auth.X(_by, _user_id, _corr, …, _tenant_id)`):
1. Validate input (either-or params, identifier resolution). Bad input raises 31xxx/33020/34003 with no side effects.
2. Run `auth.has_permission(_user_id, _corr, 'code', _tenant_id)`, or `internal.resolve_cross_tenant_access` for reads. On denial, raise 32001; the state is unchanged apart from the 32001 audit record of I-08-36.
3. Delegate to `unsecure.*`/`internal.*`, which write the rows.
4. Row triggers invalidate the cache and queue `pg_notify('permission_changes')`.
5. Write a journal entry, plus a user_event if security-relevant, carrying `_corr`, `_tenant_id` and `_request_context`.
6. Commit: notifications are delivered. Rollback: no rows, no journal, no notifications.

**Audit write** (`public.create_journal_message`):
1. Check the journal level; skip if it filters the event out.
2. If the storage mode is `notify`/`both`, `pg_notify('journal_events')`, truncating over 7900 bytes.
3. If the storage mode is `local`/`both`, insert into the monthly partition (the default partition if none exists).

**Migration** (`debee updateDatabase` then the post-update script):
1. For each `NNN_*.sql` in order:
   - `start_version_update`, which fails if the version is already present
   - DDL and `create or replace`
   - new codes with `on conflict do nothing`
   - `stop_version_update`
2. The post-update `99_fix_permissions.sql` sets the DB/role `search_path`, the grants and the ownership.

## Failure behaviour

| Situation | Expected |
|---|---|
| Caller lacks permission | 32001, no side effects (I-08-05) |
| Non-admin tenant passes `_target_tenant_id` | 34002 |
| Unknown user id passed to a permission check | 33001 (via legacy 52103) |
| Operation targets the system user (lock/disable/delete/blacklist) | 33002 |
| Missing either-or parameter | 31001-31004 |
| `create_journal_message_by_code` with unknown code | dedicated code **[confirm]** (today `22000`) |
| `update_sys_param` by a user other than 1 | today `42501`; a library code is expected **[confirm]** |
| `check_version(..., _throw_err := true)` and the version is missing | today `P0001`; a dedicated code is expected **[confirm]** |
| Re-running an applied update script | `23505` on `uq_version` at `start_version_update` **[confirm]** |
| Modify or delete a system event code/message | 31010; unknown 31011; non-empty category 31012; out of range 31013; unknown category 31014 |
| Duplicate business key under a race | mapped 3xxxx code or idempotent success, never raw `23505` (I-08-66) |

## Open questions

- **Q-01 Permission denials are never persisted.** `auth.has_permissions` journals 32001 and then raises (`022_functions_auth_permission.sql:128-136`). The raise rolls back the journal row, and the `journal_events` notify too, unless the caller catches the exception. With `_throw_err := false` nothing is written at all. So `auth.get_security_events`' "permission denials" branch (`028:296-310`) is empty in practice. Options: persist the denial outside the transaction (not possible in plain PL/pgSQL), stop advertising it, or have callers log it.
- **Q-02 `auth.user_event` has no tenant, so audit reads leak across tenants.** `auth.search_user_events` computes `__effective_tenant_id` (`028:71`) and never uses it (`028:85-94`). The user_event branches of `get_user_audit_trail` (`028:202`) and `get_security_events` (`028:288`) are unfiltered too. A tenant admin with `authentication.read_user_events` sees every tenant's user events. Should `user_event` get a `tenant_id` column, or be filtered through the target user's tenant membership?
- **Q-03 `internal.resolve_cross_tenant_access` checks `read_all_*` in `_target_tenant_id`, not in tenant 1** (`019:65`). A user who holds a `read_all_*` permission in tenant X, or owns X (owner bypass), passes `_tenant_id = 1, _target_tenant_id = X` without any rights in tenant 1. A `null` `_tenant_id` falls through to the "own tenant" branch with a null tenant (`019:62-74`). Intended?
- **Q-04 Error codes missing from `const.event_code`/`event_message`.** Codes 34004-34007 are raised (`016:600-650`, used in `023:181/461`) but are not seeded in `const.event_code` and not listed in error-codes.md. These codes have no `const.event_message` row at all: 30001-30005, 31001-31004, 32001-32008, 33001-33015, 34001-34002, 37001-37002 and 38001-38007 (live DB query). Both contradict error-codes.md ("All errors are seeded … with matching templates").
- **Q-05 Docs disagree on code ranges and the `has_permission` signature.** CLAUDE.md "Error Codes" says 50001-52999 and refers to `readme.md:16-124`. docs/concepts/schemas.md says "30xxx-37xxx" (38xxx and 39xxx exist). CLAUDE.md also shows `auth.has_permission(_tenant_id, _user_id, _perm_code, _throw_err)`; the real order is `(_target_user_id, _correlation_id, _perm_code, _tenant_id, _throw_err)` (`022:144`).
- **Q-06 Unqualified object references depend on the session `search_path`.** Examples: `018:26,45` (`__version`), `018:246,406,607` (`journal`), `018:512,532` and `028:173` (`format_journal_message`, `get_event_message_template`). Only six functions pin `search_path` (`020:983`, `021:375,1067`, `022:848,921`, `023:594`). Should the rest be qualified, or pin `search_path` (I-08-13)?
- **Q-07 Can `journal.level = 'none'` (or `notify` storage) switch off security-relevant journaling** (32001, ownership and assignment changes)? Should a minimum set of events bypass the level? The comment at `012:25` says `update` is the default, while the code default for unset/unknown is `all` (`012:46`).
- **Q-08 Notification gaps.** `033` has no trigger for:
  - `auth.user_identity` (identity disable, last-used provider change)
  - `auth.tenant_user` (user removed from tenant)
  - tenant soft delete (an update; `033:417` fires only on purge)
  - `auth.perm_set` delete (`033:547` is update-only)
  - `auth.permission` delete
  - API key expiry or secret rotation

  Which of these must notify (I-08-48)?
- **Q-09 `public.get_version` returns the latest version even when `_version` is given.** The `or version_id in (latest)` branch is not guarded by `_version is null` (`018:530-538`), so `get_version('x', '1.1')` returns both 1.1 and the latest row.
- **Q-10 Whole-row composite returns on the API surface.** `auth.get_sys_param`/`auth.update_sys_param` return `const.sys_param` (`018:63-110`), which exposes every physical column the same way `setof <table>` does. `public.validate_token` returns `___`-prefixed columns (`018:433`), against I-08-51. `auth.update_user_data` has two overloads (`020:599`, `020:657`); check them against I-08-53.
- **Q-11 `auth.update_sys_param` requires `_user_id = 1`** (`018:94`), which contradicts "never use user_id 1 at runtime" (docs/concepts/service-accounts.md). Should it use a permission (e.g. `system.update_sys_param`) and journal the change? Today it writes no journal entry.
- **Q-12 Event-code management has no permission check.** `public.create/delete_event_category/code/message` (`018:657-873`) are documented as "None" (audit-events.md:672-677). That contradicts "public always checks permissions". Any caller can register or delete non-system codes and message templates.
- **Q-13 `auth.has_permissions` is declared `stable` but has side effects through callees** (`022:63-65`): cache recalculation, `recalculate_user_groups`, the journal insert. Is the volatility class intended? The planner may fold or reuse results within one statement.
- **Q-14 `ix_owner (user_id, tenant_id, user_group_id)`** (`013:581`) doesn't stop duplicate tenant-wide owner rows, because `user_group_id` is null in them. Per I-08-67 this needs `coalesce` or `nulls not distinct`.
- **Q-15 Two grant scripts.** `099_fix_permissions.sql` (schema usage only, and missing `internal`, `stage`, `triggers`, `public`) is picked up as a migration, while `99_fix_permissions.sql` is the configured post-update script. Which one is authoritative? Also, no script revokes `EXECUTE` from `PUBLIC`; the protection relies on schema `USAGE` alone (I-08-11).
- **Q-16 `public.validate_token` has a dead filter.** `((_target_user_id is not null and token.user_id = _target_user_id) or true)` (`018:451`) never filters by target user. This belongs to domain 02 but is noted here.
- **Q-17 Should `auth.get_all_tenants`/`auth.get_tenant_by_id` (unchecked) include soft-deleted tenants?** `023:421` has no `deleted_at` filter. Should "suitable for dropdowns" (tenants.md:186) exclude them?

## Known coverage

| Suite | Covers |
|---|---|
| `test_setup_verification` | schemas, extensions, core/const tables, seeded service accounts 1-6 and 800, event codes populated, permission trees, sys_param seeds (part of I-08-15/20) |
| `test_connection`, `test_connectivity` | connectivity only |
| `test_correlation_id` | correlation id stored on journal and user_event, `null` correlation id, search by correlation id (I-08-33) |
| `test_event_code_management` | category/code/message CRUD, 31010-31014, cascade, system protection (I-08-29); runs as user 1 |
| `test_audit_and_user_ops` | `create_user_event` storage, request_context/event_data, audit trail and security-event queries (I-08-34); runs as user 1 |
| `test_tenant_scoping_security` | non-system admin, second tenant (I-08-22/23) |
| `test_search_functions/004` | journal/event paging |

No test covers:
- I-08-02/03/04: no scan that flags unchecked `auth/public` functions
- I-08-05: no side effects on denial
- I-08-09 to 14: grants, definer, search_path
- I-08-18/19: system user cannot be locked or disabled
- I-08-25/26: every raised code seeded, with a template
- I-08-27: alias mapping
- I-08-31/32: completeness of the audit trail per operation
- I-08-36: denial persisted
- I-08-38/39: journal level and storage modes, truncation
- I-08-40: tenant isolation of user_event reads (no test runs these as a non-system user from a non-admin tenant)
- I-08-43 to 48: notifications; no test LISTENs
- I-08-53: overload ambiguity
- I-08-55 to 58: version functions
- I-08-60 to 62: null and paging input
- I-08-65 to 67: concurrency
