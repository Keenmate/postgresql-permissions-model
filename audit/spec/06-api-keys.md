# 06 - API keys

## Scope

Table: `auth.api_key` (`013_tables_auth.sql:451`): one table for both key types, `key_type in ('inbound','outbound')`, `api_key` globally unique, `tenant_id` FK `on delete cascade`.
Triggers: `triggers.notify_api_key` (`033_triggers_cache_and_notify.sql:429`, INSERT/DELETE -> `api_key_created` / `api_key_deleted` notifications), `triggers.calculate_api_key*` (search values).

Inbound keys (`026_functions_auth_apikey.sql` unless noted):

| Function | Location |
|---|---|
| `auth.generate_api_key_username` / `generate_api_key` / `generate_api_secret` / `generate_api_secret_hash` | `026:13`, `:22`, `:30`, `:38` |
| `auth.create_api_key` | `026:47` |
| `auth.search_api_keys` | `026:110` |
| `auth.get_api_key_permissions` | `026:164` |
| `auth.update_api_key` | `026:181` |
| `auth.assign_api_key_permissions` | `026:216` |
| `auth.unassign_api_key_permissions` | `026:275` |
| `auth.delete_api_key` | `026:348` |
| `auth.update_api_key_secret` | `026:383` |
| `auth.validate_api_key` | `048_update_permissions_v2-1.sql:526` (overrides `026:418`) |
| `unsecure.create_api_user` | `019_functions_unsecure.sql:1679` |

Outbound keys: `create_outbound_api_key` `026:483`, `get_outbound_api_key` `:549`, `get_outbound_api_key_by_id` `:592`, `get_outbound_api_key_secret` `:638`, `get_outbound_api_key_secret_by_id` `:678`, `update_outbound_api_key` `:715`, `update_outbound_api_key_secret` `:776`, `search_outbound_api_keys` `:825`, `delete_outbound_api_key` `:889`.

Dependencies from other domains (only their API-key-relevant behaviour is specified here): `unsecure.assign_permission` / `unsecure.unassign_permission` (`048:131`, `048:240`), `unsecure.delete_user_by_id` (`019:497`), `internal.resolve_cross_tenant_access` (`019:48`), `auth.has_permissions` (`022:63`), service users `auth.create_service_user_info` (`020:268`) / `unsecure.create_service_user_info` (`019:1544`).

Permissions (seeded `022_functions_auth_permission.sql:600-609`): `api_keys.create_api_key`, `.update_api_key`, `.delete_api_key`, `.update_api_secret`, `.validate_api_key`, `.search`, `.search_all`, `.update_permissions`, `.read_outbound_secret`.
Journal codes: 14001 `apikey_created`, 14002 `apikey_updated`, 14003 `apikey_deleted`; 14010 `apikey_validated` / 14011 `apikey_validation_failed` are seeded but unused (`029_seed_data.sql:169-173`). Error: 30001 `err_api_key_invalid` (raised via legacy alias `error.raise_52301`, `016_functions_error.sql:26`, `:732`).

## Actors & preconditions

- **API key admin in own tenant T**: holds `api_keys.*` in T (perm set `api_key_manager`, `system_admin`, `full_admin`). Manages keys whose `tenant_id = T`.
- **Admin in tenant 1**: may read (search/get) keys of any tenant with `api_keys.search_all` (cross-tenant pattern). Writes are always scoped to `_tenant_id`.
- **Gateway** (`svc_api_gateway`, user 5, perm set `svc_api_gateway_permissions` = `api_keys.validate_api_key`): calls `validate_api_key` per request.
- **API key technical user** (`user_type_code = 'api'`, username/code `api_key_<key>`): the identity under which a validated key acts; gets permissions only through `permission_assignment`.
- **Service user** (`user_type_code = 'service'`, ids 1-999, `is_system`, `can_login = false`): pre-seeded backend identity, not tied to any key. Not created or deleted by any API key function.
- Precondition for all inbound management calls: the key exists, has `key_type = 'inbound'`, and belongs to `_tenant_id`.

## Invariants

### Creation & technical user
- **I-06-01** `create_api_key` requires `api_keys.create_api_key` in `_tenant_id`; without it raises 32001 and creates nothing. Source: docs/reference/api-keys.md, code `026:63`.
- **I-06-02** A successful `create_api_key` creates exactly one `api_key` row (`key_type = 'inbound'`, `tenant_id = _tenant_id`, `secret_hash = sha256(secret)`) and exactly one `user_info` row with `user_type_code = 'api'`, `code = username = 'api_key_' || api_key`. Source: docs/concepts/service-accounts.md, test test_api_keys/001 TEST 1-2.
- **I-06-03** The plaintext secret is returned once by `create_api_key` (and once by `update_api_key_secret`) and is never stored or returned by any other function; only `secret_hash` is persisted. Source: docs/reference/api-keys.md ("Secret visibility").
- **I-06-04** If `_api_key` / `_api_secret` are null they are generated (UUID v4); a supplied `_api_key` that already exists fails (unique violation) and no technical user or assignment is left behind. Source: docs, table `013:464` **[confirm]** (whole call must be atomic).
- **I-06-05** Perm set / permissions passed to `create_api_key` are assigned to the technical user in the key's tenant only; a perm set code that exists only in another tenant raises 52282, non-assignable perm set 52283, unknown permission 52180, non-assignable permission 52181 - and the key is then not created. Source: code `048:131` (unsecure.assign_permission) **[confirm]**.
- **I-06-06** An empty string perm set code or empty array means "assign nothing" (no error). Source: docs ("pass null or empty array to skip"), code `026:82,87`.
- **I-06-07** A technical user is never a member of `tenant_user` implicitly, has no identities, and cannot log in through any authentication flow (`can_login` should be false, as for service users). Source: docs/concepts/service-accounts.md (user types table says "default") **[confirm]**.
- **I-06-08** `create_api_key` journals 14001 with entity `api_key`/`api_key_id` and the key's tenant; the payload never contains the secret. Source: docs (Journal Event Codes), test test_api_keys/001 TEST 3.
- **I-06-09** Technical users get ids from the normal sequence (>= 1000); service users live in 1-999 and are never created by API key functions. Source: docs/concepts/service-accounts.md.

### Tenant scoping (inbound)
- **I-06-10** `update_api_key`, `update_api_key_secret`, `assign_api_key_permissions`, `unassign_api_key_permissions`, `delete_api_key`, `get_api_key_permissions` act only on a key with `api_key.tenant_id = _tenant_id`; a key of another tenant behaves as "not found" and is left untouched. Source: CLAUDE.md (tenant isolation), CHANGELOG v2.1 (tenant-scoped assign/unassign) **[confirm]** for assign/unassign/delete (code does not filter, see Q1).
- **I-06-11** Permissions assigned via `assign_api_key_permissions` are created with `permission_assignment.tenant_id = _tenant_id = api_key.tenant_id`; an admin of tenant B can never add or remove assignments on a tenant-A key's technical user. Source: CHANGELOG v2.1, test test_tenant_scoping_security/002 (general rule) **[confirm]**.
- **I-06-12** `search_api_keys` returns only inbound keys (`key_type = 'inbound'`); from tenant T != 1 it needs `api_keys.search` in T and returns only T's keys; from tenant 1 it needs `api_keys.search_all` and returns all tenants (or `_target_tenant_id`); `_target_tenant_id` from T != 1 raises 34002. Source: docs ("across inbound API keys"), CLAUDE.md cross-tenant pattern.
- **I-06-13** `search_api_keys` / `search_outbound_api_keys` never return `secret_hash`, `encrypted_secret` or `nrm_search_data`. Source: CLAUDE.md (no setof table), docs return columns.
- **I-06-14** `get_api_key_permissions` requires an `api_keys.*` read permission (`api_keys.search`, or `search_all` cross-tenant) and returns only assignments of the key's technical user in the key's tenant. Source: docs say it "delegates to get_user_permissions" **[confirm]** (see Q4).
- **I-06-15** Search functions cap `_page_size` at 100 and default `_page`/`_page_size` to 1/10 when null; `__total_items` is the count before paging. Source: docs/reference/api-keys.md (Pagination), test test_api_keys/004 TEST 17.

### Validation
- **I-06-16** `validate_api_key` requires the caller to hold `api_keys.validate_api_key` in `_tenant_id`. Source: docs, code `048:536`.
- **I-06-17** Validation succeeds only if all hold: key exists, `key_type = 'inbound'`, `secret_hash = sha256(_api_secret)`, `api_key.tenant_id = _tenant_id`, and `expire_at is null or expire_at > now()`. Source: docs (v2.1 expiry), test test_tenant_scoping_security/004, test_api_keys/002 TEST 7-9.
- **I-06-18** Every failure (unknown key, wrong secret, wrong tenant, expired, outbound key, null secret) raises SQLSTATE 30001, with no difference observable to the caller between the reasons. Source: docs, CHANGELOG v2.1, test_api_keys/002 TEST 8, test_tenant_scoping_security/004.
- **I-06-19** Validation fails with 30001 when the technical user is disabled (`is_active = false`), locked or deleted. Source: CLAUDE.md (disabled/locked users blocked), domain 02 rule **[confirm]** (code does not check, see Q3).
- **I-06-20** On success it returns the technical user's id, username, display name and the effective permission codes in `_tenant_id` - the same set `auth.has_permission(tech_user, ..., _tenant_id)` would grant (perm sets expanded, direct permissions, group-inherited permissions). With no permissions it returns an empty array, not `{NULL}`. Source: docs ("all effective permission codes") **[confirm]** (code reads direct assignments only, see Q5).
- **I-06-21** Every validation attempt, success or failure, leaves a durable user event (and for failures it must survive the raised exception). Source: docs ("Both successful and failed validations are logged") **[confirm]** (see Q6).
- **I-06-22** An expired key must not authorize anything through the technical user either: `has_permission` on the technical user of an expired key should not grant **[confirm]** (see Q7).

### Update, rotation, deletion
- **I-06-23** `update_api_key` requires `api_keys.update_api_key`, changes only title/description/expire_at/notification_email of an inbound key in `_tenant_id`, never the key, hash or technical user, and journals 14002. Unknown / foreign / outbound id raises an error and journals nothing. Source: docs, test test_api_keys/002 TEST 5-6; not-found behaviour **[confirm]**.
- **I-06-24** Setting `expire_at` in the past makes the key fail validation at once; clearing it re-enables the key. Source: test test_tenant_scoping_security/004.
- **I-06-25** `update_api_key_secret` requires `api_keys.update_api_secret`; after it, the old secret fails (30001) and the new one validates; key value, technical user, assignments and expiry are unchanged; journals 14002 with `action = secret_rotated` and no secret in the payload. Source: docs, test test_api_keys/002 TEST 9.
- **I-06-26** `update_api_key_secret` on an unknown, foreign-tenant or outbound key raises an error and returns no secret. Source: outbound counterpart raises (`026:808`), test test_outbound_api_keys TEST 18 **[confirm]**.
- **I-06-27** `delete_api_key` requires `api_keys.delete_api_key`; removes the inbound key, all `permission_assignment` rows of its technical user, its permission cache rows and the technical user; journals 14003. Source: docs ("permanent, cascading deletion"), test test_api_keys/001 TEST 4.
- **I-06-28** `delete_api_key` on an unknown, foreign-tenant or outbound id raises an error and deletes nothing. Source: outbound counterpart (`026:912`) **[confirm]**.
- **I-06-29** Removing the technical user's assignments on delete is audit-visible (12011 per assignment or one 14003 payload listing them). Source: CLAUDE.md (audit all security events) **[confirm]**.
- **I-06-30** Deleting a tenant removes its api keys (FK cascade) and their technical users; no orphan `api`-type `user_info` remains. Source: table `013:459` **[confirm]**.

### Permission assignment on keys
- **I-06-31** `assign_api_key_permissions` / `unassign_api_key_permissions` require `api_keys.update_permissions` in `_tenant_id`, invalidate the technical user's permission cache in that tenant, and journal 14002 (plus 12010/12011 per assignment). Source: docs, code `048:131` cache clear.
- **I-06-32** `unassign_api_key_permissions` returns the remaining assignments of the technical user (perm-set-based and permission-based). Source: docs ("Returns the remaining assignments") **[confirm]** (see Q8).
- **I-06-33** Assigning to / unassigning from an unknown api key id raises a not-found error rather than 52272 or a silent no-op. **[confirm]**

### Outbound keys
- **I-06-34** Outbound keys never create a technical user and can never pass `validate_api_key`. Source: docs.
- **I-06-35** `create_outbound_api_key` requires `api_keys.create_api_key`; `_service_code` null/empty or `_encrypted_secret` null raises 22023 and creates nothing; `service_code` is stored lowercase; `api_key = 'outbound_<service_code>_<uuid>'`; journals 14001 with `key_type = outbound`, no secret. Source: docs, test test_outbound_api_keys TEST 1-4.
- **I-06-36** Inbound functions never act on outbound keys and vice versa (every inbound function filters `key_type = 'inbound'`; every outbound function filters `key_type = 'outbound'`). Source: docs (two types) **[confirm]**.
- **I-06-37** `get_outbound_api_key_secret(_by_id)` returns the encrypted secret only to a caller holding `api_keys.read_outbound_secret` in the key's tenant (from tenant 1 cross-tenant: the elevated "all" variant must also be a secret-read permission, not `api_keys.search_all`). Source: docs ("requires the elevated api_keys.read_outbound_secret") **[confirm]** (see Q2).
- **I-06-38** Expired outbound keys are never returned by the secret getters; metadata getters/search still return them. Source: docs.
- **I-06-39** `get_outbound_api_key` / `_secret` by service code returns at most one key per tenant (one active credential per service per tenant), or the contract says it returns a set. **[confirm]** (see Q9).
- **I-06-40** `update_outbound_api_key` / `_secret` / `delete_outbound_api_key` act only on outbound keys of `_tenant_id`; unknown/foreign id raises SQLSTATE 02000 for secret update and delete. Source: test test_outbound_api_keys TEST 17-18; `update_outbound_api_key` not-found **[confirm]**.
- **I-06-41** Reading an outbound secret is audit-logged. Source: CLAUDE.md (audit all security events) **[confirm]** (code comment `026:673` says omitted for performance).

### Service users
- **I-06-42** `auth.create_service_user_info` requires `users.create_service_user`; stores `username`, `email`, `display_name` in their own columns; the new id stays within 1-999 (never collides with the >= 1000 sequence), user is `service`, `is_system`, `can_login = false`. Source: docs/concepts/service-accounts.md, test test_service_user_info.sql; id range and flags for runtime-created users **[confirm]** (code sets the flags only in seed `029:442`).

## Flows

**Create inbound key** (admin in T): permission check (T) -> insert `api_key` (inbound, T, hash) -> insert technical user -> assign perm set/permissions in T (each: `permission_assignment` row tenant T, journal 12010, cache clear for tech user in T) -> journal 14001 -> NOTIFY `api_key_created`. Result: 1 key, 1 `api` user, N assignments in T, secret returned once.

**Validate** (gateway, tenant T): permission check (gateway, T) -> look up key by value+hash+tenant+expiry (+active tech user) -> on miss: durable event `is_successful=false`, raise 30001 -> on hit: compute effective permissions in T -> event `is_successful=true` -> return row.

**Rotate secret**: permission check -> update hash of key in T -> journal 14002 `secret_rotated` -> return new secret. Old secret fails from the next call.

**Assign / unassign permissions**: permission check (T) -> resolve tech user of key in T -> assign/unassign in T (journal 12010/12011, cache clear) -> journal 14002 -> return assignments (after).

**Delete**: permission check (T) -> resolve key in T -> delete assignments (audited) -> delete tech user (cache rows cascade) -> delete key -> journal 14003 -> NOTIFY `api_key_deleted`.

**Outbound**: create (no tech user) -> metadata get/search with `api_keys.search`(`_all`) -> secret get with `read_outbound_secret` (non-expired only) -> update / rotate / delete scoped to T and `key_type = outbound`.

## Failure behaviour

| Operation | Condition | Expected |
|---|---|---|
| any `auth.*` api key function | caller lacks permission in `_tenant_id` | 32001 (`throw_no_permission`), journal 32001 |
| search/get (`_target_tenant_id` set) | `_tenant_id <> 1` | 34002 |
| `create_api_key` | perm set not in tenant / not assignable | 52282 / 52283, nothing created |
| `create_api_key` | permission unknown / not assignable | 52180 / 52181, nothing created |
| `create_api_key` | duplicate `_api_key` | unique violation 23505, nothing created |
| `validate_api_key` | unknown key, wrong secret, other tenant, expired, outbound, disabled/locked tech user | 30001 + failed event |
| `update_api_key`, `update_api_key_secret`, `delete_api_key`, `assign/unassign_api_key_permissions` | unknown / foreign-tenant / outbound id | not-found error **[confirm]** code (none defined today) |
| `unassign_api_key_permissions` | assignment of another tenant | 32009 (from `unsecure.unassign_permission`) |
| `create_outbound_api_key` | null/empty service code, null secret | 22023 |
| `update_outbound_api_key_secret` | null secret | 22023 |
| `update_outbound_api_key_secret`, `delete_outbound_api_key` | unknown / foreign / inbound id | 02000 |

## Open questions

- **Q1 Cross-tenant writes on inbound keys.** `assign_api_key_permissions` (`026:229-233`), `unassign_api_key_permissions` (`026:290-294`) and `delete_api_key` (`026:360-372`) resolve the technical user by `api_key_id` without `tenant_id`. An admin of tenant B (with `api_keys.*` in B) can delete tenant A's key and its technical user, or attach tenant-B assignments to tenant A's technical user. `update_api_key`/`update_api_key_secret` do filter tenant. Intended rule: I-06-10/11.
- **Q2 Outbound secret readable with `search_all`.** `get_outbound_api_key_secret(_by_id)` (`026:661-662`, `:701-702`) passes `api_keys.search_all` as the cross-tenant permission, so a tenant-1 caller with only `search_all` (in `system_admin`/`full_admin`, `022:645,707`) reads all tenants' encrypted secrets without `read_outbound_secret`. Also: `api_key_manager` gets the whole `api_keys` subtree (`022:686`), including `read_outbound_secret` - is that "granted sparingly"?
- **Q3 Disabled/locked technical user still validates.** `validate_api_key` (`048:538-545`) reads assignments directly and never checks `user_info.is_active`/`is_locked`, while `recalculate_user_permissions` (`019:2143`) refuses inactive users. Is `disable_user` on a technical user meant as a revoke? There is no other "disable key" function besides expiry.
- **Q4 `get_api_key_permissions` scoping.** No `api_keys.*` check (`026:164-178`); it calls `auth.get_user_permissions(_user_id, _correlation_id, ui.user_id)` without passing `_tenant_id`, so the inner call always runs as tenant 1 (cross-tenant branch, `users.get_all_permissions`) regardless of the caller's tenant. Unqualified `tenant_id = _tenant_id` (`026:177`) resolves to `ak.tenant_id` only by accident.
- **Q5 Validation permission set differs from `has_permission`.** `validate_api_key` (`048:557-575`) lists only direct assignments (perm set expansion via `effective_permissions` + direct permissions), ignoring group memberships and the cache; a key with no assignments returns `{NULL}` from `array_agg` over a left join.
- **Q6 Failed-validation audit is rolled back.** `create_user_event` is performed then `error.raise_52301` raises in the same transaction (`048:549-554`), so the failed event and its notify vanish unless the caller catches. Also the event type is the ad-hoc `api_key_validating`, while seeded codes 14010/14011 (`029:172-173`) are never used. Same pattern for journal 32001 in `has_permissions` (`022:119-126`) - cross-cutting (domain 08).
- **Q7 Expiry only enforced in `validate_api_key`.** The technical user's permissions/cache remain valid after `expire_at`; any code calling `has_permission(tech_user_id, ...)` directly (e.g. app caching the user id from validation) keeps access. Intended?
- **Q8 `unassign_api_key_permissions` result always empty.** Return query uses `inner join auth.perm_set` and `inner join auth.permission` (`026:331-333`), but an assignment has one or the other, so no rows are ever returned. Test test_api_keys/003 TEST 13-14 checks remaining via `get_api_key_permissions`, not the return value.
- **Q9 Multiple outbound keys per service code.** No uniqueness on `(tenant_id, service_code)`; `get_outbound_api_key(_secret)` by service code declares `rows 1` but returns all matches, and from tenant 1 without target tenant returns every tenant's key for that service.
- **Q10 Inbound functions don't filter `key_type`.** `search_api_keys` (`026:141-143`) lists outbound keys too (docs: inbound only); `update_api_key` (`026:191-199`) and `update_api_key_secret` (`026:399-404`) can modify an outbound key (setting a `secret_hash` on it); `delete_api_key` (`026:371`) deletes an outbound key by id.
- **Q11 Silent success on not-found.** `update_api_key`, `update_api_key_secret` (returns a fresh secret!) and `delete_api_key` neither raise nor skip the journal when the id is unknown/foreign; `assign_api_key_permissions` with unknown id raises 52272 ("no target") instead of not-found.
- **Q12 `create_api_key` with `_tenant_id = null`.** `__tenant_id := coalesce(_tenant_id, 1)` (`026:65`) is used for the user/assignments but the insert uses raw `_tenant_id` (`026:73`), and the permission check runs with null tenant.
- **Q13 Delete audit gap.** `delete_api_key` removes assignments with a raw `delete` (`026:366`) - no 12011 events - and `unsecure.delete_user_by_id` (`019:497`) journals nothing for the technical user.
- **Q14 Technical-user lookup by `code` only.** Lookups (`026:231`, `:292`, `:362`, `048:540`) match `ui.code = 'api_key_' || api_key` without `user_type_code = 'api'` (only `026:174` checks it). Is `user_info.code` guaranteed unique and unsettable to that pattern by other paths?
- **Q15 Docs vs code.** docs/concepts/authentication.md (API Key Authentication) says validate returns `api_key_id, user_id, tenant_id, permissions` - actual columns are `__user_id, __username, __user_display_name, __permission_full_codes`. Secret hashing is unsalted SHA-256 with no strength check on caller-supplied `_api_secret` - acceptable for random UUID secrets only.
- **Q16 Service user id allocation.** `unsecure.create_service_user_info` (`019:1562-1580`) uses `max(user_id between 1 and 999) + 1`; with id 999 taken it inserts 1000, colliding with the user sequence. Runtime-created service users don't get `is_system`/`can_login = false` (only seed `029:442` sets them). Belongs partly to domain 01.

## Known coverage

| Suite | Covers |
|---|---|
| `test_api_keys` (19 tests) | I-06-02, -03 (partly), -08, -16/-17 (happy path), -18 (wrong secret), -23, -25, -27 (key + user gone), -31 (happy path), search basics |
| `test_outbound_api_keys` (25 tests) | I-06-35, -38 (non-expired only happy path), -40 (02000), search |
| `test_tenant_scoping_security/004` | I-06-17/-18/-24 expiry |
| `test_service_user_info.sql` | I-06-42 column placement only (calls as user 1) |
| `test_search_functions` | search pagination for both key types |

No test today for: I-06-05 (rollback on bad perm set), -07, -10/-11 (cross-tenant assign/unassign/delete/update/rotate), -12 (inbound-only search, tenant isolation), -14, -19 (disabled/locked tech user), -20 (group-inherited / empty permissions), -21 (failed event durability), -22, -26/-28/-33 (not-found), -29/-30, -32 (unassign return value), -36 (key_type separation), -37 (secret read with `search_all` only), -39, -41, -42 (id range, flags), and any permission-denied path (most `test_api_keys` calls should be re-checked against the user-1 rule).
