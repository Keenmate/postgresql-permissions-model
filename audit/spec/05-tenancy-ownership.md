# 05 - Tenancy & ownership

## Scope

Latest definitions (from `db-objects.md`; `048` overrides the baseline where listed).

**Tenant lifecycle** (`023_functions_auth_tenant.sql` unless noted)
- `auth.create_tenant` 023:435, `auth.update_tenant` 023:527
- `auth.delete_tenant` 023:159 (soft delete), `auth.delete_tenant_by_uuid` 023:191 (alias), `auth.restore_tenant` 023:206, `auth.purge_tenant` 023:236
- Workers: `unsecure.soft_delete_tenant` 019:1955, `unsecure.restore_tenant` 019:1989, `unsecure.delete_tenant` 019:1868 (purge worker), `unsecure.create_primary_tenant` 019:464
- Tables: `auth.tenant` 013:34, `auth.tenant_identity` 013:80 (code ledger), `const.tenant_access_type` 011:29
- Triggers: `triggers.notify_tenant` 033:417 (on physical delete only), `triggers.calculate_tenant(_search_values)` 017:65/76

**Tenant reads**
- `auth.get_tenants` 023:13, `auth.get_tenant_by_id` 023:46, `auth.get_all_tenants` 023:421, `auth.search_tenants` 023:573
- `auth.get_tenant_users` 023:67, `auth.get_tenant_groups` **048:433**, `auth.get_tenant_members` 023:126
- `auth.get_user_available_tenants` 023:268

**Tenant users / preferences / last selected**
- `auth.tenant_user` 013:139 (only written by invitations, `042_functions_invitation.sql:723`)
- `auth.user_tenant_preference` 013:516; `auth.create_user_tenant_preferences` 023:301, `auth.update_user_tenant_preferences` 023:321
- `auth.get_user_last_selected_tenant` 023:348, `auth.update_user_last_selected_tenant` 023:373; column `auth.user_info.last_selected_tenant_id` (FK `on delete set null`, 013:106)

**Cross-tenant read pattern**
- `internal.resolve_cross_tenant_access` 019:48, `internal.resolve_tenant` 019:131

**Ownership** (`027_functions_auth_owner.sql`)
- `auth.has_owner` 027:13, `auth.is_owner` **048:102**, `auth.create_owner` 027:45, `auth.delete_owner` 027:70
- `unsecure.verify_owner_or_permission` 019:445; table `auth.owner` 013:353 + unique index `ix_owner` 013:581; trigger `triggers.notify_owner` 033:337
- Consumers of the tenant-wide owner shortcut: `auth.has_permissions` 022:80, `auth.can_manage_user_group` 021:41, resource access 035:180/339/526/671

**System helpers**
- `unsecure.create_user_group_as_system` **048:463**, `unsecure.create_user_group_member_as_system` **048:483**, `unsecure.assign_permission_as_system` 019:958, `unsecure.create_perm_set_as_system` 019:1297, `unsecure.create_permission_as_system` 019:1193, `unsecure.delete_user_by_username_as_system` 019:486

## Actors & preconditions

| Actor | Description |
|---|---|
| System (user 1) | `has_permissions` returns `true` immediately. Used by seeds and `*_as_system` helpers. Never use it to prove a rule (CLAUDE.md test-writing rule). |
| Admin-tenant user | Caller with `_tenant_id = 1` holding `read_all_*` / `get_all_*` permissions in tenant 1 (System admin / Full admin perm sets, 022:636, 022:695). |
| Tenant admin | Member of the "Tenant Admins" group of tenant T. Holds the copied `tenant_admin` perm set (`tenants` subtree + journal + languages + translations, 022:653). |
| Tenant owner | `auth.owner` row with `tenant_id = T`, `user_group_id is null`. |
| Group owner | `auth.owner` row with `tenant_id = T`, `user_group_id = G`. |
| Tenant member | User in any group of T, either as a direct member or through an external mapping (`auth.user_group_members` view). |
| End user (self) | `_user_id = _target_user_id` for preferences and last-selected tenant. |

Preconditions: tenant 1 ("Primary", `is_removable = false`) and user 1 (system) exist. User tenant ids start at 1000 (`047_seed_permissions.sql:21`). Tenant 1 holds the template perm sets `tenant_admin` and `tenant_member`.

## Invariants

### Tenant identity & lifecycle
- **I-05-01** Tenant 1 is the admin tenant. It can never be soft-deleted or purged; both raise 34007. Source: docs reference/tenants.md "Tenant Lifecycle"; test test_tenant_soft_delete/002
- **I-05-02** A tenant with `is_removable = false` can never be soft-deleted or purged (34007). Source: docs reference/tenants.md; test test_tenant_soft_delete/002
- **I-05-03** Every tenant code is written to `auth.tenant_identity` when the tenant is created. A code that has ever been used, by a live, soft-deleted or purged tenant, cannot be reused by `create_tenant` (34004). This includes a code derived from the title. Source: docs concepts/multi-tenancy.md; CHANGELOG 2026-08-17; test test_tenant_soft_delete/004
- **I-05-04** "A tenant code can never be reused" also covers `update_tenant`. Changing a tenant's code to a code in the ledger raises 34004, and any new code is burned in the ledger. **[confirm]** Source: docs concepts/multi-tenancy.md (warning box); code 023:539 does not touch the ledger
- **I-05-05** `create_tenant` requires `tenants.create_tenant`. A tenant can only be created by a caller who holds that permission in the admin tenant (`_tenant_id = 1`). A tenant admin of T ≠ 1 cannot create tenants. **[confirm]** Source: docs reference/tenants.md (default `_tenant_id = 1`); code 023:450 checks the permission in any `_tenant_id`
- **I-05-06** `create_tenant` leaves behind exactly: 1 tenant row, 1 ledger row (with uuid and `original_tenant_id` backfilled), groups "Tenant Admins" and "Tenant Members" in the new tenant, copies of perm sets `tenant_admin` and `tenant_member` in the new tenant, each assigned to its group, and journal 11001. Source: docs concepts/multi-tenancy.md "Automatic Bootstrapping"; test test_tenant_crud/001
- **I-05-07** If `_tenant_owner_id` is given, `create_tenant` succeeds for any caller who was allowed to create the tenant, and leaves a tenant-wide owner row for that user in the new tenant. **[confirm]** Source: docs reference/tenants.md; code 023:510 runs the owner check in the *new* tenant, where the creator has no rights
- **I-05-08** `update_tenant` requires `tenants.update_tenant`, checked in the tenant being updated (`_tenant_id`). It changes only that tenant. Null optional arguments keep current values. It logs journal 11002. Source: docs reference/tenants.md; test test_tenant_crud/001
- **I-05-09** `update_tenant` on a tenant id that does not exist raises 34003 and writes no journal entry. **[confirm]** Source: common sense; code 023:537-551 is silent
- **I-05-10** Soft, restore and purge need different permissions. `delete_tenant` needs `tenants.delete_tenant`, `restore_tenant` needs `tenants.delete_tenant`, and `purge_tenant` needs `tenants.purge_tenant`. Source: docs reference/tenants.md; CHANGELOG 2026-08-17
- **I-05-11** A caller in tenant T ≠ 1 must never soft-delete, restore or purge a tenant other than T. Lifecycle operations on another tenant are authorized only by permission held in tenant 1. **[confirm]** Source: tenant isolation (docs concepts/multi-tenancy.md "Tenant Isolation"); code 023:169/216/246 checks the permission in caller-supplied `_tenant_id` and looks up any `_tenant_uuid`
- **I-05-12** `delete_tenant` with an unknown uuid raises 34003. On an already soft-deleted tenant it raises 34005. `restore_tenant` and `purge_tenant` on a tenant that is not soft-deleted raise 34006. Source: docs reference/tenants.md; test test_tenant_soft_delete/002
- **I-05-13** Soft delete only sets `deleted_at` / `deleted_by`. Groups, members, perm sets, assignments, owners, preferences, `tenant_user` rows and the ledger are all kept. It deletes every `user_permission_cache` and `user_group_id_cache` row of the tenant and logs journal 11004. Source: docs reference/tenants.md; test test_tenant_soft_delete/001
- **I-05-14** While a tenant is soft-deleted, nobody can work in it. `get_user_available_tenants` leaves it out, `update_user_last_selected_tenant` rejects it (34001/52108), and `has_permission(s)` with `_tenant_id` = that tenant grants nothing, even after the cache is rebuilt. **[confirm]** Source: docs reference/tenants.md ("a user can never switch into or operate under a soft-deleted tenant", "users lose access immediately"); code 022:80-115 and 019:2143 never check `deleted_at`, so the next call rebuilds the cache and grants again
- **I-05-15** Owner rows of a soft-deleted tenant grant nothing while the tenant is deleted. **[confirm]** Source: follows from I-05-14; code 022:80 owner shortcut ignores `deleted_at`
- **I-05-16** Restore clears `deleted_at` / `deleted_by` and logs 11005. Child data is the same as before the soft delete. Source: docs reference/tenants.md; test test_tenant_soft_delete/003
- **I-05-17** Purge removes all child data of the tenant: caches, resource ACL and role assignments, owners, assignments, perm-set perms, perm sets, group members, mappings, groups, `tenant_user`, invitations (+ actions), MFA policies and preferences. It detaches journal rows (`tenant_id = null`) and stamps `tenant_identity.purged_at/by`, but keeps the ledger row. It deletes the tenant row, logs 11006, and fires the `tenant_purged` notification. Source: docs concepts/multi-tenancy.md; CHANGELOG 2026-08-17; test test_tenant_soft_delete/004
- **I-05-18** Purge also handles all other tenant-scoped data. It must either succeed or fail with a clear error, never with a raw FK violation. That data includes tenant-scoped `const.language` and `public.translation` rows (FK without cascade) and API keys with their technical users. No technical user may be left without its API key. **[confirm]** Source: common sense; code 019:1868 does not delete these, and 030:32/58 have no `on delete`
- **I-05-19** After a purge, `user_info.last_selected_tenant_id` for that tenant is null. Source: docs concepts/multi-tenancy.md "Last Selected Tenant" (FK set null)
- **I-05-20** `delete_tenant_by_uuid` behaves exactly like `delete_tenant`. Source: docs reference/tenants.md
- **I-05-21** `tenant.is_assignable = false` stops any user from being added to the tenant, whether as a group member, by invitation or through `tenant_user`. **[confirm]** Source: docs concepts/multi-tenancy.md column description ("Whether users can be assigned to this tenant"); nothing in the code reads it
- **I-05-22** `access_type_code` (`public` / `authenticated` / `private`) has documented meaning. If it is not enforced anywhere, the docs must say it is informational only. **[confirm]** Source: docs concepts/multi-tenancy.md "Access Types"; nothing in the code reads it

### Tenant membership
- **I-05-23** A user is a member of tenant T only through membership in a group of T, direct or through an external mapping. This one definition drives `get_user_available_tenants`, `get_tenant_users`, `get_tenant_members`, `update_user_last_selected_tenant` and the tenant filter of `search_users`. Source: docs concepts/multi-tenancy.md "Tenant Users"; `search_users` uses `auth.tenant_user` instead (020:1014) **[confirm]**
- **I-05-24** A user who is not a member of T has no permissions in T. Direct user assignments in T (`permission_assignment.user_id`, `tenant_id = T`) are the only exception, and every such assignment must come through the tenant-checked assign path. **[confirm]** Source: code 019:2243-2265 grants direct assignments without any membership check; intent unclear
- **I-05-25** `get_user_available_tenants` returns only tenants where the target user is a member and `deleted_at is null`. It needs no permission for self. For another user it needs `users.get_available_tenants` in `_tenant_id`; otherwise it raises 32001. Source: docs reference/tenants.md; test test_tenant_soft_delete/001, test_auth_group_member_tenant
- **I-05-26** `update_user_last_selected_tenant` sets the tenant only if the **target** user is a member of it and it is not soft-deleted. Otherwise it raises 34001 (alias 52108). Updating another user needs `users.update_last_selected_tenant` and logs journal 10002 with `action = last_selected_tenant_updated`. **[confirm]** Source: docs reference/tenants.md says "acting user"; code 023:391 checks `_user_id` (the actor)
- **I-05-27** `get_user_last_selected_tenant` never returns a soft-deleted tenant. It returns an empty set instead. **[confirm]** Source: block-at-boundary rule (I-05-14); code 023:362-369 does not filter `deleted_at`
- **I-05-28** `get_user_last_selected_tenant` for another user needs `users.get_data`. For self it needs nothing. Source: docs reference/tenants.md

### User tenant preferences
- **I-05-29** Self create/update of preferences needs no permission. For another user, it needs `users.create_user_tenant_preferences` / `users.update_user_tenant_preferences` in `_tenant_id`; otherwise it raises 32001. Source: docs reference/tenants.md
- **I-05-30** There is at most one preference row per (user, tenant). By default, update merges with `||`; with `_should_overwrite_data = true` it replaces the whole object. Source: docs concepts/multi-tenancy.md
- **I-05-31** Preferences can only be created for a tenant that exists, is not soft-deleted, and has the target user as a member. A second create for the same (user, tenant) raises a defined error, not a raw unique violation. Updating a missing row raises an error instead of returning 0 rows. **[confirm]** Source: common sense; code 023:308-345 has no such checks

### Cross-tenant read pattern
- **I-05-32** `internal.resolve_cross_tenant_access(_user_id, _, all_perm, regular_perm, _tenant_id, _target_tenant_id)` has three branches:
  - (a) `_target_tenant_id` not null and `_tenant_id <> 1` raises 34002, even when target = own tenant.
  - (b) `_target_tenant_id` not null and `_tenant_id = 1` requires `all_perm` and returns the target, so only the target's data is shown.
  - (c) `_target_tenant_id` null and `_tenant_id = 1` requires `all_perm` in tenant 1 and returns null, so all tenants are shown.
  - (d) Otherwise it requires `regular_perm` in `_tenant_id` and returns `_tenant_id`.
  Source: CHANGELOG "Tenant Isolation & Cross-Tenant Data Access"; test test_cross_tenant_access/001-005
- **I-05-33** In branch (b), `all_perm` is checked in the **target** tenant. Source: CHANGELOG table ("checked against tenant 30"); test test_cross_tenant_access/000_setup comment. See Open question Q1. **[confirm]**
- **I-05-34** A caller in tenant 1 without `all_perm` gets 32001, both with and without a target. Source: test test_cross_tenant_access/005
- **I-05-35** In every function that uses the helper, the returned rows belong only to the effective tenant (or to all tenants when it is null). Rows of other tenants never leak through joins (for example, a user's groups from other tenants in `get_tenant_users`). Source: docs CLAUDE.md "Multi-Tenancy"
- **I-05-36** Functions using the pattern, with their permission pairs (all-tenants / own tenant). Source: code at the listed line; CHANGELOG list.

| Function | all perm | regular perm | Line |
|---|---|---|---|
| `auth.search_users` | `users.read_all_users` | `users.read_users` | 020:993 |
| `auth.get_user_group_mappings` | `groups.get_all_mappings` | `groups.get_mapping` | 021:339 |
| `auth.search_user_group_mappings` | `groups.get_all_mappings` | `groups.get_mapping` | 021:385 |
| `auth.get_user_assigned_groups` (other user only) | `users.read_all_user_group_memberships` | `users.read_user_group_memberships` | 021:754 |
| `auth.search_user_groups` | `groups.get_all_groups` | `groups.get_group` | 021:1077 |
| `auth.get_perm_sets` | `permissions.get_all_perm_sets` | `permissions.get_perm_sets` | 022:311 |
| `auth.get_user_permissions` (other user only) | `users.get_all_permissions` | `users.get_permissions` | 022:428 |
| `auth.search_perm_sets` | `permissions.read_all_perm_sets` | `permissions.read_perm_sets` | 022:931 |
| `auth.get_tenants` | `tenants.get_all_tenants` | `tenants.get_tenants` | 023:21 |
| `auth.get_tenant_users` | `tenants.get_all_users` | `tenants.get_users` | 023:75 |
| `auth.get_tenant_groups` | `tenants.get_all_groups` | `tenants.get_groups` | 048:441 |
| `auth.get_tenant_members` | `tenants.get_all_tenants` | `tenants.get_tenants` | 023:134 |
| `auth.search_tenants` | `tenants.read_all_tenants` | `tenants.read_tenants` | 023:601 |
| `auth.search_api_keys` | `api_keys.search_all` | `api_keys.search` | 026:129 |
| `auth.get_outbound_api_key` | `api_keys.search_all` | `api_keys.search` | 026:577 |
| `auth.get_outbound_api_key_by_id` | `api_keys.search_all` | `api_keys.search` | 026:620 |
| `auth.get_outbound_api_key_secret` | `api_keys.search_all` **[confirm]** | `api_keys.read_outbound_secret` | 026:661 |
| `auth.get_outbound_api_key_secret_by_id` | `api_keys.search_all` **[confirm]** | `api_keys.read_outbound_secret` | 026:701 |
| `auth.search_outbound_api_keys` | `api_keys.search_all` | `api_keys.search` | 026:858 |
| `auth.search_user_events` | `authentication.read_all_user_events` | `authentication.read_user_events` | 028:71 |
| `auth.get_user_audit_trail` | `authentication.read_all_user_events` | `authentication.read_user_events` | 028:156 |
| `auth.get_security_events` | `authentication.read_all_user_events` | `authentication.read_user_events` | 028:266 |
| `auth.get_invitations` (inline copy, not the helper) | `invitations.get_all_invitations` | `invitations.get_invitations` | 042:1114 |

- **I-05-37** Reading outbound API key **secrets** across tenants needs a secret-specific all-tenants permission, not the search permission `api_keys.search_all`. **[confirm]** Source: common sense (privilege separation; regular branch uses `api_keys.read_outbound_secret`)
- **I-05-38** `auth.search_blacklist` does not use the pattern (the blacklist is app-wide). It requires only `users.search_blacklist`. Source: CHANGELOG; MEMORY
- **I-05-39** `auth.get_tenant_by_id` and `auth.get_all_tenants` have no permission check. They are allowed exceptions to "auth always checks permissions". **[confirm]** Source: docs reference/tenants.md says "no permission check"; conflicts with CLAUDE.md security principle

### Ownership
- **I-05-40** `auth.is_owner(u, _, null, T)` is true only for a tenant-wide owner row (`user_group_id is null`). Owning a group never makes a user a tenant-wide owner. Source: docs reference/ownership.md "Changed in v2.1"; CHANGELOG v2.1; test test_tenant_scoping_security/001, test_ownership/002
- **I-05-41** `auth.is_owner(u, _, G, T)` is true only for an owner row of exactly (T, G). A tenant-wide owner is not reported as owner of G by `is_owner`, but callers that need it check both. Source: code 048:111 **[confirm]**
- **I-05-42** A group owner gets no permission in the tenant from `has_permission` through ownership. Source: test test_tenant_scoping_security/001
- **I-05-43** A tenant-wide owner of T passes every `has_permission(s)` check in T and every resource-access check in T. Source: docs reference/ownership.md; code 022:80, 035:180
- **I-05-44** The tenant-wide owner shortcut does not apply when the owner is disabled, locked or deleted, or when T is soft-deleted. In those cases the check falls through to the normal 33003 / 33004 path. **[confirm]** Source: common sense + I-05-14; code 022:80 returns before the active/locked check in 019:2155-2171
- **I-05-45** Ownership of tenant 1 is a deliberate super-admin grant. It covers all `read_all_*` cross-tenant reads and tenant lifecycle operations. **[confirm]** Source: follows from I-05-32(c) + I-05-43; never documented
- **I-05-46** Who may change owner rows (`create_owner` / `delete_owner`), through `verify_owner_or_permission`:
  - An existing owner of the same (T, G) may.
  - A tenant-wide owner of T may.
  - Anyone else needs `tenants.assign_group_owner` (when G is not null) or `tenants.assign_owner` (when G is null) in T; otherwise 32001.
  - A group owner can never create or delete a tenant-wide owner.
  Source: docs reference/ownership.md "Authorization Model"; test none for the denial paths
- **I-05-47** `create_owner` / `delete_owner` with `_user_group_id` not null are refused (33011) unless that group belongs to `_tenant_id`. No owner row may have a `user_group_id` from a different tenant than its `tenant_id`. **[confirm]** Source: tenant isolation; code 027:57 inserts without checking
- **I-05-48** An owner row is unique per (user, tenant, group). A tenant-wide owner (null group) can be added only once. A duplicate raises a defined error, not a raw unique violation or a silent second row. **[confirm]** Source: code 013:581 `ix_owner` treats nulls as distinct, so it allows duplicate tenant-wide rows
- **I-05-49** `create_owner` logs journal 11010 and `delete_owner` logs 11011, with `action = owner_added/owner_removed` and `user_group_id`, scoped to `_tenant_id`. The `auth.owner` insert/delete fires `owner_created/owner_deleted` with scope `tenant|group`. Source: docs reference/ownership.md; test test_ownership/001-002; code 033:337
- **I-05-50** `delete_owner` for a row that does not exist raises an error. It must not log a removal that did not happen. **[confirm]** Source: common sense; code 027:78-89
- **I-05-51** Ownership is checked live, not through the permission cache. Adding or removing an owner takes effect on the next check without invalidating the cache. Source: code 048:102 (reads `auth.owner` directly) **[confirm]**
- **I-05-52** The target user of `create_owner` exists and is active, and should be a member of T. **[confirm]** Source: common sense; code 027:57 does not check

### System helpers (`*_as_system`)
- **I-05-53** `*_as_system` helpers live only in `unsecure`. They act as user 1 / `'system'` and must not be callable from any role the application uses. Source: CLAUDE.md schema model
- **I-05-54** `create_user_group_as_system(title, ..., _tenant_id)` creates the group in `_tenant_id` and returns the created row. Source: CHANGELOG v2.1; test test_tenant_scoping_security/005
- **I-05-55** `create_user_group_member_as_system(username, group_title, _tenant_id)` finds the group by title (case-insensitive) **only in `_tenant_id`** and returns the member row. If the user or group is not found, it raises 33001 / 33011 instead of passing nulls on. **[confirm]** Source: CHANGELOG v2.1; test test_tenant_scoping_security/005; null handling is common sense
- **I-05-56** `assign_permission_as_system` follows the same tenant-scoping rules as `unsecure.assign_permission`, so a group from another tenant raises 33011. Source: CHANGELOG v2.1

## Flows

**Create tenant**: permission check, then burn the code in the ledger (34004 on collision), then insert the tenant, then backfill the ledger, then journal 11001. Next, create "Tenant Admins", copy `tenant_admin` from tenant 1 and assign it to that group. Then create "Tenant Members", copy `tenant_member` and assign it the same way. Finally, add the owner if one was given (journal 11010, `owner_created` notification). Result: no cache rows for the new tenant; nobody is a member yet.

**Soft delete**: permission check, then load by uuid (34003), then the guards (34007, then 34005). Set `deleted_at/by`, delete the tenant's `user_permission_cache` and `user_group_id_cache`, and log journal 11004. Expected: from then on, all access to the tenant is refused (I-05-14).

**Restore**: permission check, then load (34003), then require that it is deleted (34006). Clear `deleted_*` and log journal 11005. Caches rebuild on demand.

**Purge**: permission check, then load (34003), then guard (34007), then require that it is soft-deleted (34006). Run the dependency-ordered cleanup (I-05-17/18), stamp the ledger as purged, delete the row (`tenant_purged` notification, `last_selected_tenant_id` set to null), and log journal 11006.

**Cross-tenant read**: call `resolve_cross_tenant_access` first and use its result as the only tenant filter for the query.

**Ownership change**: `verify_owner_or_permission`, then insert or delete in `auth.owner` (trigger notification), then journal 11010/11011 with tenant `_tenant_id`.

## Failure behaviour

| Operation | Condition | Expected |
|---|---|---|
| any `auth.*` with a permission | missing permission | 32001 (legacy 52002/52109) + journal 32001 |
| `create_tenant` | code in ledger | 34004 |
| `update_tenant` | unknown id / new code in ledger | 34003 / 34004 **[confirm]** |
| `delete_tenant` | unknown uuid / tenant 1 or not removable / already deleted | 34003 / 34007 / 34005 |
| `restore_tenant` | unknown / not deleted | 34003 / 34006 |
| `purge_tenant` | unknown / protected / not soft-deleted | 34003 / 34007 / 34006 |
| lifecycle op on another tenant from T ≠ 1 | — | 32001 or 34002 **[confirm]** |
| cross-tenant helper | target given while `_tenant_id <> 1` | 34002 |
| `update_user_last_selected_tenant` | unknown / soft-deleted / not a member | 34001 (via `raise_52108`) |
| `has_permission` in a soft-deleted tenant | — | false / 32001 **[confirm]** |
| `create_owner` / `delete_owner` | not an owner and no permission | 32001 |
| `create_owner` | group of another tenant / duplicate | 33011 / defined duplicate error **[confirm]** |
| `can_manage_user_group` | group has owners and caller is not one of them | 33015 (alias 52401) |
| `recalculate_user_permissions` | user disabled / locked / missing | 33003 / 33004 / 33001 |

Note: 34004-34007 are raised by the code but missing from `error-codes.md` (only 34001-34003 are listed).

## Open questions

- **Q1** Which tenant should hold `all_perm` for a targeted read? `resolve_cross_tenant_access` (019:65) checks it in the **target** tenant, while the unfiltered "see all" branch (019:69) checks it in tenant 1. So an admin who can see *all* tenants' data from tenant 1 is refused when narrowing to one tenant unless they also hold the permission there, which is a stricter check for less data. The CHANGELOG documents the current behaviour. Is it intended, or should both branches check tenant 1?
- **Q2** Can a tenant admin of tenant T delete or purge another tenant? The `tenant_admin` perm set grants the whole `tenants` subtree (022:653), which includes `tenants.create_tenant`, `delete_tenant`, `purge_tenant`, `assign_owner` and all `get_all_*` / `read_all_*`. `create_tenant` copies it into every new tenant (023:488). `delete_tenant`/`restore_tenant`/`purge_tenant` check the permission in the caller-supplied `_tenant_id` but act on any `_tenant_uuid` (023:169-186, 216, 246). So a tenant admin of T can call `delete_tenant(_tenant_id := T, _tenant_uuid := <other tenant>)` and then purge it. They can also create tenants (023:450). Should these be tenant-1-only, and should `tenant_admin` exclude the lifecycle and `*_all_*` nodes?
- **Q3** Should soft delete block permission checks? `has_permissions` (022:61) and `recalculate_user_permissions` (019:2143) never look at `tenant.deleted_at`. Soft delete only clears the cache, and the next call rebuilds it with full permissions. The tenant-wide owner shortcut (022:80) is not blocked either. The docs promise users "lose access immediately" and "can never operate under a soft-deleted tenant".
- **Q4** What defines tenant membership? `tenant_user` is written only by invitations (042:723). `search_users` filters by `tenant_user` (020:1014), but `get_tenant_users`/`get_tenant_members`/`get_user_available_tenants` use group membership. A user added to a group therefore appears in `get_tenant_users` but not in `search_users` for that tenant, and the reverse happens for an invited user. Should `tenant_user` be kept in sync or dropped?
- **Q5** Which user must be a member in `update_user_last_selected_tenant` (023:391)? The membership check uses `_user_id` (the actor), not `_target_user_id`. An admin can set another user's last tenant to a tenant the target cannot access, and is refused for a tenant the target is in but the admin is not. The docs ("acting user") describe the code, but the rule probably means the target.
- **Q6** Can `create_tenant` assign an owner at all? With `_tenant_owner_id` it calls `auth.create_owner` with the creator's `_user_id` and the new tenant id (023:510). The creator is neither an owner nor holds `tenants.assign_owner` in the brand-new tenant, so this should raise 32001 for anyone but user 1. Untested with a non-system caller.
- **Q7** Can `update_tenant` reuse a burned code (023:539)? It changes `code` without writing to `tenant_identity`, so a purged tenant's code (or any code) can be reused through update, and the new code is never burned. Unknown ids and soft-deleted tenants are updated silently.
- **Q8** What can a group owner create (027:45)? `create_owner` / `delete_owner` don't check that `_user_group_id` belongs to `_tenant_id`. `verify_owner_or_permission` (019:450) lets the owner of group G in T create owner rows for G with any target user, including the creator again. `ix_owner` (013:581) allows duplicate tenant-wide owner rows because null groups are distinct.
- **Q9** Should disabled or locked owners still pass? The owner shortcut in `has_permissions` (022:80) runs before the disabled/locked checks in `recalculate_user_permissions` (019:2155). A disabled or locked tenant owner keeps passing every check in the tenant. The tenant-1 owner is a silent super admin (Q-related I-05-45).
- **Q10** Purge leaves data behind (019:1868). It does not handle tenant-scoped `const.language` / `public.translation` (FK without cascade, 030:32/58), so purge fails for a tenant that has its own languages or translations. `auth.api_key` rows cascade away, but their technical users in `user_info` stay, orphaned. No `tenant_soft_deleted` notification is sent; `notify_tenant` fires only on the physical delete.
- **Q11** Should outbound API key secrets need their own cross-tenant permission? `get_outbound_api_key_secret(_by_id)` uses `api_keys.search_all` as the all-tenants permission (026:661/701), so the right to search keys is enough to read secrets across tenants.
- **Q12** Should `tenant.is_assignable` and `access_type_code` do anything? Neither is enforced anywhere. `get_user_last_selected_tenant` (023:362) returns soft-deleted tenants.
- **Q13** What should the preference functions return? `create_user_tenant_preferences` returns `updated_at` as `__created_at` (023:316). Neither function checks that the tenant exists or is live, or that the target is a member.
- **Q14** Is `get_tenant_members` gated by the right permissions? It uses `tenants.get_tenants` / `get_all_tenants` (023:135), while the sibling `get_tenant_users` uses `tenants.get_users` / `get_all_users`. Both list user data, and the docs match the code.

## Known coverage

| Suite | Covers |
|---|---|
| test_tenant_crud | create (groups, journal), update, search, soft delete, get_tenant_users/groups, owner create/delete. Runs as user 1. |
| test_tenant_soft_delete | I-05-01/02/03/12/13 (partly)/16/17, available-tenants exclusion, ledger reuse |
| test_cross_tenant_access | I-05-32/33/34 for search_users, search_user_groups, search_tenants, get_perm_sets, search_user_group_mappings |
| test_ownership | is_owner / has_owner / create / delete + journal (user 1) |
| test_tenant_scoping_security | I-05-40/42, get_tenant_groups columns, `*_as_system` group helpers (I-05-54/55 happy path) |
| test_group_members_and_delete_tenant | `unsecure.delete_tenant` return shape |
| test_search_functions | search_tenants pagination/empty results |
| test_auth_group_member_tenant | get_user_available_tenants self/other |

Invariants with **no test**: I-05-04, 05, 07 (non-system caller), 09, 11, 14 (`has_permission` after soft delete), 15, 18, 19, 21, 23 (consistency between `search_users` and `get_tenant_users`), 24, 26 (other-user case), 27, 29-31 (preferences: coverage 0), 35 for `get_tenant_users`/`get_tenant_members`/`get_tenants` cross-tenant, 36 for the API key and event functions, 37, 43-48 (`verify_owner_or_permission` denial paths, group owner managing owners, foreign-tenant group, duplicates), 50, 52, 55 (not-found path). Coverage report: `auth.create_user_tenant_preferences`, `auth.update_user_tenant_preferences`, `auth.delete_tenant_by_uuid`, `auth.get_all_tenants`, `auth.get_tenant_members`, `internal.resolve_tenant`, `unsecure.verify_owner_or_permission`, `unsecure.soft_delete_tenant` (directly) and `unsecure.restore_tenant` (directly) have 0 test callers.
