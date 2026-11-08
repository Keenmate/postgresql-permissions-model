# 03 - Group membership

## Scope

Latest definitions per `db-objects.md` (update scripts 048+ override the 010-047 baseline).

**Group lifecycle** - `auth.create_user_group` (021:58), `auth.update_user_group` (021:77),
`auth.enable_user_group` (021:109), `auth.disable_user_group` (021:140), `auth.lock_user_group` (021:171),
`auth.unlock_user_group` (021:202), `auth.delete_user_group` (021:233), `auth.get_user_group_by_id` (021:619),
`auth.search_user_groups` (021:1040), `auth.ensure_user_groups` (021:1131), `unsecure.create_user_group` (019:599),
`unsecure.get_user_group_by_id` (019:666), `unsecure.create_user_group_as_system` (048:463), `internal.resolve_group` (019:181).

**Group type** - `auth.create_external_user_group` (021:568), `auth.set_user_group_as_hybrid` (021:597),
`auth.set_user_group_as_external` (021:668), `auth.set_user_group_as_internal` (021:700).

**Members** - `auth.is_group_member` (021:13), `auth.can_manage_user_group` (021:22), `auth.create_user_group_member` (021:634),
`auth.delete_user_group_member` (021:276), `auth.get_user_group_members` (021:651), `auth.get_user_assigned_groups` (021:740),
`unsecure.create_user_group_member` (019:1734), `unsecure.create_user_group_member_as_system` (048:483),
`unsecure.get_user_group_members` (019:1791).

**Mappings** - `auth.create_user_group_mapping` (048:302), `auth.delete_user_group_mapping` (048:381),
`auth.ensure_user_group_mapping` (021:429), `auth.ensure_user_group_mappings` (021:1264), `auth.get_user_group_mappings` (021:321),
`auth.search_user_group_mappings` (021:352), `auth.validate_provider_allows_group_mapping` / `_group_sync` (024:27 / 024:39).

**Effective membership** - `unsecure.recalculate_user_groups` (019:2016), called by `auth.has_permissions` on cache miss (022:93-117)
and by `auth.ensure_groups_and_permissions` (022:752); `unsecure.get_cached_group_ids` (019:2722) + `auth.user_group_id_cache` (034:424).

**Default groups** - `auth.assign_user_default_groups` (020:365), `unsecure.assign_user_default_groups` (019:1630).

**External sync** - `stage.external_group_member` (014:13), `auth.get_user_groups_to_sync` (021:771),
`auth.process_external_group_member_sync_by_mapping` (021:796), `auth.process_external_group_member_sync` (021:914).

**Tables / views** - `auth.user_group` (013:299), `auth.user_group_mapping` (013:335, unique `uq_user_group_mapping` 013:578),
`auth.user_group_member` (013:494, unique `uq_user_group_member` 013:655), `const.user_group_member_type` (011:140),
views `auth.active_user_groups` (015:13), `auth.user_group_members` (015:46), `auth.notify_group_users` (015:94).

**Triggers (033)** - `cache_user_group_member_insert` (033:138), `cache_user_group_member_delete` (033:36),
`cache_user_group_status_change` (033:49), `cache_user_group_before_delete` (033:66), `cache_user_group_id_on_user_change` (033:150),
`notify_user_group*` (033:229-283); trigger fns `calculate_user_group` (017:101) for code + search data.

Out of scope here (see other domains): how group assignments turn into permissions (04), owners/tenant users (05).

## Actors & preconditions

- **Tenant admin** in tenant T: holds `groups.*` permissions in T; manages only T's groups.
- **Admin in tenant 1**: may read other tenants' groups/mappings/memberships with `groups.get_all_groups`,
  `groups.get_all_mappings`, `users.read_all_user_group_memberships` (CLAUDE.md, cross-tenant pattern).
- **Group owner** (`auth.owner` row with `user_group_id`) and **managing member** (group has `can_members_manage_others`):
  may add/remove members of that group only.
- **End user**: may read own memberships without permission; gets mapped membership by logging in.
- **System / sync job**: `ensure_groups_and_permissions` at login, `process_external_group_member_sync*` (seeded perm set
  "Svc group syncer permissions", 022:728).
- Preconditions: tenant exists; for mappings the provider exists with `allows_group_mapping = true`; for sync,
  `allows_group_sync = true` and group `is_synced = true`.

Terminology: **internal** = `is_external = false`, no mappings; **external** = `is_external = true`;
**hybrid** = `is_external = false` with at least one mapping (docs/concepts/group-types.md).

## Invariants

### Group lifecycle
- **I-03-01** `create_user_group` requires `groups.create_group` in `_tenant_id` and creates the group in `_tenant_id`; journal 13001. Source: docs/reference/groups.md, permission-matrix.md | test test_group_crud
- **I-03-02** Group `code` is generated from the title and is unique per tenant; the same title may exist in different tenants. Source: docs/concepts/group-types.md, 013:333
- **I-03-03** A group can never be both `is_external` and `is_default`; `is_synced` requires `is_external`; `create_missing_users_on_sync` requires `is_synced`. Violations must be rejected (ideally with a domain error, not a raw check violation). Source: docs/concepts/group-types.md (constraints) **[confirm]** (error code)
- **I-03-04** update / enable / disable / lock / unlock / delete / set_as_* / get_by_id act only on a group whose `tenant_id = _tenant_id`. A group of another tenant must be treated as not found (33011), must not be modified, and no journal entry may be written. Source: CLAUDE.md tenant model, CHANGELOG v2.1 (same rule applied to mappings) **[confirm]**
- **I-03-05** Permissions: update/enable/disable/unlock/set_as_* need `groups.update_group`; lock needs `groups.lock_group`; delete needs `groups.delete_group`; get_by_id needs `groups.get_group`. Source: docs/reference/permission-matrix.md, groups.md
- **I-03-06** Operations on an unknown group id raise 33011 rather than silently succeeding (and must not journal). Source: delete_user_group docs (52171->33011) **[confirm]** for update/enable/disable/lock/unlock/set_as_*
- **I-03-07** A system group (`is_system`) cannot be deleted: 33014 (`raise_52271`). Source: docs/reference/groups.md | test none
- **I-03-08** Deleting a group removes its members, mappings, owners, permission assignments and staged sync rows, or is rejected with a domain error; it must never fail with a raw FK violation. Source: docs/reference/groups.md ("ensure_user_groups ... deleted along with their mappings and permission assignments") **[confirm]**
- **I-03-09** Disabled (`is_active = false`) groups contribute **no** membership and **no** permissions to any user, whether membership is manual, external or synced. Source: docs/concepts/group-types.md ("Inactive groups are excluded from permission resolution")
- **I-03-10** Re-enabling a group restores the effect of its existing memberships without re-adding members. Source: common sense **[confirm]**
- **I-03-11** `is_assignable = false` (locked) blocks new manual members (33013) but does not remove existing members or their permissions. Source: unsecure.create_user_group_member 019:1765 **[confirm]**; docs describe lock as "preventing new permission set assignments" - see Open questions
- **I-03-12** disable and lock are independent flags. Source: test test_group_types (TEST 20)
- **I-03-13** Every state change journals 13002 (`group_updated`) in `_tenant_id` with an `action` payload (enabled/disabled/locked/unlocked/set_hybrid/set_external/set_internal); delete journals 13003. Source: test test_group_types (TEST 13-19), 029_seed_data.sql:159-166

### Group types
- **I-03-14** `create_external_user_group` creates an external group and its first mapping atomically; it needs both `groups.create_group` and `groups.create_mapping`; any mapping failure (31004, 33016, ...) leaves no group behind. Source: docs/reference/groups.md | test test_group_types
- **I-03-15** `set_user_group_as_external` deletes all `manual` members, keeps mappings and external/synced members, sets `is_external = true`. Source: docs/concepts/group-types.md | test test_group_types
- **I-03-16** A default group cannot be converted to external; the call is rejected with a domain error (not a raw check violation). Source: constraint `user_group_check` **[confirm]** (error code)
- **I-03-17** `set_user_group_as_internal` deletes all non-manual members and all mappings, and resets `is_external`, `is_synced`, `create_missing_users_on_sync` to false. Source: docs/concepts/group-types.md | test test_group_types
- **I-03-18** `set_user_group_as_hybrid` sets `is_external = false` and keeps all mappings and all members. Source: docs/concepts/group-types.md | test test_group_types
- **I-03-19** `update_user_group` must not be a back door around I-03-15/I-03-17: changing `is_external` through it either applies the same member/mapping side effects or is rejected. Source: common sense **[confirm]**
- **I-03-20** Every type conversion that removes members invalidates the permission cache and group-id cache of every removed member (via the member delete trigger). Source: 033:34-45 comment, docs/concepts/group-types.md

### Manual members
- **I-03-21** `create_user_group_member` adds a row with `member_type_code = 'manual'`; journal 13010 in `_tenant_id`. Source: docs/concepts/group-types.md | test test_auth_group_member_tenant
- **I-03-22** Adding a member requires: the group exists in `_tenant_id` (33011), is active (33012), is assignable and not external (33013). Source: docs/concepts/group-types.md, test test_auth_group_member_tenant/004; tenant part **[confirm]**
- **I-03-23** The target user must exist (33001) **[confirm]**, and should not be added if disabled/locked/deleted **[confirm]** (see Open questions).
- **I-03-24** Authorization for add/remove (`can_manage_user_group`): allowed when (a) the group has `can_members_manage_others` and the caller is an active member of it, or (b) the caller is a tenant-wide owner of `_tenant_id`, or (c) the group has owners and the caller is one of them (else 33015), or (d) the group has no owner and the caller holds `groups.create_member` / `groups.delete_member`. Source: docs/reference/groups.md (can_manage_user_group) | test test_auth_group_member_tenant
- **I-03-25** A group owner of group G is not a tenant-wide owner and gains no rights over other groups. Source: CHANGELOG v2.1 | test test_tenant_scoping_security/001
- **I-03-26** Adding the same user twice as manual member must not create a duplicate row; it is either idempotent or raises a domain error. Source: unique index 013:655 **[confirm]** (which behaviour)
- **I-03-27** `delete_user_group_member` removes only the `manual` row; if the user is an `external`/`synced` member it raises `restricted_operation` and removes nothing. Source: docs/reference/groups.md | test test_auth_group_member_tenant/003
- **I-03-28** Removing a non-member, or a member of another tenant's group, must not journal a 13011 "removed" event **[confirm]**.
- **I-03-29** Adding or removing a member takes effect for that user's permissions and `is_group_member` immediately (permission cache and group-id cache invalidated). Source: docs/concepts/group-types.md step 4 | test test_auth_group_member_tenant/006
- **I-03-30** `get_user_group_members` needs `groups.get_members` in `_tenant_id` and returns only members of a group in `_tenant_id`; cross-tenant read from tenant 1 needs a `read_all`-style permission. Source: CLAUDE.md cross-tenant pattern **[confirm]**
- **I-03-31** `get_user_assigned_groups`: self query needs no permission and is limited to `_tenant_id`; another user's groups need `users.read_user_group_memberships` (own tenant) or `users.read_all_user_group_memberships` (tenant 1, cross-tenant). Source: docs/reference/groups.md | test test_auth_group_member_tenant

### Mappings
- **I-03-32** `create_user_group_mapping` requires `groups.create_mapping` in `_tenant_id`; the group must be in `_tenant_id` (33011) and active (33012); the provider must allow mapping (33016); at least one of `mapped_object_id` / `mapped_role` (31004); a duplicate (group, provider, object, role) raises 33023. Journal 13020. Source: docs/reference/groups.md, CHANGELOG v2.1 | test test_tenant_scoping_security/003 TEST 7, test_provider_crud/008
- **I-03-33** `mapped_object_id` and `mapped_role` are stored lowercase, and matching against `provider_groups` / `provider_roles` is case-insensitive. Source: docs/concepts/group-types.md (storage); matching **[confirm]** (docs say "as-is", code at 019:2071 lowers the claim)
- **I-03-34** `mapped_object_id` matches only `provider_groups`; `mapped_role` matches only `provider_roles`; a mapping with both set matches if either matches **[confirm]**. Source: docs/concepts/group-types.md, identity-providers.md
- **I-03-35** A mapping only matches identities of its own `provider_code`. Source: docs/concepts/identity-providers.md
- **I-03-36** Creating a mapping invalidates the permission cache of every user whose last-used identity of that provider would match it, by object id **and** by role. Source: docs/concepts/group-types.md ("Cache Invalidation on Mapping Changes")
- **I-03-37** `delete_user_group_mapping` requires `groups.delete_mapping`; only a mapping of a group in `_tenant_id` (else 33022, nothing deleted); removes all memberships created through it and invalidates those users' caches; journal 13021. Source: docs/reference/groups.md, CHANGELOG v2.1 | test test_tenant_scoping_security/003 TEST 8
- **I-03-38** `ensure_user_group_mapping(s)` never reads, returns or deletes a mapping of a group outside `_tenant_id`; final-state mode deletes only mappings of the listed (group, provider) pairs in `_tenant_id` and needs `groups.delete_mapping`. Source: docs/reference/groups.md | test test_ensure_functions/004, 008; tenant part **[confirm]**
- **I-03-39** `get_user_group_mappings` / `search_user_group_mappings` follow the cross-tenant pattern (`groups.get_mapping` / `groups.get_all_mappings`). Source: docs/reference/groups.md | test test_cross_tenant_access

### Effective membership (login / recalculation)
- **I-03-40** A user's effective groups in tenant T = active groups of T where the user has a manual row, **or** a synced row, **or** a mapping of the group matches the provider_groups/provider_roles of the user's **last-used** identity. Source: docs/concepts/group-types.md, identity-providers.md "Last Used Provider", CLAUDE.md
- **I-03-41** Only the last-used provider's claims count: after switching provider, mapped memberships derived from the previous provider disappear, including when the new provider has `allows_group_mapping = false`. Source: docs/concepts/identity-providers.md ("their permissions shift") **[confirm]** for the no-mapping-provider case
- **I-03-42** Mapped (`external`) membership is re-evaluated whenever the permission cache is rebuilt; a claim removed at the provider removes the membership at the next recalculation. Source: docs/concepts/group-types.md
- **I-03-43** For an external group, only mapped/synced membership counts; a stray `manual` row must not grant membership. Source: docs/concepts/group-types.md **[confirm]**
- **I-03-44** For a hybrid group, a user who is both a manual member and mapped is a member once; removing either source keeps membership via the other. Source: docs/concepts/group-types.md
- **I-03-45** A disabled identity, a disabled provider, or a provider that no longer allows mapping yields no mapped memberships. Source: docs/concepts/identity-providers.md (disabled provider/identity cannot be used) **[confirm]**
- **I-03-46** A disabled, locked or deleted user has no effective groups; `has_permission` fails with 33003/33004/33001 and the group-id cache is hard-cleared on disable/lock. Source: 033:150, 019:2156-2172 | test test_disabled_locked_users
- **I-03-47** Recalculation must not remove `synced` memberships (they exist for users before their first login), nor `manual` ones. Source: docs/concepts/group-types.md "Why Synced Groups Exist" **[confirm]**
- **I-03-48** Recalculation never grants membership in a group of a tenant the mapping does not belong to; group membership of tenant T only affects permissions in T. Source: CLAUDE.md multi-tenancy
- **I-03-49** `auth.is_group_member` returns true only for active groups of `_tenant_id`. Source: 019:2722 (get_cached_group_ids) | test test_auth_group_member_tenant/006

### Default groups
- **I-03-50** `assign_user_default_groups` requires `users.add_to_default_groups` in `_tenant_id`; adds the target user as `manual` member of every **active** default group of `_tenant_id` only; is idempotent; returns the user's memberships in `_tenant_id`. Source: docs/concepts/group-types.md "Default Groups" | test test_permission_checks
- **I-03-51** The target user must exist (33001); validation is about `_target_user_id`, not the caller. Source: common sense **[confirm]**
- **I-03-52** Default groups are never joined implicitly in tenants the user has not been assigned to (by registration, tenant membership or explicit call); inactive default groups are never joined. Source: docs/concepts/group-types.md (per-tenant, active only) **[confirm]**

### External member sync
- **I-03-53** `get_user_groups_to_sync` returns only synced groups of `_tenant_id` whose provider allows sync, and requires `groups.get_groups`. Source: docs/reference/groups.md; tenant part **[confirm]**
- **I-03-54** Sync functions are permission-checked (caller holds the "Svc group syncer" permissions, e.g. `groups.create_member` / `groups.delete_member`). Source: seeded perm set 022:728 **[confirm]** (docs say "permission check is commented out")
- **I-03-55** `process_external_group_member_sync_by_mapping`: provider must allow sync (33017); staged UPNs matched case-insensitively to `user_info.username`; existing users without a row get a `synced` row; existing mapped rows become `synced`; unknown users are created (via `ensure_user_info` with the mapping's provider) only when `create_missing_users_on_sync`; journal 13030 in the group's tenant. Source: docs/concepts/group-types.md "How Synchronization Works"; tenant of journal **[confirm]**
- **I-03-56** `process_external_group_member_sync` processes only `is_synced` (and active **[confirm]**) groups, and removes `synced` members of a mapping that are not in the stage table for that mapping; returned rows carry correct group/mapping ids; journal 13011 with `action = sync_cleanup`. Source: docs/reference/groups.md
- **I-03-57** Sync never removes `manual` members. Source: docs/concepts/group-types.md **[confirm]**

### Notifications
- **I-03-58** Member insert/delete, group enable/disable/delete/type change and mapping insert/delete each emit one `permission_changes` notification with the group's tenant. Source: 033:229-283, 015:86-93 comment **[confirm]**

## Flows

**Add manual member** - `auth.create_user_group_member(T, G, U)`: `can_manage_user_group` passes -> group in T, active,
assignable, not external -> insert `user_group_member(G, U, manual, mapping_id null)` -> permission cache of U cleared,
group-id cache of U invalidated (trigger) -> notify `group_member_added` -> journal 13010 (T).

**Remove manual member** - checks as above -> reject if U's row is external/synced -> delete manual row -> trigger clears
U's caches -> notify `group_member_removed` -> journal 13011 (T).

**Login with groups** - app calls `ensure_user_from_provider` (sets `last_used_provider_code`), then
`ensure_groups_and_permissions(U, P, groups, roles)`: identity (U, P) arrays replaced -> `recalculate_user_groups(U, P)`:
for each mapping of P matching a claim, ensure an `external` row with that `mapping_id`; delete `external` rows whose
mapping no longer matches; keep manual and synced rows -> caches of affected tenants cleared -> permissions recomputed
per tenant (inactive groups excluded).

**Lazy recalculation** - `has_permissions(U, T)` with an expired cache: user exists -> `recalculate_user_groups(U, last_used_provider_code)`
-> `recalculate_user_permissions(U, T)`.

**Create mapping** - checks (I-03-32) -> insert lowercase mapping -> expire permission cache of users whose identity of P
matches by object id or role -> notify -> journal 13020. Actual `external` rows appear at the users' next recalculation.

**Delete mapping** - check tenant (33022) -> expire caches of users with rows via this mapping -> delete mapping
(rows with that `mapping_id` cascade, trigger clears caches) -> journal 13021.

**Convert type** - see I-03-15/17/18; every removed member row goes through the delete trigger; journal 13002; notify
`group_type_changed`.

**Disable group** - `is_active = false` -> trigger soft-invalidates permission cache and group-id cache of all members
in the group's tenant -> notify `group_disabled` -> journal 13002 -> members lose the group's permissions at next check.

**Sync** - load `stage.external_group_member` -> `process_external_group_member_sync(G)` -> per mapping: create/update
`synced` rows, optionally create users -> delete `synced` rows not staged -> journal 13030 / 13011.

## Failure behaviour

| Operation | Condition | Expected |
|---|---|---|
| any `auth.*` writer | caller lacks the permission in `_tenant_id` | 32001 (via `has_permission`) |
| create_user_group_member | group unknown / in other tenant | 33011 |
| create_user_group_member | group inactive | 33012 |
| create_user_group_member | group not assignable or external | 33013 |
| create/delete member | group has owners, caller not owner nor tenant owner | 33015 |
| create_user_group_member | target user unknown | 33001 **[confirm]** |
| delete_user_group_member | target is external/synced member | SQLSTATE `restricted_operation` (no domain code yet **[confirm]**) |
| delete_user_group | unknown / other tenant | 33011 **[confirm]** for other tenant |
| delete_user_group | system group | 33014 |
| update/enable/disable/lock/unlock/set_as_* | unknown / other tenant | 33011 **[confirm]** |
| set_user_group_as_external | default group | domain error **[confirm]** |
| create_user_group_mapping | neither object id nor role | 31004 |
| create_user_group_mapping | provider disallows mapping | 33016 |
| create_user_group_mapping | group unknown / other tenant | 33011 |
| create_user_group_mapping | group inactive | 33012 |
| create_user_group_mapping | duplicate | 33023 |
| delete_user_group_mapping | unknown / other tenant | 33022 |
| process_external_group_member_sync_by_mapping | provider disallows sync | 33017 |
| assign_user_default_groups | target user unknown | 33001 **[confirm]** |
| ensure_user_groups (final state) | `_source` null | exception (no code **[confirm]**) |

## Open questions

1. **Disabled groups still grant permissions (I-03-09).** `unsecure.recalculate_user_permissions` reads groups from view
   `auth.user_group_members` (019:2218), which does not filter `ug.is_active` (015:46-74). `get_cached_group_ids` does filter
   (019:2748-2752). Docs say inactive groups are excluded. No test disables a group and checks permissions.
2. **Type conversion and member writes are not tenant-scoped (I-03-04, I-03-22).** `set_user_group_as_hybrid` (021:605-609),
   `set_user_group_as_external` (021:678-689) and `set_user_group_as_internal` (021:711-729) filter only by `user_group_id`.
   `unsecure.create_user_group_member` (019:1749-1752) and `auth.delete_user_group_member` (021:296-310) never check the group's tenant,
   and `can_manage_user_group` checks owners/permission in the caller's `_tenant_id`. An admin of tenant A can therefore change
   or delete another tenant's groups, members and mappings. `unsecure.get_user_group_by_id` (019:678) ignores `_tenant_id`, too.
3. **`delete_user_group` existence check ignores tenant (021:246-249)** and selects `is_system, tenant_id` into one variable (the bug
   fixed in v2.1 for mappings). For another tenant's group it deletes nothing but still journals 13003. Also `user_group_mapping.user_group_id`
   and `permission_assignment.user_group_id` have no `on delete cascade` (013:341-342, 013:381-382), so deleting a group with
   mappings or assignments fails with a raw FK error (I-03-08).
4. **`recalculate_user_groups` adds every default group of every tenant (019:2040-2044)**, including inactive groups, with
   no tenant filter, on every cache rebuild. This conflicts with the per-tenant `assign_user_default_groups` (I-03-50, I-03-52).
5. **Synced members are removed at login/recalc (I-03-47).** The cleanup at 019:2059-2075 deletes every row with
   `mapping_id is not null` that the current claims don't match, which includes `synced` rows. With `_provider_code` null
   (user never logged in, e.g. a pre-provisioned synced user) the arrays are null, so every mapped/synced row is deleted.
6. **Provider without mapping keeps stale external rows (I-03-41).** The early return at 019:2046-2057 skips cleanup, so
   memberships mapped from a previous provider survive a switch. Identity/provider `is_active` is never checked in recalc
   (019:2033-2037) (I-03-45).
7. **Mapping-create cache invalidation is wrong (I-03-36).** 048:357-360 matches only `lower(_mapped_object_id)` (against both
   arrays), so role-only mappings invalidate nobody. It also ignores the provider and compares against raw, not lowercased, claims.
8. **Case sensitivity (I-03-33).** Docs say matching is "as-is" and claims must be lowercased by the app. The code lowercases claims
   during recalc (019:2071, 2087). Which one is intended?
9. **Lock semantics (I-03-11).** groups.md says lock prevents "new permission set assignments". The code uses `is_assignable` to block new members.
   Which is it? Should a locked group also refuse perm-set assignment?
10. **Member permissions mismatch.** permission-matrix.md lists `groups.update_group` for create/delete member. groups.md and the code use
    `groups.create_member` / `groups.delete_member`. Also `create_external_user_group` is listed with only `groups.create_mapping`.
11. **Sync functions have no permission check** (021:808, 021:925, commented out). Yet the "Svc group syncer" perm set exists (022:728).
    `process_external_group_member_sync` uses `_user_group_id is null || ...` (021:940). The `||` operator applied to booleans most likely
    fails at runtime, and the function has no test. Its 'deleted' rows use the OUT variables `__user_group_id, __user_group_mapping_id` (021:968-969),
    which are null at that point. Journals go to tenant 1 regardless of the group's tenant (021:905, 985, 1026). `get_user_groups_to_sync`
    ignores `_tenant_id` (021:787-792).
12. **`ensure_user_group_mapping(s)` and tenant.** The existence lookup (021:441-447) has no tenant filter and no permission check.
    Final-state deletion (021:1363-1379) can delete mappings of another tenant's group when given its id. It also invalidates the cache of every
    group member, not just users mapped through the deleted mapping.
13. **`assign_user_default_groups` validates the caller, not the target (019:1637-1639).** Should the target user need to be active and a member of the tenant?
14. **`update_user_group`** can flip `is_external` without the conversion side effects (021:88-98). It also silently updates 0 rows for a foreign or unknown
    group but still journals.
15. **Disabled/locked target users** can be added to groups. Is that intended (pre-provisioning) or should it raise 33003/33004?
16. **`unsecure.get_user_group_members` tenant-1 shortcut (019:1799-1803)** lets tenant 1 callers read any tenant's members with
    `groups.get_members` only, not a `read_all` permission. `can_members_see_others` is not enforced anywhere.
17. **`set_user_group_as_hybrid`** on a group without mappings just yields an internal group. Should that be rejected?

## Known coverage

Suites: `test_group_crud` (CRUD, member/mapping round trip, group permissions), `test_group_types` (conversions, enable/disable/lock
flags and journals), `test_auth_group_member_tenant` (member create/delete, validation 33011-33013, `is_group_member`, `can_manage_user_group`),
`test_group_members_and_delete_tenant` (member listing, tenant delete), `test_tenant_scoping_security/003` (mapping tenant scoping, 33022/33023),
`test_provider_crud/008` (33016/33017), `test_ensure_functions/003,004,007,008` (ensure + final state), `test_cross_tenant_access`,
`test_search_functions` (search), `test_permission_checks` (default groups), `test_disabled_locked_users`.

Most of these call as user 1 (CLAUDE.md test rule), so owner/permission/tenant branches are mostly untested.

No test covers:
- mapped membership end to end: claims -> `external` rows -> permissions; provider switch; claim removal (I-03-34, 35, 40-45)
- disabled group losing permissions, or re-enable (I-03-09, 10)
- cross-tenant group writes: set_as_*, delete group, update/enable/disable, add/remove member (I-03-04, 22)
- cache invalidation on mapping create by role (I-03-36)
- default groups scoped to the tenant and active only, including via recalc (I-03-50-52)
- sync: `get_user_groups_to_sync`, both `process_external_group_member_sync*`, synced rows surviving login (I-03-47, 53-57)
- delete group that has mappings/assignments (I-03-08); system group delete (I-03-07)
- `get_user_group_by_id`, `get_user_group_mappings`, `ensure_user_group_mapping` (single); `internal.resolve_group`
- notification triggers (I-03-58)
