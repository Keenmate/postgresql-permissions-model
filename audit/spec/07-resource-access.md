# 07 - Resource access

## Scope

Resource-level ACL that sits on top of RBAC. It covers resource types, access flags, flag grants and denies, resource roles, path-based (ltree) inheritance, the group-id cache, and the read/filter functions. No update script (048-050) changes any function in this domain. The latest definitions are all in the baseline files.

| Object | Kind | Location |
|---|---|---|
| `const.resource_type`, `const.resource_access_flag`, `const.resource_type_flag` | tables | `034_tables_resource_access.sql:34`, `:48`, `:75` |
| `auth.resource_access` (list-partitioned by `root_type`) | table | `034:100` |
| `const.resource_role`, `const.resource_role_flag` | tables | `034:196`, `:220` |
| `auth.resource_role_assignment` (partitioned by `root_type`) | table | `034:235` |
| `auth.user_group_id_cache` | table | `034:424` |
| `unsecure.ensure_resource_access_partition` | fn | `034:333` |
| `unsecure.validate_resource_id` | fn | `034:382` |
| `unsecure.validate_resource_type`, `validate_access_flags`, `validate_access_flags_for_type`, `validate_resource_identifier` | fn | `035:42`, `:57`, `:83`, `:120` |
| `auth.has_resource_access` | fn | `035:154` |
| `auth.filter_accessible_resources` | fn | `035:311` |
| `auth.get_resource_access_flags` / `get_resource_access_matrix` | fn | `035:500` / `035:634` |
| `auth.assign_resource_access` / `deny_resource_access` / `revoke_resource_access` / `revoke_all_resource_access` | fn | `035:841` / `:968` / `:1065` / `:1149` |
| `auth.get_resource_grants` / `get_user_accessible_resources` | fn | `035:1203` / `:1294` |
| `auth.ensure_resource_type_flags`, `create_resource_type`, `update_resource_type`, `ensure_resource_types`, `get_resource_types` | fn | `035:1470`, `:1577`, `:1663`, `:1741`, `:1856` |
| `auth.ensure_access_flags`, `get_access_flags` | fn | `035:1899`, `:1954` |
| `unsecure.update_resource_type_full_title_translations` | fn | `035:1528` |
| `error.raise_35007/35008/35009` + event codes 18003-18005, 18020-18021 | fn/seed | `043_tables_resource_roles.sql:49-114` |
| `unsecure.validate_resource_role`, `validate_role_flags_for_type` | fn | `044_functions_resource_roles.sql:40`, `:60` |
| `auth.delete_resource_role`, `ensure_resource_role_flags`, `get_resource_role_flags` | fn | `044:102`, `:142`, `:218` |
| `auth.assign_resource_role`, `revoke_resource_role`, `revoke_all_resource_roles` | fn | `044:242`, `:372`, `:450` |
| `auth.create_resource_role`, `ensure_resource_roles`, `update_resource_role`, `get_resource_roles`, `get_resource_role_assignments` | fn | `044:502`, `:581`, `:707`, `:776`, `:814` |
| `unsecure.get_cached_group_ids`, `invalidate_user_group_id_cache`, `clear_user_group_id_cache`, `invalidate_group_members_group_id_cache` | fn | `019_functions_unsecure.sql:2722`, `:2789`, `:2811`, `~:2833` |
| Group-id cache triggers (`cache_user_group_member_*`, `cache_user_group_status_change`, `cache_user_group_before_delete`, `cache_user_group_id_on_user_change`) | trg | `033_triggers_cache_and_notify.sql:37-168`, attached `:469-588` |
| `auth.is_owner` (owner shortcut) | fn | `048_update_permissions_v2-1.sql:102` |
| ACL cleanup in `unsecure.delete_tenant` / `soft_delete_tenant` | fn | `019:1868` / `019:1955` |

## Actors & preconditions

- **Application function** (most common). It calls `has_resource_access` / `filter_accessible_resources` for the end user after an RBAC check (the "dual-check pattern"). It passes the end user's `_user_id` and the `_tenant_id` of the current context.
- **Resource admin** in a tenant. Holds `resources.grant_access`, `resources.deny_access`, `resources.revoke_access` or `resources.get_grants` in `_tenant_id`, and manages grants inside that tenant.
- **App bootstrap / type admin**. Holds `resources.create_resource_type` and registers types, flags and roles at startup (`ensure_*`). Types, flags and roles are **global**, not per tenant.
- **System user (id 1)** and **tenant-wide owner**: short-circuit to "allowed" on every read path.
- **End user, self-query**: `get_user_accessible_resources` with `_user_id = _target_user_id` needs no permission.
- Preconditions: the resource type exists and is active. Flags exist in `const.resource_access_flag`. The target user/group exists. Each root type has partitions created by `ensure_resource_access_partition`.

## Invariants

### Identifier & validation
- **I-07-01** Every grant, deny, role assignment, read check, flag/matrix/grants query and `revoke_all_*` call must supply a non-empty `_resource_id` or a non-null `_resource_path`. Otherwise it raises **35010**. On read paths this check runs before the system-user and owner shortcuts, so even user 1 gets 35010. `_throw_err := false` does not suppress it. Source: CHANGELOG (read-side validation), docs/reference/resource-access.md "Identifier required", test test_resource_access_path/008
- **I-07-02** At the table level, every `resource_access` and `resource_role_assignment` row has a non-null `resource_path` or a non-empty `resource_id`, `resource_id` is a jsonb object, and the row has exactly one of `user_id` / `user_group_id`. Source: docs/concepts "Key constraints", code 034:119-126, 034:253-260, test test_resource_access_path/008 TEST 4
- **I-07-03** A grant, deny or role assignment whose `_resource_id` has a key not declared in the type's `key_schema` raises **35005**. Any subset of declared keys is accepted. An empty `key_schema` accepts any keys. Source: docs/concepts "Composite Resource Keys", CHANGELOG (partial-key grants)
- **I-07-04** Grant, deny and role assignment on a resource type that does not exist or is inactive raise **35003**. Source: docs/reference error table, code 035:42
- **I-07-05** A grant or deny with a flag missing from `const.resource_access_flag` raises **35004**. A flag that exists globally but is not in the type's `resource_type_flag` mapping raises **35006**. A type with no mapping allows every global flag. No rows are written when any flag in the array is invalid. Source: docs/concepts "Per-Type Flag Mapping", test test_resource_access/011
- **I-07-06** Grant and revoke without `_target_user_id` and without `_user_group_id` raise **35002**. Deny without `_target_user_id` raises **35002**, because denies on groups are not supported. Source: docs/concepts "Deny Model", docs/reference
- **I-07-07** Grant, deny and role assignment must reject a call that supplies **both** `_target_user_id` and `_user_group_id` with a domain error before writing anything. Today only the table constraint stops it. **[confirm]** Source: docs/reference ("mutually exclusive")
- **I-07-08** An invalid ltree path (for example a label with `/`) is rejected and nothing is written. Source: test test_resource_access_path/008 TEST 2

### Tenant scoping
- **I-07-09** Every grant, deny and role assignment is stored with `tenant_id = _tenant_id`. Read paths only consider rows of the `_tenant_id` passed in. A grant in tenant A never grants anything when checked with tenant B, and that holds for flags, roles, paths, filter, flags, matrix and grants listings. Source: docs/concepts/multi-tenancy link, tests test_resource_access/006, test_resource_access_path/004, test_resource_roles/006
- **I-07-10** All permission checks on write and admin functions run against `_tenant_id`, the same tenant the rows are written to or read from. Source: docs/reference "Permission required", code 035:865
- **I-07-11** `assign_resource_access` and `assign_resource_role` with `_user_group_id` must reject a group that does not belong to `_tenant_id`, using the same rule and code (**33011**) as `assign_permission` in v2.1. **[confirm]** Source: CHANGELOG v2.1 (tenant-scoping of group targets), common sense
- **I-07-12** Grant, deny and role assignment to a `_target_user_id` that is not a member of `_tenant_id` (no `auth.tenant_user` row) must be rejected. **[confirm]** Source: common sense / multi-tenancy
- **I-07-13** Group-derived access in tenant T only uses active groups that belong to T and of which the user is a member. Source: code comment 034:418, code 019:2741-2747 **[confirm]**

### Check algorithm (`has_resource_access`)
- **I-07-14** User id 1 always gets `true`, for any type, id, path, flag or tenant. This runs after I-07-01. Source: docs/reference step 2, test test_resource_access/002
- **I-07-15** A tenant-wide owner of `_tenant_id` (owner row with `user_group_id is null`) always gets `true`. The owner of only a group does **not** get this shortcut. Source: CHANGELOG v2.1 (is_owner fix), docs/reference step 3, test test_resource_access/002 TEST 6
- **I-07-16** With no matching grant, the check returns `false` when `_throw_err = false`, and raises **35001** otherwise (the default). Source: docs/reference
- **I-07-17** A user-level **deny** for flag F that matches the resource blocks F even when a direct grant, a user role, a group grant or a group role would allow it. Source: docs/concepts "Key rule", tests test_resource_access/003, test_resource_roles/004
- **I-07-18** A deny is per flag. Denying F does not affect any other flag G. Source: docs/concepts "Deny Model", test test_resource_access/003 TEST 2
- **I-07-19** Access is granted when any of these matches the resource for flag F and no deny applies (I-07-17): a direct user grant, a user role whose current flags include F, a grant to one of the user's groups (I-07-13), or a role assigned to one of those groups. Source: docs/reference algorithm step 5
- **I-07-20** **Type hierarchy:** a grant on ancestor type P for key K, where K is the subset of the resource id keys that appear in P's `key_schema`, applies to every descendant type of P for any id that contains K. A grant on a child type never applies to the parent type. Source: docs/concepts "Hierarchical Resource Paths", test test_resource_access/008
- **I-07-21** **Partial keys:** a stored grant or deny whose `resource_id` is a subset of the checked resource's keys (for the same type or an ancestor) matches. For example, a deny on `project.invoices` with `{"project_id":123}` blocks every invoice of project 123. Source: docs/concepts lines 94-95 and deny example, CHANGELOG (containment matching)
- **I-07-22** **Path hierarchy:** a row with `resource_path = A` matches every target path T where `T <@ A`, which includes A itself. A path deny at any ancestor of T blocks the flag. A deny at a descendant of A does not block A or sibling subtrees. Source: docs/concepts "Instance-Level Path Hierarchy", test test_resource_access_path/001-003
- **I-07-23** A path-addressed row (non-null `resource_path`) never matches a check that supplies no `_resource_path`. A hybrid row (path and id) matches only when both the path and the id components match. Source: CHANGELOG (compositional predicate), test test_resource_access_path/005 TEST 4
- **I-07-24** A user deny at any level that covers the resource (ancestor type, ancestor path, or partial key) beats grants found at a more specific level, including a group grant on a child type. ("User-level deny beats all group grants.") **[confirm]** Source: docs/concepts "Key rule", docs/concepts priority list. See OQ-2.
- **I-07-25** A check on a resource type that does not exist or is inactive returns `false` or raises 35001. It never returns `true`, except through the user-1 and owner shortcuts. **[confirm]**
- **I-07-26** Deactivating a resource type must not turn a denied resource into an allowed one. In particular, deactivating a child type must not drop a child-level deny while the parent-level grant keeps working. **[confirm]** See OQ-5.
- **I-07-27** Grants and roles of an **inactive** group give no access. After the group is disabled, access is lost no later than the next call (the cache is invalidated). Source: code 033:47-58 + 019:2743 **[confirm]**
- **I-07-28** A role that is inactive (deactivated by `update_resource_role` or `ensure_resource_roles(_is_final_state)`) gives no access through existing assignments. **[confirm]** See OQ-4.
- **I-07-29** Changing a role's flags (`ensure_resource_role_flags`, `ensure_resource_roles`) changes access for every assigned user and group on the next check, with no data migration. Direct flag grants are not affected. Source: docs/concepts "Expand at check time", test test_resource_roles/005
- **I-07-30** A disabled, locked or deleted user gets `false` from `has_resource_access` (and nothing from `filter_accessible_resources`) even when direct grants exist. **[confirm]** See OQ-8.
- **I-07-31** A soft-deleted tenant grants no resource access to anyone except user 1. This includes its owners. **[confirm]** See OQ-9.

### Read-function consistency
- **I-07-32** `filter_accessible_resources(ids|paths, F)` returns exactly the inputs for which `has_resource_access(..., F, _throw_err := false)` would return `true`, under the same rules (type hierarchy, partial keys, paths, hybrid rows, roles, groups, denies). Source: docs/reference ("Applies the same deny-overrides algorithm") **[confirm]** for hierarchy and partial-key parity. See OQ-3.
- **I-07-33** `filter_accessible_resources` with both inputs null returns an empty set. For user 1 and the tenant owner it returns every input unchanged. Path results come back as `{"path": "<ltree>"}`. Source: docs/reference
- **I-07-34** `get_resource_access_flags` returns flag F exactly when `has_resource_access(..., F)` is `true`. `__source` is one of `system`, `owner`, `direct`, `role:<code>`, `<group title>`, `<group title> (role:<code>)`, chosen by the precedence direct > user role > group > group role. Source: docs/reference source table, tests test_resource_access/005, test_resource_roles/003
- **I-07-35** For user 1 and the owner, `get_resource_access_flags` and `get_resource_access_matrix` return only flags valid for the type (per `resource_type_flag`). Source: docs/concepts (matrix rule), test test_resource_access/011 TEST 10. Flags function: **[confirm]**
- **I-07-36** `get_resource_access_matrix(type, id)` returns, for every active descendant type D of `type`, the flags the user would get from `has_resource_access(D, id, F)`. Inherited flags appear unless D has a matching deny. Source: docs/reference matrix, test test_resource_access/009
- **I-07-37** `get_resource_grants` lists the rows stored on the **exact** resource (same type, same `resource_id`, same `resource_path`). It includes denies, and role assignments expanded to flags with `is_deny = false`. It does not walk the hierarchy. Source: docs/reference, test test_resource_access_path/009
- **I-07-38** `get_user_accessible_resources` for another user requires `resources.get_grants` in `_tenant_id`. For self it is free. It must never list a resource/flag that `has_resource_access` would deny for that user. Source: docs/reference. The "never list a denied" part is **[confirm]**. See OQ-7.

### Grant / deny / revoke writes
- **I-07-39** `assign_resource_access` requires `resources.grant_access`, `deny_resource_access` requires `resources.deny_access`, and `revoke_resource_access` and `revoke_all_resource_access` require `resources.revoke_access`. A caller without the permission gets **32001** and no rows change. Source: docs/reference "Required Permissions Summary"
- **I-07-40** Grant and deny are upserts per (tenant, type, resource_id, resource_path, target, flag). Repeating a grant creates no duplicate. Granting over a deny flips `is_deny` to false, denying over a grant flips it to true, and `granted_by` and `updated_*` are refreshed. Source: docs/reference, tests test_resource_access/001, 003 TEST 4
- **I-07-41** `revoke_resource_access` deletes only rows on the exact resource (same id and same path, no descendants) for the given target. `_access_flags = null` revokes all flags of that target there. It returns the deleted count. Revoking a deny restores whatever the remaining grants give. Source: docs/reference, tests test_resource_access/001, test_resource_access_path/006 TEST 1
- **I-07-42** `revoke_all_resource_access(type, id, path)` deletes every grant and deny (all users and groups) in `_tenant_id` on that resource and its sub-resources: rows whose `resource_id @> _resource_id` and/or whose `resource_path <@ _resource_path`, limited to `_resource_type` and its descendant types. It must not delete rows of ancestor or sibling types. The type limit is **[confirm]**. See OQ-6. Source: docs/reference, test test_resource_access_path/006 TEST 2
- **I-07-43** Write events go to the journal in `_tenant_id`: grant **18010**, revoke **18011**, deny **18012**, bulk revoke **18013** (with `deleted_count`). Each payload includes resource_type, resource_id, resource_path, target and flags. Source: docs/reference "Journal Events"

### Resource types, flags, roles (global metadata)
- **I-07-44** Type, flag-mapping and role management (`create/update/ensure_resource_type(s)`, `ensure_access_flags`, `ensure_resource_type_flags`, `create/update/ensure/delete_resource_role(s)`, `ensure_resource_role_flags`) requires `resources.create_resource_type`. The `get_*` metadata readers (`get_resource_types`, `get_access_flags`, `get_resource_roles`, `get_resource_role_flags`) require nothing. Source: docs/reference summary
- **I-07-45** Registering a root type creates both `auth.resource_access_<root>` and `auth.resource_role_assignment_<root>` partitions. Child types share the root's partitions. `root_type` stored on rows always equals `split_part(resource_type, '.', 1)`. Source: docs/concepts "Partitioning"
- **I-07-46** A child type (code with dots) can only be registered when its parent type exists and is active. `ensure_resource_types` orders items parents-first. Source: docs/reference (`_parent_code` "must exist and be active", "validates parent references") **[confirm]**. See OQ-10.
- **I-07-47** `ensure_resource_type_flags(type, flags)` leaves the mapping exactly equal to `flags`. An empty array clears it (all flags allowed), and `null` is a no-op. Unknown flags raise 35004 and an unknown type raises 35003. Source: docs/reference, test test_resource_access/011
- **I-07-48** A role belongs to exactly one resource type. Assigning it on another type raises **35009**. Assigning an unknown or inactive role raises **35007**, and so does an empty `_role_codes`. Role flags not valid for the role's type raise **35008**. Source: docs/reference, test test_resource_roles/001-002
- **I-07-49** Roles are grant-only. There is no role-level deny, and a user flag deny blocks the matching flag from any role. Source: docs/concepts "Grant-only", test test_resource_roles/004
- **I-07-50** `assign_resource_role` is idempotent per (tenant, type, id, path, target, role) and requires `resources.grant_access`. `revoke_resource_role` (exact resource, `null` = all roles of the target) and `revoke_all_resource_roles` (containment/path cascade like I-07-42) require `resources.revoke_access`. `get_resource_role_assignments` requires `resources.get_grants`. Source: docs/reference
- **I-07-51** Role events: created **18003**, updated **18004**, deleted **18005**, assigned **18020**, revoked **18021** (also used by `revoke_all_resource_roles`). Source: docs/reference "Journal Events"
- **I-07-52** `delete_resource_role` removes the role, its flags and all its assignments in every tenant, and logs 18005. Source: docs/reference, test test_resource_roles/001 TEST 4, 007
- **I-07-53** `ensure_resource_roles(_is_final_state := true, _source := S)` deactivates every active role of source S that is not in the input, and never touches roles of other sources. Source: docs/reference, test test_resource_roles/001 TEST 6
- **I-07-54** Removing a flag from a type's mapping (`ensure_resource_type_flags`) must not leave that flag effective through existing grants or roles on that type. Either those grants and role flags are removed, or the change is rejected. **[confirm]** See OQ-11.

### Cache
- **I-07-55** There is no ACL result cache. Every grant, deny, revoke or role change takes effect on the very next check. Source: code (read paths query tables directly) **[confirm]**, tests test_resource_access/003 TEST 3, test_resource_roles/005
- **I-07-56** `auth.user_group_id_cache` (per user and tenant) is filled on demand with a TTL of `auth.perm_cache_timeout_in_s` (default 300 s). It is soft-invalidated on group member insert/delete, group activation change and group delete. It is hard-cleared on user disable, lock and delete, and for the whole tenant on tenant delete or soft delete. A membership change is visible on the next check, not after the TTL. Source: docs/concepts `user_group_id_cache`, test test_resource_access/010
- **I-07-57** Group-derived resource access for external and hybrid groups follows the user's **last-used identity** in the same way as RBAC. A mapping-derived membership that RBAC would recalculate must not stay stale in the group-id cache. Source: docs/concepts "All group types ... work equally" **[confirm]**. See OQ-12.

### Cleanup
- **I-07-58** Deleting a user deletes all their resource_access and role-assignment rows and their group-id cache. Rows they granted keep existing with `granted_by = null`. Source: docs (FK cascade), test test_resource_access/007
- **I-07-59** Deleting a group deletes all its resource_access and role-assignment rows, and members' group-id caches are invalidated. Source: test test_resource_access/007 TEST 2, code 033:65-87
- **I-07-60** Hard-deleting a tenant deletes all its resource_access and role-assignment rows and its group-id cache rows. Source: test test_resource_access/007 TEST 3, code 019:1868-1885
- **I-07-61** Deleting a resource type with existing grants is either blocked or cascades. It never leaves orphan rows. Source: code 034:108 (FK without cascade) **[confirm]**

## Flows

**Grant (user or group)**
1. `has_permission(_user_id, 'resources.grant_access', _tenant_id)`, else 32001.
2. Validate target (35002), identifier (35010), type (35003), flags (35004/35006) and resource_id keys (35005).
3. For each flag, upsert one row `(tenant, type, root_type, resource_id, resource_path, target, flag, is_deny=false, granted_by=_user_id)`.
4. Return one `(id, flag)` row per flag and write journal 18010. There is no cache change. The next `has_resource_access` sees the row.

**Deny**: same as grant with `resources.deny_access`, a user target only, `is_deny=true`, and journal 18012. After a deny, `has_resource_access` for that flag is false for that user under any group or role grant (I-07-17, I-07-24).

**Revoke / revoke all**: `resources.revoke_access`. Deletes exact-resource rows (revoke) or the subtree (revoke all, I-07-42) and writes journal 18011 / 18013 with `deleted_count`. When an app deletes a resource it is expected to call both `revoke_all_resource_access` and `revoke_all_resource_roles`.

**Check**
1. Validate the identifier (35010).
2. User 1 gets true. The tenant-wide owner of `_tenant_id` gets true.
3. Load group ids from the cache, recalculating on a miss (this writes `user_group_id_cache`).
4. Evaluate deny, then the grant sources, across the type ancestors, partial keys and ancestor paths.
5. Return true or false, or raise 35001.

Side effects: only the group-id cache upsert. No journal entry.

**Role assignment**: `resources.grant_access`. Validate the identifier, the type, the keys, a non-empty role list, and for each role that it is active (35007) and of the same type (35009). Upsert the assignment row, then write journal 18020.

**Type registration**: `resources.create_resource_type`. Insert the type (idempotent) and its translations, recompute `full_title` for the type and its descendants, insert the flag mapping, create the partitions, and write journal 18001.

## Failure behaviour

| Operation | Condition | Expected |
|---|---|---|
| any read/write with an identifier | empty id and null path | 35010 (before shortcuts, independent of `_throw_err`) |
| `has_resource_access` | no grant / denied | 35001, or `false` with `_throw_err := false` |
| grant/deny/revoke/revoke_all, role assign/revoke | caller lacks the permission in `_tenant_id` | 32001, nothing written |
| grant/revoke/role assign/role revoke | no target | 35002 |
| deny | no `_target_user_id` (group only) | 35002 |
| grant/deny/role assign | type unknown or inactive | 35003 |
| grant/deny/type create/flag ensure | flag not registered | 35004 |
| `ensure_access_flags` | item without `code` or `title` | 35004 |
| grant/deny/role assign | `resource_id` key not in schema | 35005 |
| grant/deny | flag not valid for type | 35006 |
| role assign/update/delete/flags | role unknown (or inactive, for assign) / empty role list | 35007 |
| role create/ensure/flags | role flag not valid for type | 35008 |
| role assign | role type differs from `_resource_type` | 35009 |
| grant/role assign | group from another tenant | 33011 **[confirm]** |
| grant/deny/role assign | target user not in tenant | domain error, code TBD **[confirm]** |
| grant/deny/role assign | both user and group given | domain error (35002?) instead of a raw check violation **[confirm]** |
| `update_resource_type` / `ensure_resource_type_flags` | type unknown | 35003 |
| `get_resource_grants` / `get_resource_role_assignments` / `get_user_accessible_resources` (other user) | caller lacks `resources.get_grants` | 32001 |

## Open questions

- **OQ-1 Partial-key matching regressed (likely bug).** The docs (concepts:94-95, the deny-on-invoices example at :321-336) and CHANGELOG ("ancestor-level lookups now use containment") say a stored partial key matches every descendant id. `has_resource_access` uses equality: `ra.resource_id = __ancestor_key` (`035:216`, `:235`, `:253`, `:268`, `:286`). Git shows the containment form `__ancestor_key @> resource_id` was added in `80aea7f` and replaced by equality in `d71afdb` ("consolidate dup defs"). So the documented deny `{"project_id":123}` on `project.invoices` does **not** block Bob's group grant on `project`. No test covers partial keys.
- **OQ-2 Deny precedence across type levels.** The walk returns on the first level that has any match (`035:189-292`). So a user grant, user role, **group grant** or group role on a child type wins over a user deny on the parent type for the same flag. In the path dimension, by contrast, an ancestor deny always wins (both rows are evaluated at the same level). The concepts doc says deny "overrides everything" and "user-level deny beats all group grants". The reference doc describes per-level precedence. Which one is intended? I-07-24 assumes the deny wins.
- **OQ-3 `filter_accessible_resources` disagrees with `has_resource_access`.** (a) The id branch uses `ra.resource_id @> r.id` (`035:369` etc.): stored ⊇ candidate. There is no ancestor key extraction, so a parent-type grant `{project_id:42}` does not cover candidate `{project_id:42, folder_id:1}`, while a stored child grant does cover a partial candidate (over-grant). (b) The path branch ignores `resource_id` of hybrid rows (`035:429-487`), which over-grants compared with `has_resource_access`. (c) The id branch ignores all path rows and the path branch ignores all id-only rows. A path deny therefore never removes an id candidate, and the reverse is also true. `get_resource_access_flags` and the matrix use the same reversed `ra.resource_id @> _resource_id` (`035:553`, `:703`), so parent-type grants with a narrower `key_schema` are missing from the flags output. Tests only use same-shape keys.
- **OQ-4 Inactive roles still grant.** None of the read functions join `const.resource_role.is_active` (`035:244-257` etc.). `ensure_resource_roles(_is_final_state)` and `update_resource_role(_is_active := false)` therefore do not revoke access. Is "deactivate" meant to cut access (I-07-28)?
- **OQ-5 Inactive resource types.** The ancestor walk skips inactive types (`035:193`). Deactivating a child type drops its denies (and its grants), while grants on the active parent still cascade to it. Also `revoke_resource_access`, `revoke_all_*` and `revoke_resource_role` call `validate_resource_type` (`035:1093`, `:1167`, `044:400`), so grants on a deactivated type **cannot be revoked**. What is the intended behaviour?
- **OQ-6 `revoke_all_resource_access` / `revoke_all_resource_roles` ignore `_resource_type`.** They filter only by `root_type` + tenant + id/path (`035:1177-1181`, `044:475-479`). Revoke-all on `project.invoices {project_id:42}` also deletes `project` and `project.documents` rows for project 42. With path-only input they delete every row under the path for the whole root type.
- **OQ-7 `get_user_accessible_resources` deny handling.** Denies are subtracted only on an identical `(resource_id, resource_path, flag)` and not on `resource_type` (`035:1348-1353`). An ancestor-path deny or a partial-key deny does not remove a descendant grant, so the listing shows resources that `has_resource_access` denies. It also has no user-1/owner handling and is never tested (coverage.md).
- **OQ-8 Disabled/locked/deleted users.** `has_resource_access` never checks `user_info.is_active` / `is_locked` (`035:154-300`). Clearing the cache on disable (`033:150-168`) only forces a rebuild, and direct grants still apply. RBAC `has_permissions` has the same gap (domain 04). Is the resource check meant to be safe on its own?
- **OQ-9 Soft-deleted tenants.** `soft_delete_tenant` keeps ACL rows (`019:1955-1971`) and the read paths do not look at `tenant.deleted_at`. Access continues for grantees and owners.
- **OQ-10 Parent type existence.** The docs list a `_parent_code` parameter ("must exist and be active") and a `parent_code` column. Neither exists. The parent is derived from the dotted code and never validated (`035:1613-1617`, `:1795-1803`). A child type can be created with no parent and is then silently a root for checks, while its rows still go to the `split_part` root partition, which may be the default one. Also, re-creating an existing type silently ignores a changed `key_schema` and still logs 18001.
- **OQ-11 Removing a flag from a type mapping** (`035:1503-1505`) leaves existing grants with that flag and role flags effective. Should it cascade or be rejected?
- **OQ-12 External group freshness.** `get_cached_group_ids` reads only `user_group_member` (`019:2741-2747`) and never calls `recalculate_user_groups`. RBAC does call it on a cache miss (`022:101-104`). Mapping-derived membership seen by resource checks therefore depends on whether an RBAC check ran first.
- **OQ-13 Tenant membership and cross-tenant group targets.** Grant, deny and role assignment do not check that `_user_group_id` belongs to `_tenant_id` or that `_target_user_id` is a tenant member (`035:885-895`, `044:286-296`). A foreign group's grant is inert (filtered by `ug.tenant_id` in the cache). A non-member user's grant is fully effective. v2.1 fixed the equivalent gap in `assign_permission` (33011).
- **OQ-14 Audit gaps.** A denied `has_resource_access` writes no journal entry, unlike RBAC 32001 (`022:118-125`). `ensure_resource_type_flags`, `ensure_access_flags` and `update_resource_role` deactivation write no or generic events. `delete_resource_role` does not record how many assignments were cascaded. Is that intended?
- **OQ-15 `get_resource_role_assignments`** has no `_resource_path` parameter and does not call `validate_resource_identifier` (`044:814-871`). Path-only role assignments therefore cannot be listed.
- **OQ-16 Matrix semantics with child-specific rows.** The matrix matches child rows with `resource_id @> _resource_id` (`035:703-746`). A grant or deny on one invoice therefore shows as a type-wide grant or deny on `project.invoices` in the matrix for the project. Is that intended?

## Known coverage

- `test_resource_access` (transaction): grant/revoke, deny overrides, filter (flat `{id}` keys only), flags/grants, tenant isolation, cascade on user/group/tenant delete, type hierarchy with same-prefix keys, matrix, group-id cache (populate, hit, soft invalidation, hard clear on disable), per-type flags.
- `test_resource_access_path`: path inheritance, path deny scoping, group plus user deny, path tenant isolation, composite/path coexistence, revoke vs revoke-all on paths, role paths, invalid input (35010, ltree), flags/grants on paths, path filter.
- `test_resource_roles`: role CRUD, assignment, checks with roles, deny vs role, redefinition, tenant isolation, cascade on role delete, parent-type role cascade.
- All three suites use a dedicated `system_admin` user as the actor (not user 1). That follows the CLAUDE.md rule.

**Invariants with no test:** I-07-07, I-07-11, I-07-12, I-07-15 (group owner must *not* bypass), I-07-21 (partial keys), I-07-24 (parent deny vs child grant), I-07-25/26 (inactive type), I-07-27 (inactive group), I-07-28 (inactive role), I-07-30, I-07-31, I-07-32 parity for hierarchy, partial keys and hybrid rows, I-07-35 (flags function for user 1/owner), I-07-38 (`get_user_accessible_resources`: never called by any test), I-07-39 (no test calls any write as an unauthorized user, so 32001 is untested), I-07-42 type scoping, I-07-43/51 (journal events never asserted), I-07-46, I-07-50 (`revoke_all_resource_roles` never called), I-07-54, I-07-57, I-07-61, and `update_resource_type` (never called).

**Perf notes for the performance phase:**
- `has_resource_access` runs up to 5 `exists` probes per ancestor level, and each uses `or` predicates (`resource_path is null or ...`, `resource_id = '{}' or ...`) that may defeat the GiST/GIN indexes.
- `filter_accessible_resources` runs 5 correlated subqueries per candidate.
- Every read path may write `user_group_id_cache`, so these functions cannot be `stable` and cannot run on read replicas.
- `get_resource_access_flags` and the matrix scan all of the user's and groups' rows in the root partition.
