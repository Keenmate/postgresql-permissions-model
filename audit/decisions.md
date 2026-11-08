# Audit decisions

There are about 125 open questions across the 8 specs, plus roughly 238 `[confirm]` markers. Most of
them come down to the design decisions below. Answer these and I will apply the answers back to the
specs; what is left after that is a short list of domain-specific questions (section C).

How to answer: fill in the **Answer** line, either with the option letter or in your own words.
"Rec" is my recommendation. References use the form `spec/question`, for example `01/OQ-05` is
`spec/01-registration-ensure.md`, open question OQ-05.

---

## A. Design decisions

### D-01 Must failure side effects persist when the call raises?
Today several functions write an event or state and then raise in the same transaction, so all of it
is rolled back:
- failed login and `record_login_failure`, which means auto-lockout never counts
- `verify_mfa_challenge`, which means MFA brute-force protection does nothing and the token stays
  `valid`
- `validate_api_key` failure
- the `has_permissions` 32001 denial journal
- an expired invitation's status update

- **a)** Authentication flows (login, MFA verify, API key validate) **return a status row instead
  of raising**. The failure event, counter, lock and token state commit normally. The caller turns
  the status into an error.
- **b)** Keep raising, but write the failure through an autonomous transaction (`dblink` to self).
  This adds an extension dependency and the cost of a connection on every failure.
- **c)** Keep raising and document that the app must catch the error and call a separate
  `record_*` function.
- **Rec:** **a** for authentication flows, because lockout is a security control and must not depend
  on the app getting it right. For permission denials (32001), **c**: `has_permissions` keeps
  raising, the app library logs denials, and `get_security_events` stops promising them.
- Refs: 01/OQ-05, 02/1, 04/OQ-04, 06/Q6, 08/Q-01
- **Answer:** a for authentication flows, implemented in v2.6 (`audit/design-d01-auth-outcomes.md`): changed in place, `create_*_attempt` functions, outcome = `__event_id` / `__outcome_code` / `__user_event_id`, temporary escalating lockout in `auth.user_login_state`. Permission denials (32001): still open.

### D-02 Must an entity passed by id belong to `_tenant_id`?
This is the most common bug class found, appearing in 6 specs. Functions take a group, perm set,
API key, invitation, tenant uuid, resource grant or owner row by id and never check that it belongs
to the caller's `_tenant_id`.
- **a)** Strict: for every write and every per-entity read, the entity's tenant must equal
  `_tenant_id`. A mismatch raises the same *not found* error as a missing id, so the entity's
  existence is not revealed. Tenant-1 admins act in another tenant by calling with that tenant's
  `_tenant_id`, and need the permission there.
- **b)** Same as a, but a caller in tenant 1 holding the permission in tenant 1 may write to any
  tenant (the write-side mirror of `read_all_*`).
- **Rec:** **a**. It is simple, uniform and easy to test. If cross-tenant administration is needed,
  it should go through explicit tenant-1-only functions (see D-07), not through a general exception.
- Refs: 01/OQ-09, 01/OQ-10, 02/9, 03/2, 03/3, 03/12, 03/16, 04/OQ-18, 05/Q2, 05/Q8, 06/Q1, 06/Q4,
  07/OQ-13
- **Answer:** **a**. Done in v2.8 (`055`) for groups, members, group owners, API keys,
  invitations, invitation templates and MFA policies. Global templates and policies (`tenant_id` null)
  belong to tenant 1. User lock/disable/MFA reset are global user state: see D-04, still open.

### D-03 What makes a user a member of a tenant?
`auth.tenant_user` is written only by invitations, yet `search_users` filters on it. The other tenant
functions use group membership. Permission calculation requires neither.
- **a)** `tenant_user` is the source of truth. It is maintained automatically: a row is added when
  the user joins any group in the tenant, gets a direct assignment, accepts an invitation, or a
  tenant is created with them as owner. Permission calculation and tenant-scoped admin operations
  on a user require the row.
- **b)** Drop `tenant_user`; membership means belonging to at least one group in the tenant.
- **c)** Keep both definitions and only make them consistent where they are read.
- **Rec:** **a**. Membership becomes explicit and indexed (useful for the performance phase), and
  it gives D-02 and D-04 a way to decide whether a user is in a tenant.
- Refs: 01/OQ-06, 03/13, 03/15, 04/OQ-13, 05/Q4, 05/Q5, 07/OQ-13
- **Answer:**

### D-04 Who may change global user state?
Users are global: lock, disable, enable, password, MFA reset, identities and blacklist apply to the
user everywhere. Today an admin in any tenant can lock any user, including tenant-1 admins.
- **a)** Global user state needs the permission in **tenant 1**. Tenant-N admins can only manage the
  user's membership and grants in tenant N.
- **b)** A tenant-N admin may change a user's global state only if the user belongs to tenant N
  alone (by D-03).
- **Rec:** **a**. Option b is fragile: the rule changes the moment the user joins a second tenant.
  Self-service actions (own password, own MFA) need no permission. Admin actions on other users
  follow a.
- Refs: 02/2, 02/9
- **Answer:** **a** ("users are global, so it makes no sense any other way"). Done in v2.9 (`056`).
  Self-service unchanged: own password, identity link, profile data and preferences.

### D-05 Owners: keep the bypass in `has_permissions`, or replace it?
A tenant-wide owner currently passes every check before any status check. This applies even when
the owner is disabled or locked, or the tenant is soft-deleted, and it also covers global operations
such as changing the permission tree. The code comment there says "NOT REALLY SAFE".
- **a)** Keep the bypass, but run it after the status checks (user active and not locked, tenant
  not deleted), and never apply it to global, tenant-1-only permissions.
- **b)** Remove the bypass. `create_owner` assigns the seeded "Tenant owner" perm set instead (it
  already exists), so ownership becomes an ordinary, cached and inspectable grant. Group owners get
  only member management of their own group.
- **Rec:** **b**. It removes a hidden path around the cache and every status check, and permission
  checks get faster because the owner lookup goes away. Option a keeps a second code path that
  every future fix would have to remember.
- Refs: 02/5, 04/OQ-01, 04/OQ-07, 05/Q8, 05/Q9, 08/Q-03
- **Answer:**

### D-06 Does every inactive or deleted state remove access?
The proposed rule:
- A disabled, locked or deleted user fails every check (RBAC, resource access, provider login,
  API key validation).
- Disabled groups, identities, providers, roles and resource types contribute nothing.
- A soft-deleted tenant fails every check inside it.
- An expired API key's technical user fails `has_permission` as well, not only `validate_api_key`.
- `_throw_err := false` returns `false` instead of raising 33003/33004.
- **a)** Yes, apply this rule everywhere.
- **b)** Yes, with exceptions (list them).
- **Rec:** **a**. Revoking a grant on a deactivated resource type must keep working (07/OQ-5), so
  revoke calls skip the "type is active" validation.
- Refs: 01/OQ-04, 02/4, 03/1, 03/6, 04/OQ-02, 04/OQ-03, 04/OQ-05, 05/Q3, 06/Q3, 06/Q7, 07/OQ-4,
  07/OQ-5, 07/OQ-8, 07/OQ-9, 08/Q-17
- **Answer:** **a**, including the "what it does not mean" list: no data deleted, pre-provisioning
  allowed, tenant-1 admin reads unaffected, revokes never blocked. RBAC part done in v2.7 (`054`).
  Resource access and API-key expiry are still to do, together with D-14.

### D-07 Which operations are global (tenant 1 only)?
Today many global objects are changed by checking a permission against whatever `_tenant_id` the
caller passes.
- **Proposed tenant-1-only list:**
  - the permission tree (create, assignable, ensure)
  - tenant lifecycle (create, delete, restore, purge)
  - `is_system` perm sets
  - token types
  - the blacklist
  - global (null-tenant) MFA policies
  - system parameters
  - event categories, codes and messages
  - providers
  - resource types and access flags
  - languages
- **Rec:** accept the list, and have a null `_tenant_id` raise an error instead of silently falling
  through. `update_sys_param` gets a real permission instead of the `user_id = 1` check, and the
  `public` event-code functions get permission checks.
- Refs: 02/3, 02/9, 04/OQ-07, 04/OQ-08, 05/Q2, 08/Q-11, 08/Q-12
- **Answer:**

### D-08 Fix the seeded perm sets
- The `read_all_*` permissions sit under assignable parents (`users`, `groups`, `tenants`,
  `api_keys`, `authentication`). So User manager, Group manager, API key manager and Tenant admin
  silently grant cross-tenant reads.
- Tenant admin, which is copied into every new tenant, holds the whole `tenants` subtree, including
  delete and purge of tenants.
- Every assignable set received all MFA and MFA-policy permissions.
- API key manager includes `read_outbound_secret`.
- Tenant owner references a permission code that does not exist.
- **a)** Keep the permission codes. Rewrite the seeded sets with explicit child lists, so that the
  `read_all_*`, tenant lifecycle, MFA admin and `read_outbound_secret` permissions are only in
  System admin and Full admin.
- **b)** Also move the `read_all_*` and lifecycle permissions to a separate non-assignable subtree.
  This is a breaking change for apps that check those codes.
- **Rec:** **a**, delivered as an update script that also repairs existing tenants' copies of the
  sets. Reading outbound secrets across tenants requires `read_outbound_secret` in tenant 1.
- Refs: 02/2, 04/OQ-15, 04/OQ-16, 05/Q2, 05/Q11, 06/Q2
- **Answer:**

### D-09 Where does the cross-tenant read check `read_all_*`?
`resolve_cross_tenant_access` checks it in the *target* tenant for a narrowed read, but in tenant 1
for the "all tenants" read. So holding the permission in tenant X, or owning X, lets you query X
"from tenant 1". The CHANGELOG and tests currently encode this behaviour.
- **a)** Both branches check in tenant 1.
- **b)** Keep it as it is.
- **Rec:** **a**. Updating the CHANGELOG note and the tests is part of the fix.
- Refs: 05/Q1, 08/Q-03
- **Answer:**

### D-10 Account linking, and the unchecked `ensure_*` / `register_user` functions
Registering with a username that already exists returns the existing user, and a new identity
(including an email and password one) is attached to it. This is a likely account takeover.
- **a)** Never link automatically. An existing username or email raises an error, and linking a
  second identity needs an explicit call made by the already authenticated user (or an admin).
- **b)** Link automatically only when the provider asserts a verified email that matches a verified
  existing identity.
- **Rec:** **a**. An ambiguous identity lookup (uid matches one user, oid another) raises an error.
  `ensure_user_from_provider`, `ensure_user_info` and `register_user` stay permission-free (they are
  the login and registration entry points) but are listed explicitly as documented exceptions to the
  "auth always checks" rule.
- Refs: 01/OQ-01, 01/OQ-03, 01/OQ-11
- **Answer:**

### D-11 Invitations: whose authority do their actions use?
At the moment someone with only `invitations.create_invitation` can attach "assign the Full admin
set" to an invitation.
- **a)** At creation, each action is validated as if the inviter performed it directly: same
  permission checks, same tenant. On accept, the actions run through the `auth.*` functions as the
  inviter, so a revoked or disabled inviter makes them fail.
- **b)** Validate only at creation and run as the system on accept.
- **Rec:** **a**. Accept, reject and revoke also check that `_tenant_id` matches the invitation's
  tenant, and that the accepting user matches `target_email`.
- Refs: 01/OQ-09, 01/OQ-10, 01/OQ-13
- **Answer:**

### D-12 How do external and synced memberships live and die?
The proposed rule:
- `external` member rows (from login claims) are rebuilt from the last-used identity on every login
  or recalculation. Switching provider removes the previous provider's rows, even when the new
  provider does not support mapping.
- `synced` rows belong only to the sync process; login recalculation never deletes them.
- Claims from a disabled identity or provider count for nothing.
- Claim matching is case-insensitive on both sides. The code already lowercases claims; the docs
  will be updated.
- Resource-access group lookup uses the same freshness as RBAC.
- **Rec:** accept as written.
- Refs: 03/5, 03/6, 03/7, 03/8, 07/OQ-12
- **Answer:**

### D-13 Default groups
Today every cache rebuild adds the user to every default group in **every** tenant, including
inactive groups.
- **Proposed rule:** a tenant's default groups are assigned once, when the user becomes a member of
  that tenant (D-03), and only active default groups count. Removing someone from a default group
  is not undone by the next rebuild.
- **Rec:** accept.
- Refs: 01/OQ-06, 03/4, 04/OQ-06
- **Answer:**

### D-14 Resource access semantics
- **Precedence:** a deny on the user (or any group) at any ancestor level, whether type-level or
  path-level, beats every grant. Today the first type level with any match wins, so a child-type
  grant beats a parent-type deny.
- **Partial keys:** a stored partial key matches all descendants (containment). This was the
  documented behaviour until commit `d71afdb` lost it.
- **Bulk functions:** `filter_accessible_resources`, `get_resource_access_flags`, the matrix and
  `get_user_accessible_resources` must give exactly the same answer as `has_resource_access` for
  every candidate. This becomes a property test that compares them.
- **Rec:** accept all three. Removing a flag from a type mapping makes existing grants with that
  flag stop counting (07/OQ-11).
- Refs: 07/OQ-1, 07/OQ-2, 07/OQ-3, 07/OQ-7, 07/OQ-11, 07/OQ-16
- **Answer:**

### D-15 What happens when the target is missing, foreign or a system object?
Today update, delete and state-change functions silently change 0 rows and still journal (and
`update_api_key_secret` even returns a new secret).
- **Rec:** raise the domain's *not found* error, write no journal or event, and treat an entity in
  another tenant as not found (D-02). System users and system objects raise a "cannot modify system
  object" error.
- Refs: 02/10, 03/3, 03/14, 05/Q7, 06/Q11
- **Answer:**

### D-16 Audit reads across tenants
`auth.user_event` has no tenant column, so a tenant admin with `read_user_events` sees every
tenant's user events.
- **a)** Add a nullable `tenant_id` to `user_event`. Tenant-scoped events carry their tenant; global
  events (login, lock, password) have none and are visible only to tenant 1.
- **b)** Filter by the target user's tenant membership (D-03). Every tenant the user belongs to
  then sees all of that user's events.
- **Rec:** **a**.
- Refs: 08/Q-02
- **Answer:**

### D-17 Notifications and journal level
- Every change that removes access must send a notification:
  - identity disabled
  - user removed from a tenant
  - tenant soft-deleted
  - perm set or permission deleted
  - API key expired or rotated
  - group mapping changed
- Security events (permission and assignment changes, ownership, lock, disable) are always
  journaled, whatever `journal.level` says.
- **Rec:** accept both.
- Refs: 08/Q-07, 08/Q-08
- **Answer:**

### D-18 Housekeeping decisions
- **a)** Grant scripts: `99_fix_permissions.sql` is authoritative. Delete `099_fix_permissions.sql`
  and add `revoke execute ... from public`. (04/OQ-17, 08/Q-15)
- **b)** Service users: the id range is 1-999 and overflow raises an error. The custom id is the id
  itself, not "id - 1". They always have `is_system = true` and `can_login = false`.
  (01/OQ-07, 01/OQ-08, 06/Q16)
- **c)** Lockout: an admin unlock and a successful login both reset the failure counter. (02/8) **Done in v2.6** (temporary lock; success resets, decay after `lockout_reset_hours`).
- **d)** Deleting a group removes its mappings and assignments (cascade) instead of failing with a
  raw FK error. (03/3)
- **e)** `validate_api_key` returns identity only: the user id, after the expiry, active and locked
  checks. Permission questions go through `has_permission`. (06/Q3, 06/Q5)
- **f)** `has_permissions` becomes `volatile`, since it writes the cache. (04/OQ-19, 08/Q-13)
- **g)** Email registration stores `_user_data` on the email identity, the same as v2.3 does for
  providers, and the empty `update_user_data` stub is dropped. (01/OQ-02)
- **Rec:** accept all.
- **Answer:**

---

## B. Clear bugs, no decision needed
These go straight to the verify pass: write a failing test, then fix. Shown here so you can
object.

- 01/OQ-06 `assign_user_default_groups` validates the caller instead of the target. 01/OQ-12
  `update_user_identity_uid_oid` journals the caller's username, the stale-identity delete writes no
  event, and the email lookup is not normalized.
- 02/6 Null password hash matches a null input (`is distinct from`). 02/7 `validate_token` ignores
  `expires_at`. Used/failed token updates have no state filter, and an empty uid updates many rows.
  02/11 Unseeded `change_password` event; `mfa_disabled` is seeded twice (10051/10098).
- 03/7 Role-only mappings invalidate nobody's cache. 03/11 `process_external_group_member_sync` has
  `boolean || boolean`, null ids on deleted rows, and journals to tenant 1. 03/14 `update_user_group`
  flips `is_external` without the conversion side effects.
- 04/OQ-09 `create_perm_set_permissions` skips the assignability check and ignores unknown codes.
  04/OQ-10 Short code collisions after a sibling is deleted. 04/OQ-11 Translations keyed by `code`
  are shared across tenants. 04/OQ-12 `assign_permission` accepts both a set and a permission, and
  `raise_52283` gets the wrong argument. 04/OQ-14 The cache-invalidation gaps (a)-(e). 04/OQ-20 The
  group branch pairs the assignment's tenant with the group's tenant.
- 05/Q6 `create_tenant` with an owner fails for non-system callers. 05/Q7 Changing a tenant code
  bypasses the `tenant_identity` ledger. 05/Q10 Purge fails on tenant languages and translations and
  orphans API-key technical users. 05/Q13 The preference functions return the wrong column. 08/Q-14
  `ix_owner` allows duplicate tenant-wide owners.
- 06/Q8 `unassign_api_key_permissions` always returns no rows. 06/Q10 Inbound functions also act on
  outbound keys. 06/Q12 `create_api_key` with a null tenant. 06/Q13 `delete_api_key` writes no
  events for the removed assignments or the technical user. 06/Q14 The technical-user lookup does not
  check `user_type_code`.
- 07/OQ-6 `revoke_all_*` ignores `_resource_type`. 07/OQ-10 The parent resource type is never
  validated, and a changed `key_schema` is silently ignored. 07/OQ-15 Path-only role assignments
  cannot be listed.
- 08/Q-04 Unseeded error codes 34004-34007 and about 40 codes without messages. 08/Q-06 Unqualified
  object names / unpinned `search_path`. 08/Q-09 `get_version` returns the latest version as well as
  the one requested. 08/Q-10 Composite-type returns from `get/update_sys_param`, and `___` columns on
  `validate_token`. 08/Q-16 `validate_token`'s `or true`.

Docs-only fixes, collected for the docs repo and CLAUDE.md:
- 02/13 MFA error code aliases.
- 03/10 Member permission codes in permission-matrix.md.
- 04 `auth.copy_perm_set` / `duplicate_perm_set` do not exist.
- 06/Q15 Return columns of `validate_api_key`.
- 07/OQ-10 The `_parent_code` parameter does not exist.
- 08/Q-05 Error code ranges and the `has_permission` signature in CLAUDE.md.

---

## C. Remaining domain-specific questions
These are smaller, but only you can answer them.

| Ref | Question | Rec |
|---|---|---|
| 01/OQ-13 | An invitation with no actions journals 22008 "completed" while still `pending`. Should an `on_create` action failure fail the invitation? | Journal only when the status changes; yes, fail it |
| 02/7 | Is uid-only `validate_token` (no token value) intended for any token type? | Only for types explicitly flagged as such; otherwise require the value |
| 02/12 | Does the blacklist also block logins of *existing* users? (the two doc pages disagree) | Yes. The blacklist is a ban; otherwise it is only a registration filter |
| 03/9 | Group "lock" (`is_assignable = false`): does it block new members, new perm-set assignments, or both? | Both |
| 03/15 | Can disabled or locked users be added to groups (for example, pre-provisioning)? | Yes. D-06 already makes them get nothing |
| 03/17 | Converting a group with no mappings to hybrid: reject? | No; allow it, a mapping can be added later |
| 05/Q12 | `tenant.is_assignable` and `access_type_code` are not enforced anywhere. Enforce them or drop them? | Tell me what they were meant for |
| 05/Q14 | `get_tenant_members` gated by `tenants.get_tenants`, while its sibling uses `tenants.get_users`? | Use `get_users` / `read_all_users` |
| 06/Q9 | More than one outbound key per `(tenant, service_code)`? | Unique, plus an `is_active` flag for rotation overlap |
| 07/OQ-14 | Should a denied `has_resource_access` be journaled, like RBAC? | No (per-row calls in filters would flood the journal); same answer as 32001 in D-01 |
| 07/OQ-16 | A grant or deny on one invoice shows as type-wide in the access matrix. Intended? | No; the matrix shows only type-level rows, with child-specific rows separate |
