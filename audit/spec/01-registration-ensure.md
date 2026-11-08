# 01 - Registration & ensure

## Scope

Latest definitions (db-objects.md; update scripts 048+ override the 010-047 baseline).

| Object | Location |
|---|---|
| `auth.register_user` | `020_functions_auth_user.sql:309` |
| `auth.ensure_user_from_provider` | `050_update_permissions_v2-3.sql:23` (v2.3; baseline `020:767` is superseded) |
| `auth.ensure_user_info` | `020_functions_auth_user.sql:562` |
| `auth.create_service_user_info` / `unsecure.create_service_user_info` | `020:268` / `019_functions_unsecure.sql:1544` |
| `auth.assign_user_default_groups` / `unsecure.assign_user_default_groups` | `020:365` / `019:1630` |
| `auth.enable_user_identity`, `auth.disable_user_identity`, `auth.verify_user_identity` | `020:174`, `020:221`, `020:155` (+ `unsecure.verify_user_identity` `019:2391`) |
| `auth.get_user_identity`, `auth.get_user_identity_by_email` | `020:409`, `020:434` |
| `auth.update_user_data` (6-arg stub, `_provider_code`) | `020:599` |
| `auth.update_user_data` (partial merge), `auth.get_user_data` | `020:657`, `020:615` |
| `unsecure.create_user_info` | `019:1498` |
| `unsecure.create_user_identity` | `019:1828` |
| `unsecure.update_user_identity_uid_oid` | `019:2339` |
| `unsecure.update_user_info_basic_data` | `019:1708` |
| `unsecure.update_last_used_provider` | `019:1489` |
| `unsecure.check_user_blacklist` | `019:2852` |
| Invitations: `unsecure.create_invitation` 43, `accept_invitation` 79, `reject_invitation` 137, `revoke_invitation` 186, `complete_invitation_action` 233, `fail_invitation_action` 282, `check_invitation_completion` 352, `evaluate_invitation_condition` 393, `resolve_action_payload` 475, `create_invitation_from_template` 620, `execute_database_action` 699, `process_invitation_actions` 775; `auth.create_invitation` 905, `auth.accept_invitation` 976, `auth.reject_invitation` 1015, `auth.revoke_invitation` 1053, `auth.get_invitations` 1080, `auth.get_invitation_actions` 1141, `auth.create_invitation_from_template` 1177, template CRUD 1230-1430, `auth.ensure_invitation_templates` 1534 | `042_functions_invitation.sql` |
| Tables `auth.user_info` (`uq_auth_user_info` on `username`), `auth.user_data`, `auth.user_identity` (`uq_user_identity` on `(provider_code, coalesce(uid,'-1'))`, unique `provider_oid`) | `013_tables_auth.sql:93`, `:181`, `:206`, `:554`, `:566` |
| Tables `auth.invitation`, `auth.invitation_action`, `auth.invitation_template(_action)` | `041_tables_invitation.sql:235`, `:275`, `:311`, `:335` |

Out of scope here (other domains): login status checks for email/password (02), external group resolution from `provider_groups`/`provider_roles` and `ensure_groups_and_permissions` (03), permission cache internals (04), blacklist CRUD (02/08).

## Actors & preconditions

- **svc_registrator (2)** - calls `register_user`, `assign_user_default_groups`. Holds `users.register_user`, `users.add_to_default_groups` (docs concepts/service-accounts.md).
- **svc_authenticator (3)** - calls `ensure_user_from_provider` after the app has validated the provider token (docs concepts/authentication.md).
- **svc_group_syncer (6)** - calls `ensure_user_info` for directory users (docs concepts/group-types.md).
- **Admin (tenant 1 or own tenant)** - enables/disables/verifies identities, creates service users, manages invitations and templates.
- **Inviter** - a user with `invitations.create_invitation` in the invitation's tenant. **Acceptor** - the backend acting on behalf of the invitee, or the invitee.
- Preconditions: provider row exists and `is_active`; `email` provider exists for `register_user`; default groups exist per tenant; invitation action types are seeded in `const.invitation_action_type`.
- User 1 bypasses `has_permission(s)`; tests of this domain must use a dedicated caller (CLAUDE.md test-writing rule).

## Invariants

### Common user creation (`unsecure.create_user_info`, `create_user_identity`)
- **I-01-01** `user_info.username` is stored as `lower(trim(input))`, `original_username` as `trim(input)`; `email` as `lower(trim(input))`, `original_email` as `trim(input)`. Source: CHANGELOG (original_email entry) | test test_registration_login_events/008
- **I-01-02** A user whose normalized username is blacklisted is never created; error 33018. Source: docs concepts/authentication.md (blacklist table) | code `019:1511`
- **I-01-03** An identity whose `(provider_code, uid)` or `provider_oid` is blacklisted is never created; error 33019. Source: docs concepts/authentication.md
- **I-01-04** Creating a *new* user must never silently attach a new identity to a pre-existing user that merely shares the username. If the normalized username is already taken by another user, the creating operation must fail (or require an explicit, verified linking step) rather than return the existing user. Source: common sense (account takeover) **[confirm]** - see OQ-01
- **I-01-05** Journal 10001 `user_created` is written only when a `user_info` row is actually inserted. Source: docs reference/audit-events (event name) **[confirm]**
- **I-01-06** Every identity insert writes journal 10030 `identity_created` with provider_code/uid/oid, `is_active`, `is_verified`. Source: docs concepts/identity-providers.md (10030-10034)
- **I-01-07** `(provider_code, uid)` maps to at most one identity and `provider_oid` is globally unique; a conflict surfaces as error 33007 (identity already used), not a raw unique-violation. Source: docs identity-providers.md (unique constraints), error-codes.md 33007 **[confirm]** (error code choice)
- **I-01-08** Public/auth return columns are stock types with `__` prefix; no `password_hash`/`password_salt` is returned by any function in this domain. Source: CLAUDE.md

### `auth.register_user` (email/password)
- **I-01-10** Requires `users.register_user` in `_tenant_id`; otherwise 52109/32001 and no rows are written. Source: docs reference/users.md
- **I-01-11** Fails with 33010 when the `email` provider is inactive. Source: docs reference/users.md
- **I-01-12** Fails with 33007 (`raise_52102`) when an `email` identity with `uid = lower(trim(_email))` already exists. Source: docs reference/users.md
- **I-01-13** Must fail (not link) when any existing user already has `username = lower(trim(_email))` through another provider. Source: common sense **[confirm]** - OQ-01
- **I-01-14** On success creates exactly one `user_info` (`user_type_code='normal'`, `username = email`, `last_used_provider_code='email'`, `can_login`, `is_active`, not locked, not system), one `email` identity (`uid = provider_oid = lower(trim(email))`, `password_hash` stored in `password_hash`, `is_active = true`). Source: test test_registration_login_events/002 (TEST 4) | docs identity-providers.md (email row)
- **I-01-15** A new email identity starts `is_verified = false` (verification is a separate token flow). Source: code `019:1828` default **[confirm]**
- **I-01-16** A non-null `_user_data` is persisted (docs: "Creates user record, email identity, and user data"). Source: docs reference/users.md - OQ-02
- **I-01-17** Writes exactly one `user_registered` user_event with `event_data.email`, `provider='email'` and the passed `_request_context`. Source: test test_registration_login_events/002
- **I-01-18** Does not assign tenant membership or default groups by itself; the app calls `assign_user_default_groups`. Source: docs concepts/group-types.md ("may add ... depending on implementation") **[confirm]**

### `auth.ensure_user_from_provider` (external login / JIT provisioning)
- **I-01-20** `_provider_code = 'email'` (any case) is rejected with 33006 before any write. Source: docs identity-providers.md, ensure-functions.md (52101 alias)
- **I-01-21** Inactive or unknown provider is rejected with 33010 before any write. Source: docs identity-providers.md
- **I-01-22** Caller permission: the function is documented as permission-free, but it lives in `auth` and is called by svc_authenticator; it should require an authentication permission (e.g. `authentication.ensure_permissions` or a dedicated one). Source: CLAUDE.md schema rule vs docs reference/users.md ("None") **[confirm]** - OQ-03
- **I-01-23** Identity lookup is by `provider_code` + (`uid = _provider_uid` or `provider_oid = _provider_oid`); it must resolve to at most one user. If uid and oid match identities of *different* users, the call fails instead of picking one arbitrarily. Source: docs identity-providers.md step 3 | common sense **[confirm]**
- **I-01-24** New identity: blacklist check (33019), create user (I-01-02/I-01-04), create identity with `is_active = true`, `is_verified = true`, `user_data = _user_data`, then `user_registered` event (`provider`, `provider_uid`). Source: docs identity-providers.md, ensure-functions.md, CHANGELOG v2.3 | test test_identity_user_data, test_registration_login_events/005
- **I-01-25** Existing identity: uid/oid changes are written and journaled 10031 per changed field. Source: docs identity-providers.md step 5
- **I-01-26** Existing identity: username/display_name/email are refreshed only when they differ (email compared case-insensitively, null-safe); a username change must not steal another user's username (fail with a defined error, not 23505). Source: CHANGELOG (original_email) | common sense **[confirm]**
- **I-01-27** Existing identity: non-null `_user_data` that differs from the stored value replaces it (no merge) and journals 10031 with `user_data_keys`; `null` or equal data leaves it untouched and writes no 10031. Source: CHANGELOG v2.3 | test test_identity_user_data
- **I-01-28** Existing identity, status checks in this order: `can_login=false` -> 33005, user `is_active=false` -> 33003, identity `is_active=false` -> 33008; each logs `user_login_failed` with reason `login_disabled`/`user_disabled`/`identity_disabled`. Source: docs concepts/authentication.md | test test_registration_login_events/006
- **I-01-29** A **locked** user (`is_locked = true`) cannot log in via a provider: 33004 + `user_login_failed` reason `user_locked`. Source: docs reference/ensure-functions.md ("validates ... not locked") - OQ-04
- **I-01-30** A failed status check leaves no side effects from this call (no uid/oid/profile/user_data change, no `last_used_provider_code` change, no `user_logged_in`), but the `user_login_failed` audit event must be durable. Source: docs authentication.md ("logs ... -> raises") | common sense **[confirm]** - OQ-05
- **I-01-31** After success, the user has exactly one identity for `_provider_code` (other uids for the same user+provider are deleted, journal 10032 expected). Source: docs identity-providers.md step 6 | 10032 journaling **[confirm]**
- **I-01-32** After success `user_info.last_used_provider_code = _provider_code`, and one `user_logged_in` event (`provider`, `provider_uid`, `_request_context`) is written - for both new and returning users. Source: docs identity-providers.md "Last Used Provider" | test test_registration_login_events/003, 005
- **I-01-33** Switching last-used provider changes which identity's `provider_groups`/`provider_roles` drive permissions; therefore a change of `last_used_provider_code` must invalidate that user's permission/group caches (or the next `ensure_groups_and_permissions` must rebuild them). Source: docs identity-providers.md **[confirm]** (cache part)
- **I-01-34** `ensure_user_from_provider` never writes `provider_groups`/`provider_roles` (that is `ensure_groups_and_permissions`). Source: docs authentication.md step 2
- **I-01-35** Returns exactly one row: the resolved user's `user_id, code, uuid, username, email, display_name`. Source: docs reference/users.md

### `auth.ensure_user_info`
- **I-01-40** Idempotent by normalized username: returns the existing user unchanged, or creates one (with I-01-01..05). Source: docs reference/ensure-functions.md
- **I-01-41** Creates no identity and writes no login event; `_provider_code` only sets `last_used_provider_code` on create. Source: docs ensure-functions.md **[confirm]** (no identity)
- **I-01-42** `_user_data` is "used only when creating" and must then be persisted somewhere defined (user_data or identity). Source: docs ensure-functions.md - OQ-02
- **I-01-43** Permission: docs say none; it creates users from the `auth` schema. Source: docs vs CLAUDE.md **[confirm]** - OQ-03

### Identities: enable / disable / verify / get
- **I-01-50** `enable_user_identity` / `disable_user_identity` require `users.enable_user_identity` / `users.disable_user_identity`; unknown user+provider or a system user -> 33009 (`raise_52111`). Source: docs reference/users.md | test test_identity_and_providers/001
- **I-01-51** They set only `is_active` on that one identity, journal 10033/10034 and write `identity_enabled`/`identity_disabled` user_events. Source: docs identity-providers.md events | code `020:196-217` **[confirm]** (user_event)
- **I-01-52** A disabled identity blocks login through that provider (33008) while other identities of the user keep working. Source: docs reference/users.md
- **I-01-53** Disabling the identity that is the user's `last_used_provider_code` must stop its `provider_groups`/`provider_roles` from granting permissions immediately (clear that user's permission/group caches), consistent with `disable_user`. Source: docs reference/users.md (disable_user clears cache) | common sense **[confirm]**
- **I-01-54** `verify_user_identity` requires `users.verify_user_identity`; unknown user -> 52001-class "user not found", missing identity -> 33009; sets `is_verified = true`, journals 10035, writes `identity_verified` event. Idempotent. Source: test test_identity_and_providers/001 | code `019:2391` **[confirm]** (error codes)
- **I-01-55** `get_user_identity` / `get_user_identity_by_email` require `users.get_user_identity`, return `__user_data`, `__provider_groups`, `__provider_roles`, `__is_verified`, never password data. Email lookup is case-insensitive (email is stored normalized). Source: CHANGELOG v2.3 | test test_identity_user_data | common sense **[confirm]** (case)

### User data (`auth.user_data`)
- **I-01-60** `update_user_data` on self needs no permission; on another user needs `users.update_user_data`. Source: CLAUDE.md, CHANGELOG | test test_user_data/003
- **I-01-61** First update auto-creates the row; jsonb columns default to `{}`; shallow merge `||`; a key passed as `null` is removed; name fields use coalesce (null = unchanged). Source: CLAUDE.md | test test_user_data/001-002
- **I-01-62** Each update journals 10002 `user_updated` with changed names and key lists, never full jsonb values. Source: code `020:707` **[confirm]**
- **I-01-63** `get_user_data` on self is free; for others needs `users.get_data`. Source: test test_user_data/003
- **I-01-64** No function in the public API is a silent no-op: the 6-arg `auth.update_user_data(..., _provider_code, _user_data)` must either persist data or not exist. Source: common sense **[confirm]** - OQ-02

### Default groups
- **I-01-70** `assign_user_default_groups` requires `users.add_to_default_groups` in `_tenant_id`. Source: docs reference/users.md
- **I-01-71** Unknown `_target_user_id` -> 33001. (The check must be on the *target*, not the caller.) Source: docs group-types.md | common sense **[confirm]** - OQ-06
- **I-01-72** Adds the target only to active, `is_default` groups of `_tenant_id` (never other tenants), as `manual` members; idempotent; clears the target's permission cache for that tenant; journals 13010 per added group. Source: docs concepts/group-types.md "Default Groups"
- **I-01-73** Returns the user's full group membership in that tenant after the call. Source: docs group-types.md
- **I-01-74** A non-tenant-1 caller cannot add users to default groups of a tenant they have no permission in; a caller in tenant B with permission must not be able to target tenant A by passing `_tenant_id = A`. Source: CLAUDE.md tenant model **[confirm]**

### Service users
- **I-01-80** `auth.create_service_user_info` requires `users.create_service_user`. Source: docs reference/users.md
- **I-01-81** Creates `user_type_code = 'service'` with email and display_name in their own columns. Source: test test_service_user_info.sql | CHANGELOG
- **I-01-82** Service user ids stay inside the reserved range 1-999; if the range is full the call fails with a defined error, never allocating 1000+ (which collides with the normal-user sequence restart at 1000). Source: docs concepts/service-accounts.md ("IDs 1-999 reserved") **[confirm]** - OQ-07
- **I-01-83** `_custom_service_user_id` is documented as "specific user ID to assign"; the created user must get exactly that id. Source: docs reference/users.md - OQ-07
- **I-01-84** Service users are non-interactive: `can_login = false` (and `is_system = true`) like the seeded accounts, unless explicitly requested. Source: docs service-accounts.md (shared flags) **[confirm]** - OQ-08
- **I-01-85** Username blacklist applies (33018); journal 10001 with `user_type='service'`. Source: code `019:1559`, `019:1595` **[confirm]**

### Invitations
- **I-01-90** `create_invitation` / `create_invitation_from_template` require `invitations.create_invitation` in `_tenant_id`; the invitation is stored with that tenant, `inviter_user_id = _user_id`, status `pending`, `expires_at` = given or now()+7 days; journal 22001 + user_event `invitation_created`. Source: docs reference/invitations.md | code `042:58` (7-day default) **[confirm]**
- **I-01-91** All database actions of an invitation operate only inside the invitation's tenant: `add_group_member` group, `assign_perm_set` perm set and `assign_resource_access` resource must belong to `invitation.tenant_id`; otherwise the action fails. Source: CLAUDE.md tenant model **[confirm]** - OQ-09
- **I-01-92** An inviter cannot grant more than they could grant directly: creating an invitation with `assign_perm_set` / `assign_permission` / `add_group_member` / `assign_resource_access` actions requires the same permissions as the direct operation (or the actions run with the inviter's authority). Source: common sense (privilege escalation) **[confirm]** - OQ-09
- **I-01-93** `accept_invitation` requires `invitations.accept_invitation` **in the invitation's tenant** (or tenant 1); `reject`, `revoke`, `get_invitation_actions` likewise. A caller from tenant B cannot act on tenant A invitations. Source: CLAUDE.md tenant model **[confirm]** - OQ-10
- **I-01-94** The accepted `_target_user_id` must exist and must be the invitee (email matches `target_email`, or the acceptor is the invitee). Source: common sense **[confirm]** - OQ-10
- **I-01-95** Accept/reject/revoke only from `pending`; else 39002. Unknown id -> 39001. Accept after `expires_at` -> 39003 and the invitation ends up (durably) `expired`. Source: docs invitations.md lifecycle | test test_invitation/007 - OQ-05
- **I-01-96** Reject after `expires_at` is also refused with 39003. Source: docs lifecycle (pending -> expired) **[confirm]**
- **I-01-97** Accept: status `processing`, `target_user_id` and `accepted_at` set, `on_reject`/`on_expired` actions skipped, `on_accept` processed; journal 22002, event `invitation_accepted`. Reject: status `rejected`, non-`on_reject` pending actions skipped, `on_reject` processed; 22003. Revoke: status `revoked`, all pending actions skipped; 22004. Source: docs invitations.md | test test_invitation/001,004,007
- **I-01-98** Action processing: within a phase, by `sequence` then id; condition false -> `skipped`; database actions run inline -> `completed` (22006) or `failed` (22007); a failed required action skips later sequences of the same phase and sets the invitation `failed` (22009); backend/external actions become `processing` and are returned with a payload resolved from `payload_schema` (action payload wins). Source: docs invitations.md | test test_invitation/002,003,005,009
- **I-01-99** `is_required` defaults to `true` when omitted. Source: code `042:947` **[confirm]**
- **I-01-100** The invitation becomes `completed` (22008) exactly once, when no action is `pending`/`processing` and status is `processing`/`accepted`; 22008 is not journaled when the status did not change. Source: docs invitations.md | code `042:352` **[confirm]** (no spurious 22008)
- **I-01-101** `complete_invitation_action` / `fail_invitation_action` only from `pending`/`processing`; else 39005; unknown -> 39004. Source: docs invitations.md error table
- **I-01-102** Template from `create_invitation_from_template`: tenant-specific active template beats global; inactive/missing -> 39006; `_payload_overrides` shallow-merge into every action's `payload_template`; `template_code` stored. Source: docs invitations.md | test test_invitation/006
- **I-01-103** Template create/update/delete/ensure require `invitations.manage_templates`, and update/delete may only touch templates of the caller's tenant (global templates only from tenant 1). Source: docs invitations.md | CLAUDE.md tenant model **[confirm]**
- **I-01-104** `get_invitations` follows the cross-tenant pattern: `_tenant_id = 1` + `invitations.get_all_invitations` sees all/target tenant; other tenants see only their own (`invitations.get_invitations`); `_target_tenant_id` from non-1 tenant -> 34002. Source: CLAUDE.md | test test_invitation/008

## Flows

**Email registration** (svc_registrator): `register_user` -> permission check -> email provider active -> no existing email identity -> new `user_info` (journal 10001) -> email identity (10030, `is_verified=false`) -> user data persisted -> `user_registered` event. App then calls `assign_user_default_groups` (group members + 13010 + cache cleared) and the verification token flow (`verify_user_identity` -> 10035).

**First provider login** (svc_authenticator): `ensure_user_from_provider` -> not email, provider active -> no identity -> blacklist -> new `user_info` (10001) -> identity with `user_data`, active+verified (10030) -> `user_registered` -> `last_used_provider_code` set -> `user_logged_in`. App then calls `ensure_groups_and_permissions` with groups/roles (domain 03).

**Returning provider login**: lookup -> uid/oid refresh (10031) -> profile refresh -> `user_data` refresh (10031) -> status checks (I-01-28/29) -> delete stale same-provider uids -> `last_used_provider_code` -> `user_logged_in`.

**Invitation**: create (22001, `on_create` backend actions returned) -> backend completes them (22006) -> invitee registers/logs in -> accept (22002, `on_accept` db actions inline, conditions evaluated) -> completed (22008). Alternatives: reject (22003 + `on_reject`), revoke (22004), expiry (39003), required failure (22009).

## Failure behaviour

| Operation | Condition | Expected |
|---|---|---|
| register_user | no `users.register_user` | 32001 (52109), no writes |
| register_user | email provider disabled | 33010 |
| register_user | email identity exists | 33007 |
| register_user | username taken via other provider | defined error, no linking **[confirm]** |
| register_user / any create | username blacklisted | 33018 |
| ensure_user_from_provider | provider `email` | 33006 |
| ensure_user_from_provider | provider inactive / unknown | 33010 |
| ensure_user_from_provider | new identity blacklisted | 33019 |
| ensure_user_from_provider | `provider_oid` used by another identity | 33007 **[confirm]** |
| ensure_user_from_provider | can_login false / user disabled / identity disabled / user locked | 33005 / 33003 / 33008 / 33004 |
| enable/disable_user_identity | identity missing or system user | 33009 |
| verify_user_identity | user missing / identity missing | 33001-class / 33009 |
| assign_user_default_groups | target user missing | 33001 |
| create_service_user_info | no permission / reserved range full | 32001 / defined error **[confirm]** |
| invitations | not found / not pending / expired / action not found / action not pending / template missing | 39001 / 39002 / 39003 / 39004 / 39005 / 39006 |
| invitations | caller lacks permission in invitation's tenant | 32001 |

## Open questions

- **OQ-01 Silent account linking by username.** `unsecure.create_user_info` returns the existing user when the username exists (`019:1516-1526`) and still journals 10001. `register_user` (`020:339`) and the new-identity branch of `ensure_user_from_provider` (`050:67-72`) then attach a new identity to that user. Example: AAD user `jane@corp.com` exists; anyone calling `register_user('jane@corp.com', <own hash>)` gets an email/password identity on Jane's account, and email login does not check `is_verified`. Is cross-provider linking by username ever intended? If so, it needs a verified/explicit link step.
- **OQ-02 `_user_data` dropped in `register_user` and `ensure_user_info`.** `register_user` calls the 6-arg `auth.update_user_data(..., 'email', _user_data)` (`020:347`), which resolves to the empty stub at `020:599` (the merge overload has no jsonb 6th parameter). `ensure_user_info` never uses `_user_data` (`020:562`). Same bug class v2.3 fixed for `ensure_user_from_provider`. Where should registration data go (`user_data.custom_data`? the email identity's `user_data`?), and should the stub be dropped?
- **OQ-03 Permission-free `auth` functions.** `ensure_user_from_provider` and `ensure_user_info` create users with no permission check (docs say "None"), which conflicts with the CLAUDE.md rule that `auth` always checks permissions. Anyone with EXECUTE can provision users or log in as any external identity. Intended?
- **OQ-04 Locked users can log in via providers.** `ensure_user_from_provider` checks `can_login`, `is_active` and identity `is_active`, but not `is_locked` (`050:114-142`). ensure-functions.md says it validates "not locked"; authentication.md lists only three checks.
- **OQ-05 Failure audit is rolled back.** `user_login_failed` events are inserted and then `error.raise_*` aborts the transaction (`050:115-142`), so the event never persists for a normal caller. The same applies to the `expired` status update in `unsecure.accept_invitation` (`042:105-109`). The same pattern in `auth.record_login_failure` (`037:142-162`) would stop auto-lockout from counting failures (domain 02). Should these writes persist (return a status instead of raising, or log in a separate transaction)?
- **OQ-06 `unsecure.assign_user_default_groups` checks the caller, not the target** (`019:1640`, `where user_id = _user_id`): an unknown `_target_user_id` passes and fails later with an FK error. It also does not check that the target belongs to `_tenant_id` (`tenant_user`). Should default-group assignment add the user to the tenant, or require membership?
- **OQ-07 Service user id allocation.** `_custom_service_user_id` is used as the *previous* id (`+1`, `019:1580`; seeds pass 1 to get 2), not the id itself as the docs say. With no custom id it takes `max(user_id) in 1..999 + 1`, so after id 999 it inserts 1000, which collides with the user sequence restarted at 1000 (`029:446`). There is no range check.
- **OQ-08 Service-user flags.** Seeded service accounts get `is_system = true, can_login = false` through a separate UPDATE (`029:443`); `create_service_user_info` leaves the defaults (`can_login = true`, `is_system = false`). Which is intended for runtime-created service users?
- **OQ-09 Invitation actions bypass authority and tenant.** `execute_database_action` (`042:699`) runs `assign_perm_set` / `assign_permission` / `add_group_member` through `unsecure` with no check that the inviter may grant them, and `unsecure.create_user_group_member` (`019:1734`) does not check that the group belongs to `_tenant_id`. An inviter with only `invitations.create_invitation` can grant any perm set (e.g. a full admin set) or add the invitee to any group, even one in another tenant. `assign_resource_access` instead goes through `auth.assign_resource_access` with the *acceptor's* `_user_id`, which is inconsistent.
- **OQ-10 Invitation tenant and target scoping.** `auth.accept_invitation`, `reject_invitation`, `revoke_invitation` and `get_invitation_actions` check permission in `_tenant_id` (default 1) but never compare it with `invitation.tenant_id` (`042:976-1170`). `_target_user_id` on accept is not validated against `target_email` or for existence. Template update/delete has no tenant check (`042:1282`, `042:1323`).
- **OQ-11 Identity lookup ambiguity.** `uid = _provider_uid or provider_oid = _provider_oid` (`050:51`) can match two identities of different users; `select ... into` picks one arbitrarily. The later `user_data` update filters on `uid = _provider_uid` (`050:97`). Should an ambiguous match be an error?
- **OQ-12 Identity side effects without events/cache.** The stale-uid delete (`050:143-147`) writes no 10032. `disable_user_identity` does not clear caches. `unsecure.update_user_identity_uid_oid` reads the *caller's* username into the journal (`019:2352`, `ui.user_id = _user_id`). `get_user_identity_by_email` compares `ui.email = _email` without normalizing (`020:455`).
- **OQ-13 Minor invitation questions.** Is a 22008 `invitation_completed` journal intended for an invitation with zero actions that is still `pending` (`042:352-372`)? Should an `on_create` required-action failure fail a not-yet-accepted invitation?

## Known coverage

| Suite | Covers |
|---|---|
| `test_registration_login_events` | I-01-01, 10, 14, 17, 24, 28, 32 (mostly as user 1 - CLAUDE.md test rule not met) |
| `test_identity_user_data` | I-01-24, 27, 55 (dedicated admin) |
| `test_identity_and_providers` | I-01-50, 51, 54, 55 (user 1) |
| `test_user_data` | I-01-60, 61, 63 |
| `test_service_user_info.sql` | I-01-81 (user 1) |
| `test_permission_checks` | I-01-70 (one call) |
| `test_user_blacklist` | I-01-02, 03 |
| `test_invitation` | I-01-90, 95, 97, 98, 101, 102, 104 (single tenant) |
| `test_ensure_functions` | template ensure only |

No tests: I-01-04/13 (username linking), 07 (oid conflict), 11, 12, 15, 16/42/64 (`_user_data` on register/ensure_user_info), 20-23, 26, 29 (locked), 30 (durable failure events), 31, 33, 34, 40-43 (`ensure_user_info` as such), 52, 53, 62, 71-74 (default-group target/tenant), 80, 82-85 (id range, flags), 91-94 (invitation tenant/authority/target), 96, 99, 100, 103. Untested functions: `auth.update_invitation_template`, `auth.delete_invitation_template`, `unsecure.assign_user_default_groups` (directly), `unsecure.update_user_identity_uid_oid`.
