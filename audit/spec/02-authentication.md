# 02 - Authentication

Draft. Rules marked **[confirm]** come from the code or from common sense, not from docs, tests or
the changelog. The owner must confirm or rewrite each one. Source shorthand: `docs/...` =
`../postgresql-permissions-model-docs/docs/...`, `CL` = `CHANGELOG.md`, `test <suite>` = `tests/<suite>/`.

## Scope

Login (email/password and external provider)
- `auth.get_user_by_email_for_authentication` - `020_functions_auth_user.sql:460`
- `auth.verify_user_by_email` - `037_functions_auto_lockout.sql:178`
- `auth.record_login_failure` - `037_functions_auto_lockout.sql:123`
- `auth.ensure_user_from_provider` (login part only; provisioning is domain 01) - `050_update_permissions_v2-3.sql:23`
- `unsecure.update_last_used_provider` - `019_functions_unsecure.sql:1489`
- `unsecure.create_user_event` - `019_functions_unsecure.sql:518`; table `auth.user_event` - `013_tables_auth.sql`

Auto-lockout
- `unsecure.check_and_auto_lock_user` - `037_functions_auto_lockout.sql:31`
- sys params `login_lockout.max_failed_attempts` / `window_minutes` - `036_tables_mfa.sql` section 5

User status and password
- `auth.enable_user` / `auth.disable_user` / `auth.unlock_user` / `auth.lock_user` - `020_functions_auth_user.sql:13/47/84/118`
- `auth.enable_user_identity` / `auth.disable_user_identity` - `020_functions_auth_user.sql:174/221`
- `auth.update_user_password` - `020_functions_auth_user.sql:285`; `unsecure.update_user_password` - `019_functions_unsecure.sql:1604`
- Enforcement point: `unsecure.recalculate_user_permissions` (`019_functions_unsecure.sql:2143`) and `auth.has_permissions` (`022_functions_auth_permission.sql:63`)

Tokens
- `auth.create_token` `:13`, `auth.set_token_as_used` `:94`, `auth.set_token_as_used_by_token` `:145`, `auth.set_token_as_failed` `:173`, `auth.set_token_as_failed_by_token` `:225`, `auth.validate_token` `:253` - all `025_functions_auth_token.sql`
- `public.validate_token` - `018_functions_public.sql:432`
- `unsecure.expire_tokens` - `019_functions_unsecure.sql:573`
- `public.get_token_types` / `create_token_type` / `update_token_type` / `delete_token_type` - `025_functions_auth_token.sql:335/348/383/434`
- tables `auth.token` (`013_tables_auth.sql:420`), `const.token_type` / `token_state` / `token_channel` (`011_tables_const.sql:35-55`, seeds `029_seed_data.sql:13-35`)

MFA and MFA policy
- `auth.enroll_mfa` `:25`, `auth.confirm_mfa_enrollment` `:111`, `auth.disable_mfa` `:171`, `auth.get_mfa_status` `:219`, `auth.create_mfa_challenge` `:259`, `auth.verify_mfa_challenge` `:344` - all `038_functions_mfa.sql`
- `auth.reset_mfa` `:22`, `auth.create_mfa_policy` `:97`, `auth.delete_mfa_policy` `:145`, `auth.get_mfa_policies` `:198`, `unsecure.is_mfa_required` `:249`, `auth.is_mfa_required` `:325` - all `040_functions_mfa_policy.sql`
- tables `auth.user_mfa` (`036_tables_mfa.sql:44`), `const.mfa_type` (`036_tables_mfa.sql:30`), `auth.mfa_policy` (`039_mfa_policy.sql:18`)

Blacklist
- `auth.is_blacklisted` `:1033`, `auth.create_blacklist_user` `:1046`, `auth.delete_blacklist_user` `:1112`, `auth.search_blacklist` `:1150` - all `020_functions_auth_user.sql`
- `unsecure.check_user_blacklist` `:2852`, `unsecure.blacklist_user` `:2874`, `unsecure.blacklist_user_identities` `:2910` - all `019_functions_unsecure.sql`
- table `auth.user_blacklist` - `013_tables_auth.sql:537`

## Actors & preconditions

- **Auth service accounts** (not user 1): `svc_authenticator` (login data, failure recording, permission resolution), `svc_token_manager` (tokens), `svc_registrator` (registration, tokens). Seeded perm sets: `022_functions_auth_permission.sql:713-723`. Source: docs/concepts/authentication.md "Service Accounts".
- **End user** acting on themselves (password change, MFA self-service).
- **Admin in own tenant** with `users.*`, `mfa.*`, `tokens.*` permissions.
- **Admin in tenant 1** - same functions, plus global config (token types, blacklist).
- **App layer** hashes passwords, verifies TOTP codes and encrypts TOTP secrets. The DB never sees a raw password or TOTP secret. Source: docs/concepts/authentication.md.
- Preconditions: the `email` provider must exist and be active for Path B; `const.token_type`, `const.token_state` and `const.mfa_type` must be seeded; the `login_lockout` sys params exist (with code fallbacks 5 / 15).

## Invariants

### Login - status gating
- **I-02-01** Email/password login (`get_user_by_email_for_authentication`, `verify_user_by_email`) requires `authentication.get_data` in `_tenant_id`. Source: docs/reference/users.md
- **I-02-02** Email/password login fails with 33010 (52107) when the `email` provider is inactive. Source: docs/concepts/authentication.md
- **I-02-03** The email lookup key is `lower(trim(_email))` matched against `user_identity.uid` where `provider_code = 'email'`. Source: docs/concepts/authentication.md, CL (email normalization), test test_registration_login_events/008
- **I-02-04** Status checks run in this order, each logging `user_login_failed` (10012) with `event_data.reason` and raising: not found -> `user_not_found`, 33001 (52103); `can_login=false` -> `login_disabled`, 33005 (52112); `is_active=false` -> `user_disabled`, 33003 (52105); identity inactive -> `identity_disabled`, 33008 (52110); `is_locked=true` -> `user_locked`, 33004 (52106). Source: docs/reference/users.md "Error behavior", test test_registration_login_events/004
- **I-02-05** Unknown email and wrong password both raise SQLSTATE 33001, so a caller cannot tell them apart. Source: docs/concepts/authentication.md (both 52103), test test_auto_lockout/007
- **I-02-06** A wrong password hash in `verify_user_by_email` logs `user_login_failed` with reason `wrong_password`, runs the auto-lock check, and raises 33004 if that call locked the user, otherwise 33001. Source: docs/reference/users.md
- **I-02-07** `verify_user_by_email` logs `user_logged_in` (10010) and updates `last_used_provider_code = 'email'` only after a hash match, and never returns the hash or salt. Source: docs/reference/users.md, CL "Single-Call Email/Password Verification"
- **I-02-08** A null or empty stored hash, or a null or empty `_password_hash`, never authenticates. `verify_user_by_email` compares with `is distinct from`, so null = null counts as a match (`037:273`). Source: common sense **[confirm]**
- **I-02-09** `get_user_by_email_for_authentication` (two-step flow) logs `user_logged_in` once all status checks pass, before the app verifies the password. It returns `password_hash` and `password_salt`. Source: docs/concepts/authentication.md (two-step, step 9), test test_registration_login_events/003
- **I-02-10** `request_context` passed to any login function is stored unchanged on every `user_event` that the call writes. A null context is stored as null. Source: test test_registration_login_events/003 (TEST 8), 006 (TEST 20/21)
- **I-02-11** Provider login (`ensure_user_from_provider`, existing user) checks `can_login` -> 33005, `is_active` -> 33003, identity `is_active` -> 33008, logging `user_login_failed` with the matching reason, then logs `user_logged_in` and sets `last_used_provider_code`. Source: docs/concepts/authentication.md Path A, test test_registration_login_events/006
- **I-02-12** A locked user (`is_locked=true`) must also be refused by provider login (33004, reason `user_locked`), not only by email login. The code has no `is_locked` check in `050:131-156`. Source: common sense; docs list `is_locked` only for Path B **[confirm]**
- **I-02-13** Provider login with `_provider_code = 'email'` is rejected with 33006 (52101). Source: docs/concepts/authentication.md
- **I-02-14** Service accounts and other `can_login=false` users can never complete a login by any path. Source: docs/concepts/authentication.md, `029_seed_data.sql:441`

### Login - audit durability
- **I-02-15** A failed login attempt must leave a persisted `user_login_failed` event even though the call raises an error. Otherwise the audit trail and the lockout counter both lose it. Today the event is written and then the function raises in the same transaction, so the event is rolled back (`037:147-163`, `037:273-289`, `020:487-545`). Source: docs/concepts/authentication.md (failure is logged, then raises), CL "MFA Failures Count Toward Auto-Lockout"; test test_auto_lockout/007-008 notes say the event is rolled back **[confirm]**

### Auto-lockout
- **I-02-16** Failures counted = `user_event` rows for the target with `event_type_code in ('user_login_failed','mfa_challenge_failed')` and `created_at >= now() - window_minutes`. Source: docs/concepts/authentication.md, CL, test test_auto_lockout/003
- **I-02-17** When the count is >= `max_failed_attempts`, the user is set `is_locked=true`, the permission cache is cleared for all tenants, and `user_auto_locked` (10083) is logged with `failure_count`, `window_minutes` and `max_attempts`. Source: docs/concepts/authentication.md, test test_auto_lockout/003
- **I-02-18** A count below the threshold does not lock. Failures older than the window are not counted. Source: test test_auto_lockout/002, 005
- **I-02-19** An already locked user is not locked again and gets no second `user_auto_locked` event. The check returns false. Source: test test_auto_lockout/004
- **I-02-20** Thresholds come from `const.sys_param` (`login_lockout`), fall back to 5 / 15 when missing, and a runtime change takes effect on the next check. Source: docs/reference/system-parameters.md, test test_auto_lockout/001
- **I-02-21** Auto-lockout must actually trigger through the public flow: N consecutive wrong-password calls to `verify_user_by_email` (or `record_login_failure`, or failed `verify_mfa_challenge`), each in its own transaction, lock the account. Source: docs/concepts/authentication.md, CL. Currently blocked by I-02-15 **[confirm]**
- **I-02-22** `record_login_failure` requires `authentication.get_data`, always raises (33004 if locked by this call, else 33001), and logs reason `wrong_password`. Source: docs/reference/users.md
- **I-02-23** `record_login_failure` only records a failure against the user who owns the `email` identity `_email`. A mismatched `_target_user_id` / `_email` pair is rejected, so a caller cannot lock an arbitrary user id. Source: common sense **[confirm]**
- **I-02-24** After an admin `unlock_user`, failures from before the unlock do not count. A single new failure must not re-lock immediately. Source: common sense **[confirm]**

### User status (enable/disable/lock/unlock)
- **I-02-25** `enable_user` / `disable_user` / `lock_user` / `unlock_user` require `users.enable_user` / `users.disable_user` / `users.lock_user` / `users.unlock_user` respectively in `_tenant_id`. Source: docs/reference/users.md
- **I-02-26** These four functions never change a system user (`is_system=true`). Source: docs/reference/users.md ("Does not affect system users")
- **I-02-27** A non-existent target raises 33001 and a system target raises 33002. Neither may write a journal entry or user event (today both are written while 0 rows change, `020:23-43`). Source: common sense, matches `auth.delete_user_info` (33001/33002, docs/reference/users.md) **[confirm]**
- **I-02-28** `disable_user` and `lock_user` clear the target's permission cache in every tenant before returning. Source: docs/reference/users.md, test test_disabled_locked_users/001-002
- **I-02-29** Each status change writes the journal code (10004 enabled, 10005 disabled, 10006 locked, 10007 unlocked) and the user event (`user_enabled`, `user_disabled`, `user_locked`, `user_unlocked`) with `_request_context`. Source: code `020:33-43` etc., event seeds `029_seed_data.sql:110-113` **[confirm]**
- **I-02-30** A disabled or locked user cannot obtain permissions: `recalculate_user_permissions` raises 33003 / 33004, and `has_permission(s)` for such a user returns false or throws. That includes the owner short-circuit (`022:80`), which today returns true before any status check. Source: test test_disabled_locked_users/001 (Test 3), 002 (Test 6); owner part **[confirm]**
- **I-02-31** Re-enabling or unlocking restores the ability to recalculate permissions. Source: test test_disabled_locked_users/003
- **I-02-32** A caller whose `_tenant_id` is not 1 can only change the status of users who are members of their tenant (`auth.tenant_user`). Changing a user from another tenant, or a tenant-1-only user, is rejected. Source: CLAUDE.md tenant model, v2.1 tenant-scoping fixes (CL) **[confirm]**
- **I-02-33** `enable_user_identity` / `disable_user_identity` require `users.enable_user_identity` / `users.disable_user_identity`, raise 33009 (52111) when the user/provider identity does not exist or belongs to a system user, and log 10033 / 10034 plus `identity_enabled` / `identity_disabled`. Source: docs/reference/users.md
- **I-02-34** A disabled identity blocks login through that provider only. Other identities of the same user still work. Source: docs/reference/users.md

### Password update
- **I-02-35** `update_user_password` with `_user_id = _target_user_id` needs no permission. Changing another user's password requires `users.change_password` in `_tenant_id`. Source: docs/reference/users.md, test test_audit_and_user_ops
- **I-02-36** Only the `email` identity's `password_hash` / `password_salt` are changed, and the function returns that identity's `(user_id, provider_code, uid)`. Source: docs/reference/users.md
- **I-02-37** A target with no `email` identity, or that does not exist, raises an error and writes no event or journal entry. Today the event is logged first and the update then silently matches 0 rows (`020:298`). Source: common sense **[confirm]**
- **I-02-38** A password change logs a user event with a registered event code. Code uses `'change_password'`, which is not in `const.event_code`; the seeded code is `password_changed` (10020, `029_seed_data.sql:118`). The journal 10020 is also written. Source: seeds **[confirm]**
- **I-02-39** A password change invalidates all `valid` `password_reset` tokens for the target. Source: common sense **[confirm]**
- **I-02-40** Changing another user's password is tenant-scoped the same way as I-02-32. Source: CLAUDE.md **[confirm]**

### Tokens
- **I-02-41** `create_token` requires `tokens.create_token`, `validate_token` (auth and public) requires `tokens.validate_token`, and `set_token_as_used` / `set_token_as_failed` (and their `_by_token` wrappers) require `tokens.set_as_used`. Source: docs/reference/tokens.md
- **I-02-42** `create_token` without `_expires_at` sets `expires_at = now() + token_type.default_expiration_in_seconds`. Seeded defaults: password_reset 3600, email_verification 86400, invite 604800, mfa 300. Source: docs/reference/tokens.md, docs/concepts/authentication.md, test test_tokens/001 (TEST 1, 6)
- **I-02-43** Creating a token for a non-null target sets every `valid` token of the same type for that user to `invalid` first. At most one `valid` token per (user, type) exists afterwards. Source: docs/reference/tokens.md, test test_tokens/001 (TEST 8)
- **I-02-44** Creating a token whose value equals an existing `valid` token of the same type raises 30004 (52276). Source: docs/reference/tokens.md, test test_tokens/001 (TEST 14)
- **I-02-45** `create_token` journals 15001 with username, token type and uid, and never journals the token value. Source: docs/reference/tokens.md, test test_tokens/001 (TEST 2)
- **I-02-46** Validation fails with 30005 (52277) when no token matches, 30002 (52278) when the token is not `valid`, and 30003 (52279) when `_target_user_id` is given and differs from the owner. Source: docs/reference/tokens.md, test test_tokens/001 (TEST 5, 9, 12, 13)
- **I-02-47** A token whose `expires_at < now()` is never accepted by `validate_token`, `set_token_as_used` or `verify_mfa_challenge`, whether or not `expire_tokens` has run yet. Today `auth.validate_token` checks only `token_state_code` and expires overdue tokens after validating (`025:276-326`). Source: docs/concepts/authentication.md (lifecycle), common sense **[confirm]**
- **I-02-48** When several tokens match the lookup (same value across states or users), validation must pick deterministically, preferring the `valid` one, and never accept based on an arbitrary row. The `select ... into` has no `order by` (`025:265`, `018:449`). Source: common sense **[confirm]**
- **I-02-49** `set_token_as_used` / `set_token_as_failed` only change a token that is `valid`, of `_token_type_code`, and matches uid + value. Otherwise they raise 30005 / 30002 and change nothing. Today the UPDATE ignores state and type (`025:122-126`, `025:201-205`). Source: docs/reference/tokens.md ("Marks a valid token as used") **[confirm]** for the error behaviour
- **I-02-50** A token transitions out of `valid` exactly once (valid -> used | expired | invalid | validation_failed | failed). No transition ever returns a token to `valid` or re-marks a terminal token. Source: docs/concepts/authentication.md state diagram
- **I-02-51** `validate_token(_set_as_used := true)` leaves the token `used` with `used_at` set and `request_context` stored. Source: docs/reference/tokens.md, test test_tokens/001 (TEST 10)
- **I-02-52** `expire_tokens` sets every `valid` token with `expires_at < now()` to `expired` and journals 15003 with the count, only when the count is > 0. Source: docs/reference/tokens.md
- **I-02-53** Token type CRUD requires `token_configuration.create_token_type` / `update_token_type` / `delete_token_type`. System types raise 36002, unknown types raise 36001, and new types always get `is_system=false`. Token types are global, so only a tenant-1 caller may change them. Source: docs/reference/tokens.md; tenant-1 restriction **[confirm]**
- **I-02-54** Tokens are app-wide (no `tenant_id`). Token functions only use `_tenant_id` for the permission check. Source: `013_tables_auth.sql:420` **[confirm]**

### MFA
- **I-02-55** MFA functions require their own permission: `mfa.enroll_mfa`, `mfa.confirm_mfa_enrollment`, `mfa.disable_mfa`, `mfa.get_mfa_status` (also `auth.is_mfa_required`), `mfa.create_mfa_challenge`, `mfa.verify_mfa_challenge`, `mfa.reset_mfa`. Source: docs/reference/mfa.md
- **I-02-56** `enroll_mfa` rejects an unknown or inactive type with 38006 and an already confirmed enrollment with 38001. It replaces a pending (unconfirmed) enrollment, stores `is_enabled=false, is_confirmed=false`, returns 10 plaintext recovery codes once, stores only their SHA-256 hex hashes, and logs `mfa_enrolled` (10090). Source: docs/reference/mfa.md, test test_mfa/001-002
- **I-02-57** `confirm_mfa_enrollment` raises 38002 when there is no pending enrollment and 38004 when `_code_is_valid=false`. Otherwise it sets enabled + confirmed + `confirmed_at` and logs `mfa_enrollment_confirmed` (10091). Source: docs/reference/mfa.md, test test_mfa/003
- **I-02-58** `disable_mfa` deletes the enrollment (raises 38002 if there is none) and logs `mfa_disabled` (10051). Source: docs/reference/mfa.md, test test_mfa/007
- **I-02-59** `create_mfa_challenge` raises 38002 when not enrolled or not enabled and 38003 when not confirmed. It invalidates earlier valid `mfa` tokens, creates an `mfa` token (5 min) carrying `user_mfa_id` in `token_data`, and logs `mfa_challenge_created` (10092). Source: docs/reference/mfa.md, test test_mfa/005
- **I-02-60** `verify_mfa_challenge`: unknown uid -> 30005, not `valid` or expired -> 30002, token of another user -> 30003. A valid TOTP marks the token `used` and logs `mfa_challenge_passed` (10093). A valid recovery code removes that hash, marks the token `used` and logs `mfa_recovery_used` (10094). Otherwise the token becomes `failed`, `mfa_challenge_failed` (10099) is logged, the auto-lock check runs, and the call raises 33004 if locked, else 38004. Source: docs/reference/mfa.md, CL, test test_mfa/005, 006, 008
- **I-02-61** A failed MFA challenge must persist both the `failed` token state and the `mfa_challenge_failed` event, so the same challenge cannot be retried and TOTP brute force is bounded by the lockout. Today both are rolled back by the final raise (`038:467-490`). Source: CL "MFA Failures Count Toward Auto-Lockout" **[confirm]**
- **I-02-62** A recovery code is single-use. The same code never passes twice, including under concurrent verification of two challenges. Source: docs/concepts/authentication.md ("Recovery codes are single-use"); concurrency **[confirm]**
- **I-02-63** A challenge token passes at most once, even with concurrent `verify_mfa_challenge` calls on the same uid (row lock or conditional update). Source: common sense **[confirm]**
- **I-02-64** MFA challenge creation and verification are refused for a user who is disabled, locked or `can_login=false`, and verification is refused if the enrollment was disabled after the challenge was created. Source: common sense **[confirm]**
- **I-02-65** `reset_mfa` raises 38002 when not enrolled and 38003 when not confirmed, replaces all recovery hashes with 10 new ones, returns them once, and logs `mfa_recovery_reset` (10097). Source: docs/reference/mfa.md, test test_mfa_policy/001-002
- **I-02-66** Acting on another user's MFA (enroll, disable, reset, status) requires the caller to manage that user, either self or an admin in a tenant the target belongs to. Ordinary role perm sets (e.g. "Tenant member", "Auditor") must not grant `mfa.disable_mfa` / `mfa.reset_mfa` / `mfa.mfa_policy.*` over other users. Source: common sense; see Open questions **[confirm]**

### MFA policy
- **I-02-67** `is_mfa_required(user, tenant)` resolves user rule (tenant-specific before global user rule) > group rules (`bool_or` over the user's active groups in that tenant) > tenant rule > global rule > `false`. Source: docs/reference/mfa.md, test test_mfa_policy/003-007
- **I-02-68** Policy create/delete/list require `mfa.mfa_policy.create_mfa_policy` / `delete_mfa_policy` / `get_mfa_policies`. A missing policy raises 38007. Create and delete log `mfa_policy_created` (10095) / `mfa_policy_deleted` (10096). A duplicate scope raises unique_violation. Source: docs/reference/mfa.md, test test_mfa_policy/007, 009
- **I-02-69** Only a tenant-1 caller can create, delete or list global rules (`tenant_id is null`) or rules for another tenant. A tenant-N caller can only touch rules with `tenant_id = N` whose group or user belongs to tenant N. Source: CLAUDE.md tenant model **[confirm]**
- **I-02-70** The policy is advisory. No DB login function blocks on it, and the app enforces it. Source: docs/reference/mfa.md

### Blacklist
- **I-02-71** `create_blacklist_user` / `delete_blacklist_user` require `users.manage_blacklist` and `search_blacklist` requires `users.search_blacklist`. The blacklist is app-wide. Source: docs/reference/users.md, CL
- **I-02-72** `create_blacklist_user` refuses entries that match a system user by username or provider identity (33002) and logs journal 10080. Source: docs/reference/users.md, CL
- **I-02-73** A blacklisted username blocks every user creation path (33018), and a blacklisted provider uid (with code) or oid blocks provider user creation and identity creation (33019). Source: docs/concepts/authentication.md "Blacklist Checks", test test_user_blacklist/002
- **I-02-74** `delete_user_info(_blacklist := true)` blacklists the username and every identity of the user, and a re-login through the provider is then blocked. Source: docs/reference/users.md, test test_user_blacklist/003
- **I-02-75** Deleting an entry logs 10081 and makes the username or identity usable again. A missing entry raises an error. Source: docs/reference/users.md, test test_user_blacklist/004
- **I-02-76** A blacklist entry with no matching criteria (all of username / uid / oid null) is rejected. Source: common sense **[confirm]**
- **I-02-77** Blacklisting is only checked on creation. Existing users are not re-checked on login. Source: docs/concepts/authentication.md (contradicted by docs/reference/users.md, see Open questions) **[confirm]**

## Flows

**Email/password, single call** (`verify_user_by_email`): permission -> provider active -> lookup -> status checks (I-02-04) -> hash compare. A match leaves `last_used_provider_code='email'` and one `user_logged_in` event, with no cache change. A mismatch leaves one `user_login_failed(wrong_password)` event (persisted, I-02-15), and if the threshold is reached, `is_locked=true`, the cache cleared and `user_auto_locked`, then an error.

**Email/password, two step**: `get_user_by_email_for_authentication` (status checks plus `user_logged_in`, returns hash) -> app compares -> on mismatch `record_login_failure` (same end state as the mismatch above).

**MFA step**: `get_mfa_status` -> confirmed and enabled -> `create_mfa_challenge` (previous mfa tokens `invalid`, new `valid` token, event) -> app verifies TOTP -> `verify_mfa_challenge` (token `used` plus a passed/recovery event, or token `failed` plus a failed event plus a lockout check). If MFA is not enrolled -> `unsecure.is_mfa_required` decides whether to redirect to enrollment.

**Provider login**: `ensure_user_from_provider` -> status checks (I-02-11, I-02-12) -> `user_logged_in` -> `ensure_groups_and_permissions` (domains 03/04).

**Admin lock**: `lock_user` -> `is_locked=true`, cache rows deleted for all tenants, journal 10006, event `user_locked`. The next `has_permission` for the user fails (I-02-30).

**Token round trip**: `create_token` (older same-type tokens `invalid`, journal 15001, overdue tokens expired) -> `validate_token(_set_as_used := true)` (journal 15002, token `used`) -> a second validate gives 30002.

## Failure behaviour

| Operation | Condition | Expected |
|---|---|---|
| any `auth.*` here | caller lacks the permission | 32001 (52109), journal 32001 |
| email login | provider inactive | 33010 |
| email login | unknown email / wrong hash | 33001 + `user_login_failed` |
| email login | can_login=false / disabled / identity disabled / locked | 33005 / 33003 / 33008 / 33004 |
| email login | wrong hash reaching the threshold | 33004 + `user_auto_locked` |
| provider login | `email` provider | 33006 |
| provider login | can_login / disabled / identity disabled / locked | 33005 / 33003 / 33008 / 33004 **[confirm]** for locked |
| `record_login_failure` | always | 33004 (locked by this call) or 33001 |
| enable/disable/lock/unlock | target missing / system | 33001 / 33002 **[confirm]** |
| `*_user_identity` | identity missing | 33009 |
| `update_user_password` | other user without `users.change_password` | 32001 |
| `create_token` | duplicate valid value for the same type | 30004 |
| `validate_token` | not found / not valid or expired / wrong user | 30005 / 30002 / 30003 |
| `set_token_as_used`/`failed` | token not valid | 30002 **[confirm]** |
| token type update/delete | unknown / system | 36001 / 36002 |
| `enroll_mfa` | bad type / already confirmed | 38006 / 38001 |
| `confirm_mfa_enrollment` | none pending / invalid code | 38002 / 38004 |
| `create_mfa_challenge` | not enrolled or disabled / unconfirmed | 38002 / 38003 |
| `verify_mfa_challenge` | no token / invalid or expired / other user / bad code / lock reached | 30005 / 30002 / 30003 / 38004 / 33004 |
| `reset_mfa` | not enrolled / unconfirmed | 38002 / 38003 |
| `delete_mfa_policy` | missing | 38007 |
| `create_blacklist_user` | system user | 33002 |
| user creation | blacklisted username / identity | 33018 / 33019 |

## Open questions

1. **Failure side effects are rolled back by the final `raise`.** `record_login_failure` (`037:147-163`), `verify_user_by_email` (`037:273-289`), `verify_mfa_challenge` (`038:467-490`) and every failure branch in `get_user_by_email_for_authentication` / `ensure_user_from_provider` write events (and possibly the lock) and then raise in the same transaction. Unless the app catches the error inside a savepoint and commits, nothing persists. So auto-lockout cannot trigger, the MFA brute-force protection from CL is ineffective, a failed MFA token stays `valid`, and failed logins are missing from the audit trail. `test_auto_lockout/007-008` work around this. What is the intended mechanism (return a status instead of raising, `dblink`/autonomous write, app-side catch)?
2. **MFA and MFA-policy permissions were added to every assignable perm set**, including "Tenant member" and "Auditor" (`036_tables_mfa.sql:211-231`, `039_mfa_policy.sql:91-112`, perm sets at `022_functions_auth_permission.sql:636-731`). Combined with no self/target or tenant checks in `038`/`040`, an ordinary member could disable another user's MFA, reset their recovery codes (and receive the new plaintext codes), or create a global `mfa_required=false` policy. Intended?
3. **`create_mfa_policy` / `get_mfa_policies` default `_tenant_id` to null** and pass it to `has_permission` (`040` create/get). How should `has_permissions` behave with a null tenant? There is no cache row, so it recalculates for all tenants and takes an arbitrary first row.
4. **Provider login ignores `is_locked`** (`050:131-156`), so a locked user gets `user_logged_in`. Recalculation later raises 33004, but the audit trail is misleading.
5. **The owner short-circuit in `has_permissions`** (`022_functions_auth_permission.sql:80`) returns true for a disabled or locked tenant/group owner, while non-owners are blocked by `recalculate_user_permissions`. Overlaps with domain 04.
6. **`verify_user_by_email` null hash**: `is distinct from` treats null = null as a match (`037:273`). Can an email identity exist with a null `password_hash` (invitation, admin-created)?
7. **Token lookups**: `validate_token` does not check `expires_at` (`025:276-326`; the public variant expires first, `018:446`). `set_token_as_used` / `set_token_as_failed` UPDATE without a state or type filter (`025:122-126`, `201-205`) and raise nothing when the token is not valid. With an empty uid they update every token with that value. The `_by_token` wrappers pick an arbitrary uid (`025:153-158`, `233-238`). `validate_token` accepts uid-only input with no token value. Is uid-only validation intended for non-MFA token types?
8. **Lockout counter reset**: failures before an admin unlock or a successful login still count inside the window (`037:77-82`). Should unlock or success reset the counter?
9. **Tenant scoping of user status, password change, MFA and blacklist**: all use `_tenant_id` only for the permission check, and the target can be any user in any tenant (`020:13-150`, `285`, `038`, `040`, `020:1046`). Should a tenant-N admin be limited to members of tenant N, and should app-wide config (blacklist, token types, global MFA policy) be tenant-1 only?
10. **Status functions on missing or system targets** return 0 rows and still journal and log events (`020:23-43` etc.). Error, or a silent no-op without events?
11. **Event codes**: `update_user_password` logs `change_password`, which is not seeded (seed has `password_changed` 10020). `mfa_disabled` is seeded as both 10051 (`029:130`) and 10098 (`036:93`); the second is dropped by `on conflict`. The CL says 10098, the docs say 10051.
12. **Blacklist docs conflict**: docs/reference/users.md says the blacklist prevents "registering or logging in", while docs/concepts/authentication.md says existing users are not re-checked on login. `delete_blacklist_user` raises a "not found" error with SQLSTATE 33018, the same code as "username blacklisted" (`020:1131`). `check_user_blacklist` matches an oid entry regardless of provider code (`019:2866`).
13. **Doc mismatch**: docs/reference/mfa.md says `verify_mfa_challenge` raises 30002/30003/30005 while tokens.md lists 52277-52279. These are the same SQLSTATEs through aliases; only the naming is inconsistent.

## Known coverage

| Suite | Covers |
|---|---|
| test_registration_login_events | I-02-04, 05, 09, 10, 11, 13 |
| test_auto_lockout | I-02-05, 06 (error code only), 16-20; works around I-02-15 |
| test_disabled_locked_users | I-02-28, 30, 31 (calls as user 1, so permission checks are bypassed) |
| test_tokens | I-02-42-46, 51; the expiry test sets state manually, so I-02-47 is untested |
| test_mfa | I-02-56-60 (success paths, 30005, 38004) |
| test_mfa_policy | I-02-65, 67, 68 |
| test_user_blacklist | I-02-72-75 |
| test_audit_and_user_ops | I-02-35 (self path) |

No test at all: `auth.record_login_failure`, `auth.set_token_as_failed_by_token`, `public.validate_token`, token type CRUD, `unsecure.expire_tokens`, `unsecure.update_user_password`.
Invariants with no test: I-02-01, 02, 07, 08, 12, 14, 15, 21-27, 29, 32, 33 (status errors), 37-40, 47-50, 52-54, 61-64, 66, 69, 76, 77. Permission-denied paths are untested for every function in this domain because the suites call as user 1 or as an all-permission admin.
