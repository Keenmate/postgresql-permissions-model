# Client library notes

Technical notes for the libraries that wrap this database model: `keen-auth-permissions` (Elixir)
today, and the planned C# library. These are notes for the people who write a client library, not
for application developers.

- **Sections are per database version.** Each one lists exactly what a library must change to
  support that version. Versions are `postgresql_permissionmodel` versions in `public.__version`,
  each shipped as one `NNN_update_permissions_v2-N.sql`.
- **Status:** each version section says whether `keen-auth-permissions` has adopted it.
- Every update script that changes a function signature, return shape, error behaviour or required
  permission adds a section here (see CLAUDE.md).

**Minimum database version:** a library checks `public.check_version('2.9', 'postgresql_permissionmodel')`
at startup (currently 2.9) and refuses to run against an older database. The versions below are not backward compatible.

---

## General contract (applies to all versions)

### Calling convention
- Every `auth.*` function takes the acting user and the correlation id first:
  `(_created_by|_updated_by|_deleted_by text, _user_id bigint, _correlation_id text, ...)`. Read
  functions omit the `*_by` argument.
- `_user_id` is the **acting** user, the one whose permission is checked. The user being acted on
  is `_target_user_id`.
- `_tenant_id integer default 1` is the caller's tenant for the permission check. Tenant 1 is the
  admin tenant.
- Return columns are `__`-prefixed (`__user_id`). Map them to idiomatic names in the library
  (`user_id`, `UserId`), but keep the mapping mechanical so the code can be generated.
- Parameters and return columns use only stock PostgreSQL types and `jsonb`; no extension types.
- **Never call user 1 at runtime.** It bypasses every check. Use the seeded service users below.

### Service users
The flows a library runs on behalf of an anonymous visitor go through seeded service users. Load
their ids once by username (`select user_id from auth.user_info where username = $1`); don't
hard-code the ids.

| Service user | Used for | Perm set |
|---|---|---|
| `svc_registrator` | `register_user`, default groups, tokens for registration | `svc_registrator_permissions` |
| `svc_authenticator` | Email login (steps 1 and 2), provider login, MFA challenge + attempt, token validation | `svc_authenticator_permissions` |
| `svc_token_manager` | Token create / validate / mark used | `svc_token_permissions` |
| `svc_api_gateway` | API-key validation | `svc_api_gateway_permissions` |

### Errors (exceptions)
- Errors are raised with a five-digit `SQLSTATE` equal to the error code (e.g. `33004`). Postgrex
  shows it as `%Postgrex.Error{postgres: %{pg_code: "33004"}}`; Npgsql as `PostgresException.SqlState`.
- Codes are listed in `error-codes.md`. Message templates are in `const.event_message`
  (`event_id`, `language_code`, `message_template`) for localized messages.
- Codes `52xxx` are legacy aliases that raise the matching `3xxxx` code. Map the `3xxxx` code.
- Map errors to typed results / exceptions **by code**, not by message text.

### Outcomes (since v2.6)
The authentication functions don't raise for **expected** results (wrong password, locked,
disabled, invalid code, expired key). They return a row with:

| Column | Type | Meaning |
|---|---|---|
| `__event_id` | integer | Code from `const.event_code`: a success event (10010, 10093, 10094, 14010) or an error code (33001, 33004, …) |
| `__outcome_code` | text | The `const.event_code.code` for `__event_id` (`user_logged_in`, `err_user_locked`, …) |
| `__user_event_id` | bigint | The `auth.user_event` row this call wrote (audit link). Null if user events are stored as notify-only |

Library rules:
1. **Switch on `__event_id`.** It's the stable contract, and the numbers equal the SQLSTATEs the
   functions raised before v2.6, so existing error mappings can be reused.
2. **Do not roll back on a failure outcome.** The row the function wrote (event, failure counter,
   lock, failed MFA token) must commit, or the lockout stops working. Call these functions outside
   an explicit transaction (autocommit), or commit before turning the outcome into an error. Never
   call them inside a transaction that is rolled back because the login failed.
3. **One generic message for the end user.** Map every failure to "invalid credentials", except
   33004 (locked), which may say "locked until `__locked_until`". 33001 is returned for an unknown
   user *and* a wrong password on purpose (no account enumeration).
4. Exceptions still mean faults: the service user lacks a permission (32001), bad arguments, the
   provider is not active, a blacklisted identity. Surface them as errors, not as login failures.

---

## v2.9 — global user state needs the permission in tenant 1 (`056`)

**Status in keen-auth-permissions: not adopted.** No signature changes. Behaviour changes:

- **Some user functions now check the permission in tenant 1, whatever `_tenant_id` you pass:**
  - `lock_user`, `unlock_user`, `enable_user`, `disable_user`, `delete_user_info`
  - `update_user_password`, `update_user_data`, `update_user_preferences`
  - `enable_user_identity`, `disable_user_identity`, `verify_user_identity`, `create_user_identity_link`
  - `enroll_mfa`, `confirm_mfa_enrollment`, `disable_mfa`, `reset_mfa`
  - `create_blacklist_user`, `delete_blacklist_user`

  A tenant admin who held `users.*` / `mfa.*` only in their own tenant now gets 32001. Grant these
  permissions in tenant 1 to whoever manages users: user-manager admins, and service users that
  enroll or confirm MFA on the user's behalf.
- **Hide these actions from tenant-only admins.** A UI that offers lock / disable / reset-MFA in a
  tenant's admin screen should drop them unless the caller holds the permission in tenant 1.
- **Self-service is unchanged.** Own password, own identity link, own profile data and preferences
  still need no permission.
- **`_tenant_id` is still accepted** and goes into the journal, so keep passing the current tenant.

---

## v2.8 — entities passed by id must belong to `_tenant_id` (`055`)

**Status in keen-auth-permissions: not adopted.** No signature changes. Behaviour changes:

- **Pass the entity's own tenant as `_tenant_id`.** Every function that takes a group, API key,
  invitation, invitation template or MFA policy id now raises *not found* when the entity belongs to
  another tenant:

  | Entity | Error raised on a mismatch |
  |---|---|
  | group | 33011 |
  | API key | 30007 (new) |
  | invitation | 39001 |
  | template | 39006 |
  | MFA policy | 38007 |

  - **Tenant-1 admins** who managed other tenants' entities while passing `_tenant_id := 1` now get
    *not found*. They must call with the entity's tenant and hold the permission there.
  - **Libraries** that defaulted `_tenant_id` to 1 for these calls must pass the current tenant.
- **Silent no-ops became errors.** These used to report success without changing anything on a
  mismatch, and now raise:
  - `update_user_group`;
  - enable / disable / lock / unlock / delete group;
  - `update_api_key`, `unassign_api_key_permissions`.

  `update_api_key_secret` used to return a secret that was never stored. Map these errors to
  "not found" in the UI.
- **Global templates and MFA policies.** Templates and policies with `tenant_id` null are managed
  with `_tenant_id := 1`; the permission is checked in tenant 1. Passing null to
  `create_mfa_policy`, `get_mfa_policies` or `create_invitation_template` checks tenant 1 too.
- **`has_permission(s)` with `_tenant_id := null` is denied** (32001, or `false`). It used to
  succeed if the user held the permission in any tenant.
- **Error 30007 `err_api_key_not_found`** is new; add it to the error mapping.

---

## v2.7 — disabled and deleted state removes access (`054`)

**Status in keen-auth-permissions: not adopted.** No signature changes. Behaviour changes:

- **`auth.has_permission(s)` with `_throw_err := false` never raises any more.** It returns `false`
  for an unknown, disabled or locked user, where it used to raise 33001 / 33003 / 33004 when the
  cache needed a rebuild. If the library relied on catching those to detect a disabled user, check
  the user's state explicitly instead. With `_throw_err := true` (the default) the codes are still
  raised: 33003 disabled, 33004 locked, 33001 unknown.
- **Permission checks inside a soft-deleted tenant are denied** (32001, or `false`), for owners too.
  An app that lets users keep working in a tenant after it was closed will now see 32001. Treat it
  like a revoked permission.
- **Access ends immediately, not after the cache expires.** Disabling a group, provider, identity
  or user, or soft-deleting a tenant, removes access at the next check. Libraries that cache
  permission results on their side should keep that cache short, or listen to the
  `pg_notify` channels, so they don't undo this.

---

## v2.6 — authentication outcomes (`053`)

**Status in keen-auth-permissions: not adopted.** Breaking.

### Removed functions
| Removed | Replacement |
|---|---|
| `auth.record_login_failure` | `auth.create_user_login_attempt` with `_is_credential_valid := false` |
| `auth.verify_user_by_email` | Two-step login below (hashes are compared in the app; the database can't compare salted hashes) |
| `auth.verify_mfa_challenge` | `auth.create_mfa_challenge_attempt` |
| `auth.validate_api_key` | `auth.create_api_key_validation_attempt` + `auth.has_permission` |

### Email + password login

```
1. auth.get_user_by_email_for_authentication(_user_id := svc_authenticator, _correlation_id, _email,
                                               _request_context, _tenant_id)
   -> 0 or 1 row:
      __user_id, __code, __uuid, __username, __email, __display_name, __provider,
      __can_login, __is_active, __is_locked, __locked_until, __is_identity_active,
      __password_hash, __password_salt        -- hash/salt only when the user may log in now
   Read only: writes no event, never raises for user state.

2. In the library:
      if row and row.password_hash is not null:  valid = hasher.verify(password, row.password_hash)
      else:                                       hasher.no_user_verify(); valid = null   -- constant time

3. auth.create_user_login_attempt(_created_by, _user_id := svc_authenticator, _correlation_id,
                                  _provider_code := 'email', _provider_uid := <email as typed>,
                                  _target_user_id := row?.user_id,      -- null when step 1 returned nothing
                                  _is_credential_valid := valid,        -- null when there was no hash to check
                                  _request_context, _tenant_id)
   -> __event_id, __outcome_code, __user_event_id, __failed_login_count, __max_failed_attempts, __locked_until
```

**Always call step 3**, including when step 1 returned no row or no hash. It's what records the
attempt and enforces the lockout.

| `__event_id` | `__outcome_code` | Library result |
|---|---|---|
| 10010 | `user_logged_in` | success, return the user from step 1 |
| 33001 | `err_user_not_found` | invalid credentials (unknown email *or* wrong password) |
| 33003 | `err_user_not_active` | invalid credentials (user disabled) |
| 33004 | `err_user_locked` | locked; `__locked_until` is set for a temporary lock and null for an admin lock |
| 33005 | `err_user_cannot_login` | invalid credentials (login disabled, e.g. service account) |
| 33008 | `err_identity_not_active` | invalid credentials (email identity disabled) |

`__failed_login_count` / `__max_failed_attempts` are for logging and metrics. Don't show them to
the user.

Elixir sketch:
```elixir
row = case db.auth_get_user_by_email_for_authentication(svc, corr, email, ctx) do
  {:ok, [row]} -> row
  {:ok, []}    -> nil
end
valid? = if row && row.password_hash, do: Pbkdf2.verify_pass(password, row.password_hash),
                                      else: (Pbkdf2.no_user_verify(); nil)
{:ok, [r]} = db.auth_create_user_login_attempt("svc_authenticator", svc, corr, "email", email,
                                               row && row.user_id, valid?, ctx)
case r.event_id do
  10010 -> {:ok, row}
  33004 -> {:error, {:locked, r.locked_until}}
  _     -> {:error, :invalid_credentials}
end
```

C# sketch:
```csharp
var row = await db.GetUserByEmailForAuthenticationAsync(svcId, corr, email, ctx);
bool? valid = row?.PasswordHash is { } hash ? hasher.Verify(password, hash) : NoUserVerify();
var r = await db.CreateUserLoginAttemptAsync("svc_authenticator", svcId, corr, "email", email,
                                             row?.UserId, valid, ctx);
return r.EventId switch {
    10010 => LoginResult.Success(row!),
    33004 => LoginResult.Locked(r.LockedUntil),
    _     => LoginResult.InvalidCredentials()
};
```

### Provider (SSO) login: `auth.ensure_user_from_provider`
- Same parameters as before.
- **New return columns** `__event_id`, `__outcome_code` and `__user_event_id`, after the user columns.
- On failure the **user columns are null**. Check `__event_id = 10010` before treating the user as
  logged in. Code that only read `__user_id` and relied on an exception for failures now treats a
  null user as success. **Update it.**
- Outcomes: 10010, 33003, 33004 (now also for locked users, which used to log in), 33005, 33008,
  **33024** `err_username_already_exists`. The last one means a first login whose username belongs
  to another user. Offer an account-link flow (see v2.4); don't create a new account.
- Still raises (faults): 52101 (email provider not allowed here), inactive provider, 33019
  blacklisted identity, 33018 blacklisted username.
- Provider logins never count toward the lockout, but a locked user cannot log in.

### MFA: `auth.create_mfa_challenge_attempt`
- Call as `svc_authenticator`. The step runs before the user is logged in. Since v2.6 that service
  user holds `mfa.create_mfa_challenge`, `mfa.verify_mfa_challenge` and `tokens.create_token`.
- Signature: `(_created_by, _user_id, _correlation_id, _target_user_id, _token_uid, _is_code_valid boolean, _recovery_code text default null, _request_context, _tenant_id)`.
  `_code_is_valid` was renamed to `_is_code_valid`.
- The library verifies the TOTP code itself (the secret never reaches the database) and passes
  `_is_code_valid`. A recovery code is passed as plain text and checked by the database.
- Returns `__event_id, __outcome_code, __user_event_id, __recovery_codes_remaining, __failed_login_count, __locked_until`.

| `__event_id` | Meaning | Library result |
|---|---|---|
| 10093 | `mfa_challenge_passed` | success |
| 10094 | `mfa_recovery_used` | success; warn the user when `__recovery_codes_remaining` is low |
| 38004 | `err_mfa_invalid_code` | invalid code. **The token is spent**: create a new challenge to retry |
| 33004 | `err_user_locked` | locked (MFA failures share the login lockout counter) |
| 33003 / 33005 | user disabled / cannot log in | invalid credentials |
| 30002 / 30003 / 30004 / 30005 | token invalid or expired / wrong user / already used / not found | restart the login |

### API keys: `auth.create_api_key_validation_attempt`
- Call as `svc_api_gateway`.
- Signature: `(_created_by, _user_id, _correlation_id, _api_key, _api_secret, _request_context, _tenant_id)`.
- Returns `__user_id, __username, __user_display_name, __event_id, __outcome_code, __user_event_id`.
  The user columns are null on failure.
- **Permissions are no longer returned** (`__permission_full_codes` is gone). Check them with
  `auth.has_permission(__user_id, _correlation_id, '<code>', _tenant_id, false)`, or load them with
  the regular permission functions. The old list ignored group membership and the cache.
- Outcomes:
  - 14010 `apikey_validated`
  - 30001 `err_api_key_invalid` (unknown key or wrong secret; not distinguished, on purpose)
  - **30006** `err_api_key_expired` (new)
  - 33003 / 33004 (technical user disabled / locked)
- Cache the validation result only briefly. Disabling the technical user, expiring the key or
  rotating the secret must take effect.

### Lockout
- Temporary and escalating. After `login_lockout.max_failed_attempts` (5) failures within
  `window_minutes` (15), the user is locked for the next step of `lockout_durations_minutes`
  (`15,60,240,960,1440`; the last step repeats). A successful login resets it; so do
  `lockout_reset_hours` (24) without a failure.
- The admin lock (`auth.lock_user` / `auth.unlock_user`, `__is_locked`) is separate and permanent.
  33004 with `__locked_until = null` means an admin lock.
- The settings are system parameters: update them with `auth.update_sys_param`. They cannot be
  deleted (31015), and invalid values are rejected (31016).

### Codegen checklist (db-gen models)
- **Drop:** `auth_record_login_failure`, `auth_verify_user_by_email`, `auth_verify_mfa_challenge`,
  `auth_validate_api_key`.
- **Regenerate** (return shape changed): `auth_get_user_by_email_for_authentication`,
  `auth_ensure_user_from_provider`.
- **Add:** `auth_create_user_login_attempt`, `auth_create_mfa_challenge_attempt`,
  `auth_create_api_key_validation_attempt`.

---

## v2.5 — tenant lifecycle scoping (`052`)

**Status in keen-auth-permissions: not adopted.** No signature changes. Behaviour changes callers must know:

- `auth.create_tenant`, `auth.restore_tenant` and `auth.purge_tenant` check their permission **in
  tenant 1**, whatever `_tenant_id` is passed. A tenant admin calling them from their own tenant
  gets 32001.
- `auth.delete_tenant`:
  - A tenant's own admin may soft-delete that tenant (call with `_tenant_id` = that tenant).
  - Deleting any other tenant needs `tenants.delete_tenant` in tenant 1.
  - A soft-deleted tenant can only be restored from tenant 1.
- `auth.update_tenant`: renaming stays with the tenant's admin. Changing `_is_removable` or `_code`
  also needs `tenants.update_tenant` in tenant 1 (otherwise 32001).
- The `tenant_admin` perm set no longer contains `create_tenant`, `purge_tenant` or any
  `get_all_*` / `read_all_*`. Admin UIs that offered "create tenant" or a cross-tenant view to
  tenant admins must hide them.

---

## v2.4 — no identity linking by username (`051`)

**Status in keen-auth-permissions: not adopted.**

- `auth.register_user` raises **33007** when the address is taken: an email identity exists, or
  any user has that username, including SSO-only users. Map it to "email already registered".
- A first provider login whose username belongs to another user is refused. Since v2.6 it is the
  outcome 33024 of `ensure_user_from_provider` (in v2.4–v2.5 it was a raised 33024).
- **Account linking is explicit:**
  ```
  auth.create_user_identity_link(_created_by, _user_id, _correlation_id, _target_user_id,
                                 _provider_code, _provider_uid, _provider_oid default null,
                                 _password_hash default null, _user_data jsonb default null,
                                 _request_context, _tenant_id)
  -> __user_identity_id, __user_id, __provider_code, __uid, __is_active, __is_verified
  ```
  - **Self-link** (`_user_id = _target_user_id`) needs no permission. Linking another user's
    account needs `users.create_user_identity_link`.
  - **The library must authenticate both sides before calling it:** the current session (the user
    is logged in) *and* the new identity (provider callback completed, or a password the user just
    set). The database cannot check either.
  - A linked **email** identity is created unverified. Run the email-verification flow
    (`auth.verify_user_identity`) before trusting the address.
  - Errors: 33007 (identity already used by anyone), 33001 / 33003 / 33004 / 33005 (target
    unknown / disabled / locked / service account), 32001.
- Suggested UX: on 33024 from a provider login, tell the user an account with that username exists
  and ask them to sign in with their existing method, then link the provider from their account
  settings.
