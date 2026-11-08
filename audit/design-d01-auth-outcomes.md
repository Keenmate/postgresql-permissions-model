# Design D-01: authentication outcomes instead of exceptions

Status: **implemented 2026-11-08** in `053_update_permissions_v2-6.sql` (v2.6).
Resolves `decisions.md` D-01 (authentication part) and D-18c, plus audit findings 01/OQ-04, 01/OQ-05,
02/1, 02/4, 02/6, 02/8, 06/Q3, 06/Q6. Naming follows `C:\Git\BlissFramework\web\docs\coding-guidelines-postgres\`.

## Problem

1. **Lost writes.** `record_login_failure`, `verify_user_by_email`, `verify_mfa_challenge`,
   `validate_api_key` and the failure branches of `get_user_by_email_for_authentication` /
   `ensure_user_from_provider` write the failure event (plus the auto-lock and the token's `failed`
   state), then raise in the same statement. The raise rolls all of it back, so:
   - auto-lockout never triggers;
   - MFA brute-force protection does nothing, and a failed MFA token stays `valid`;
   - failed logins and failed API-key validations are missing from the audit trail.
2. **The library never reports failures.** `keen-auth-permissions` checks the password itself and
   returns `:invalid_credentials` without telling the database.
3. **The email flows are broken:**
   - `get_user_by_email_for_authentication` logs `user_logged_in` *before* the password is checked.
   - `verify_user_by_email` compares hashes in the database. That can't work with salted hashes
     (Pbkdf2/Argon2), and a null stored hash matches a null input.
4. **Lockout is a denial-of-service hole.** An auto-lock is permanent until an admin unlocks it, so
   anyone who knows a username can lock that user out.
5. **Failures are counted by scanning `auth.user_event`.** That gets slower as the table grows, and
   concurrent failures race past the threshold.
6. **Provider login ignores `is_locked`.**

## Decisions

| # | Decision |
|---|---|
| 1 | Expected authentication outcomes are **returned, not raised**. Exceptions stay for faults (missing permission of the calling service, bad arguments). |
| 2 | Functions are **changed in place**. Breaking changes are acceptable; `keen-auth-permissions` is updated alongside. Changed return types need `drop function` + `create`. |
| 3 | Verb registry: `get_*` only reads; every write and every login decision happens in a `create_*_attempt` function. `verify_*` / `validate_*` keep their meaning (they raise), so the functions that now return outcomes are renamed. |
| 4 | Outcome columns: `__event_id integer` (id from `const.event_code`), `__outcome_code text` (its `code`), and `__user_event_id bigint` (the `auth.user_event` row this call wrote). No new outcome vocabulary. |
| 5 | Wrong password reports **33001**, the same as an unknown user (no account enumeration). |
| 6 | Lockout is **temporary and escalating** (`locked_until`). The admin lock (`is_locked`, `lock_user` / `unlock_user`) stays separate and permanent. |
| 7 | The escalation steps are a **system parameter** that can be updated but not deleted. |
| 8 | Counters live in a narrow table `auth.user_login_state`, **not** on `user_info`. Updating `user_info` fires the search-text trigger and two after-triggers, and touches indexed columns. |

## Schema

```sql
create table auth.user_login_state
(
    created_at           timestamp with time zone default now()           not null,
    created_by           text                     default 'unknown'::text not null,
    updated_at           timestamp with time zone default now()           not null,
    updated_by           text                     default 'unknown'::text not null,
    user_id              bigint primary key references auth.user_info on delete cascade,
    failed_login_count   integer default 0 not null,   -- failures inside the current window
    last_failed_login_at timestamp with time zone,
    lockout_count        integer default 0 not null,   -- consecutive auto-lockouts, drives escalation
    locked_until         timestamp with time zone      -- temporary lock; null = not temporarily locked
);
```

The row is created on the first failure (`insert ... on conflict (user_id) do update`).

### System parameters (`const.sys_param`)

- New column `is_system boolean default false not null`. Every core-seeded parameter becomes
  `is_system = true` (`journal.*`, `user_event.*`, `partition.*`, `login_lockout.*`), because code
  reads all of them.
- New trigger `trg_const_sys_param_validate` (before update or delete) calling
  `triggers.validate_sys_param()`. It raises:
  - **31015** `err_sys_param_is_system` when deleting an `is_system` row, or when switching
    `is_system` off;
  - **31016** `err_sys_param_invalid_value` when `login_lockout.lockout_durations_minutes` is not a
    comma-separated list of positive integers.

| group_code | code | value | Meaning |
|---|---|---|---|
| `login_lockout` | `max_failed_attempts` | `5` (exists) | Failures inside the window that trigger a lockout |
| `login_lockout` | `window_minutes` | `15` (exists) | Failure-counting window |
| `login_lockout` | `lockout_durations_minutes` | `'15,60,240,960,1440'` (new, `text_value`) | Duration of the 1st, 2nd, 3rd … lockout. The last value repeats, so it is the cap. |
| `login_lockout` | `lockout_reset_hours` | `24` (new) | After this long without a failure, `lockout_count` drops back to 0, so the next lockout starts at the first step again |

Updated through the existing `auth.update_sys_param`; nothing can delete them.

## Functions

All the functions below write the `auth.user_event` row for the attempt. Because they never raise
for an expected outcome, that row, the counters and the token state **commit with the caller's
transaction**.

> **Caller contract:** do not wrap these calls in a transaction that you roll back when the outcome
> is a failure. Postgrex calls outside `Repo.transaction` autocommit.

### 1. `auth.get_user_by_email_for_authentication`: read only (changed in place)

It no longer writes anything: no events, no `last_used_provider` update.

```sql
returns table(__user_id bigint, __code text, __uuid text, __username text, __email text, __display_name text,
              __can_login boolean, __is_active boolean, __is_locked boolean, __locked_until timestamptz,
              __is_identity_active boolean,
              __password_hash text, __password_salt text)   -- only when the user may log in now
```

No row is returned when the email is unknown. The app still calls step 2 in that case.

### 2. `auth.create_user_login_attempt`: every login decision (new; replaces `record_login_failure`)

```sql
auth.create_user_login_attempt(_created_by text, _user_id bigint, _correlation_id text,
                               _provider_code text, _provider_uid text,   -- email for the email provider
                               _target_user_id bigint,                   -- null when step 1 found nothing
                               _is_credential_valid boolean,             -- null when there was no hash to check
                               _request_context jsonb default null, _tenant_id integer default 1)
returns table(__event_id integer, __outcome_code text, __user_event_id bigint,
              __failed_login_count integer, __max_failed_attempts integer, __locked_until timestamptz)
```

- Permission: new `authentication.create_user_login_attempt`, added to the Svc authenticator perm set.
- It re-reads the user's state itself (never trusts step 1), locking the `user_login_state` row with
  `for update`.
- The checks run in this order; the first one that applies decides the outcome:

| # | Condition | Writes | `__event_id` / `__outcome_code` |
|---|---|---|---|
| 1 | no such user / identity | `user_login_failed`, reason `user_not_found` | 33001 `err_user_not_found` |
| 2 | `can_login = false` | `user_login_failed`, reason `login_disabled` | 33005 `err_user_cannot_login` |
| 3 | user disabled | `user_login_failed`, reason `user_disabled` | 33003 `err_user_not_active` |
| 4 | identity disabled | `user_login_failed`, reason `identity_disabled` | 33008 `err_identity_not_active` |
| 5 | `is_locked` (admin) | `user_login_failed`, reason `user_locked` | 33004 `err_user_locked` |
| 6 | `locked_until > now()` | `user_login_failed`, reason `user_temporarily_locked`. **Not counted**, so a lock can't escalate while it's running. | 33004 `err_user_locked` |
| 7 | credential not valid, threshold not reached | `user_login_failed`, reason `wrong_password`; counter +1 (reset first if the last failure is outside the window; `lockout_count` reset first if the last failure is older than `lockout_reset_hours`) | 33001 `err_user_not_found` |
| 8 | credential not valid, threshold reached | as 7, plus: `lockout_count + 1`; `locked_until = now() + step(lockout_count)`; counter reset to 0; event `user_auto_locked` (10083, same correlation id) | 33004 `err_user_locked` |
| 9 | credential valid | `user_logged_in`; `last_used_provider` set; `failed_login_count = 0`, `lockout_count = 0`, `locked_until = null` | 10010 `user_logged_in` |

`__user_event_id` is the row for the attempt. For case 8 that is the `user_login_failed` row; the
`user_auto_locked` row shares the correlation id.

### 3. `auth.ensure_user_from_provider`: outcome columns added (changed in place)

- Adds `__event_id`, `__outcome_code` and `__user_event_id` to the existing user columns.
- It runs the same state checks (rows 2–6, now including `is_locked` and `locked_until`) through a
  shared `unsecure.*` worker, and returns the outcome instead of raising.
- A username taken by another user returns **33024** `err_username_already_exists`, logged as a
  `user_login_failed` event.
- Provider logins never increment the failure counter: the provider checked the credential, not us.

### 4. `auth.create_mfa_challenge_attempt` (new; replaces `verify_mfa_challenge`)

- Same parameters as today's `verify_mfa_challenge`, with `_code_is_valid` renamed to `_is_code_valid`.
- Returns `__event_id`, `__outcome_code`, `__user_event_id`, `__recovery_codes_remaining`,
  `__failed_login_count`, `__locked_until`.
- Outcomes:
  - 10093 `mfa_challenge_passed`
  - 10094 `mfa_recovery_used`
  - 38004 `err_mfa_invalid_code`: the token is set to `failed` (and stays failed), and the shared
    counter goes up;
  - 33004 `err_user_locked`
  - 30002 `err_token_invalid`, 30004 `err_token_already_used`, 30005 `err_token_not_found`
- MFA failures increment the same counter as password failures.

### 5. `auth.create_api_key_validation_attempt` (new; replaces `validate_api_key`)

- Returns `__event_id`, `__outcome_code`, `__user_event_id`, `__user_id`, `__username`,
  `__user_display_name`.
- Outcomes:
  - 14010 `apikey_validated`
  - 30001 `err_api_key_invalid`
  - **30006** `err_api_key_expired` (new code)
  - 33003 / 33004 when the technical user is disabled or locked (audit 06/Q3)
- Failures are logged as `apikey_validation_failed` (14011), which is seeded today but never used.
- Permissions are no longer returned. The caller asks `auth.has_permission` (audit 06/Q5): the
  current list ignores group membership and the cache.
- No lockout for API keys.

### Removed
- `auth.record_login_failure`, replaced by `create_user_login_attempt`.
- `auth.verify_user_by_email`: hash comparison in the database can't work with salted hashes.
- `auth.verify_mfa_challenge` and `auth.validate_api_key`: renamed as above.
- `unsecure.check_and_auto_lock_user`, replaced by the counter logic.

## Rules for the app (to be written into the function comments)

- Map every failure outcome to one generic "invalid credentials" message. Only 33004 (locked) may
  be shown differently, with `__locked_until`.
- When step 1 returns no row, still run a dummy hash check (timing), then call step 2 with
  `_target_user_id = null`.
- Rate-limiting unknown emails, per IP or per email address, is the app's or proxy's job. There is
  no user to lock.

## Library changes (`keen-auth-permissions`)

- Regenerate the db-gen models for every changed or new function.
- `Auth.authenticate` / `Email.authenticate`: call step 1, check the hash, **always** call
  `create_user_login_attempt`, and map `__outcome_code`.
- MFA verification: call `create_mfa_challenge_attempt`.
- API key validation: call `create_api_key_validation_attempt`, then `has_permission`.
- Provider login: map the new outcome columns of `ensure_user_from_provider` instead of matching
  `pg_code`.

## Tests (`tests/test_audit_authentication/`, transaction isolation, never user 1)

- 5 wrong passwords: the 5th returns 33004; `locked_until` is about 15 min out; the
  `user_login_failed` and `user_auto_locked` rows **exist after the call** (the core regression).
- While locked: a correct password returns 33004 and the counter doesn't grow. After `locked_until`
  passes (simulated by moving the timestamp), a correct password logs in and resets the counters.
- Escalation: the 2nd lockout lasts 60 min and the 6th lasts 1440 (the cap). A changed
  `lockout_durations_minutes` value is honoured.
- Decay: with the last failure older than `lockout_reset_hours`, the next lockout is back at the
  first step.
- An admin lock (`is_locked`) blocks login regardless of `locked_until`.
- Step 1 writes nothing: no `user_logged_in` before the password check, and no hash for disabled or
  locked users.
- Unknown email: 33001, an event with no target, no counter row.
- Provider login of a locked user returns 33004 (it used to log in).
- MFA: a wrong code persists the `failed` token state, a failed token can't be retried, and MFA
  failures count toward the lockout.
- API key: an invalid secret persists 14011; an expired key returns 30006; a disabled technical user
  returns 33003.
- sys_param: deleting a system parameter raises 31015; an invalid duration list raises 31016;
  updating works.

## Out of scope (tracked in `decisions.md`)

- Permission denials (32001) keep raising. The library logs them; `get_security_events` stops
  claiming to persist them.
- Permission checks on soft-deleted tenants and disabled users (D-06).
