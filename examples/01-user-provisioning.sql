/*
 * Example 01 — User provisioning, authentication, password & account status
 * =========================================================================
 *
 * A full user lifecycle, aspect by aspect:
 *   - provisioning from an external provider (+ idempotency) and local signup
 *   - authenticating: provider (SSO) path vs. email + password path
 *   - password management (change the hash, prove it took effect)
 *   - how account status (lock / disable) gates authentication
 *
 * Each statement is standalone plain SQL — run them one at a time in any client.
 * Negative cases (wrong password, locked, disabled) use do-blocks that catch the
 * raised error so the whole file still runs clean. Data PERSISTS (Twin Peaks
 * characters on @twinpeaks.com); run examples/cleanup.sql to remove it (and
 * before re-running). Acts as the seeded system user (user_id = 1, tenant 1).
 */

set search_path = public, const, ext, stage, helpers, internal, unsecure, auth, triggers;


-- ── Aspect: register an external identity provider ───────────────────────────
-- ensure_provider upserts a provider row (idempotent). AzureAD, group-mapping on.
select * from auth.ensure_provider('examples', 1, 'ex01', 'aad', 'Azure Active Directory',
                                   _allows_group_mapping := true, _allows_group_sync := true);


-- ── Aspect: provision a user from that provider ──────────────────────────────
-- Creates auth.user_info + auth.user_identity in one call.
select * from auth.ensure_user_from_provider('examples', 1, 'ex01',
        _provider_code := 'aad', _provider_uid := 'coop-001', _provider_oid := 'oid-coop-001',
        _username := 'dale.cooper@twinpeaks.com', _display_name := 'Dale Cooper',
        _email := 'dale.cooper@twinpeaks.com');


-- ── Aspect: idempotency ──────────────────────────────────────────────────────
-- Re-running the SAME (provider_code, provider_uid) returns the existing user_id
-- instead of creating a duplicate — this is also the provider LOGIN path (below).
select * from auth.ensure_user_from_provider('examples', 1, 'ex01',
        _provider_code := 'aad', _provider_uid := 'coop-001', _provider_oid := 'oid-coop-001',
        _username := 'dale.cooper@twinpeaks.com', _display_name := 'Special Agent Dale Cooper',
        _email := 'dale.cooper@twinpeaks.com');

-- Proof: exactly one row for Cooper.
select count(*) as cooper_rows from auth.user_info where email = 'dale.cooper@twinpeaks.com';  -- expect 1


-- ── Aspect: local registration (email + password) ────────────────────────────
-- Creates the user + an 'email' identity holding the password hash. In a real
-- app you pass the already-hashed password; here 'pw-hash-v1' stands in for it.
-- _user_data is an arbitrary jsonb profile stored on the user.
select * from auth.register_user('examples', 1, 'ex01',
        _email := 'donna.hayward@twinpeaks.com', _password_hash := 'pw-hash-v1',
        _display_name := 'Donna Hayward',
        _user_data := '{"firstName": "Donna", "lastName": "Hayward"}');


-- ── Aspect: list users known to a provider ───────────────────────────────────
select * from auth.get_provider_users('examples', 1, 'ex01', 'aad');    -- Cooper
select * from auth.get_provider_users('examples', 1, 'ex01', 'email');  -- Donna (local)


-- ── Aspect: authentication lookup by email (login step 1, read only) ─────────
-- Returns the user, their login state and - only when they may log in right
-- now - the stored password hash/salt, so the app can verify the password itself.
-- Writes nothing.
select * from auth.get_user_by_email_for_authentication(1, 'ex01', 'donna.hayward@twinpeaks.com');


-- ── Aspect: AUTHENTICATION — provider (SSO) path ─────────────────────────────
-- A returning SSO user "logs in" by the app re-calling ensure_user_from_provider
-- with the provider's uid; it returns the existing user (no duplicate) plus the
-- outcome (__event_id 10010 user_logged_in, or a failure such as 33004 with null
-- user columns). Usually followed by ensure_groups_and_permissions (see ex05).
select * from auth.ensure_user_from_provider('examples', 1, 'ex01',
        _provider_code := 'aad', _provider_uid := 'coop-001', _provider_oid := 'oid-coop-001',
        _username := 'dale.cooper@twinpeaks.com', _display_name := 'Dale Cooper',
        _email := 'dale.cooper@twinpeaks.com');


-- ── Aspect: AUTHENTICATION — email + password path (login step 2) ────────────
-- After checking the hash, the app reports the result with
-- create_user_login_attempt. It decides the outcome (__event_id / __outcome_code),
-- logs the user_event, counts failures and locks temporarily after
-- login_lockout.max_failed_attempts. Failures are returned, not raised, so the
-- event and the counter persist. Below, "__password_hash = '<hash>'" stands in
-- for the app's own password check.
-- Correct password → 10010 user_logged_in:
select a.*
from auth.get_user_by_email_for_authentication(1, 'ex01', 'donna.hayward@twinpeaks.com') u
   , auth.create_user_login_attempt('examples', 1, 'ex01', 'email', 'donna.hayward@twinpeaks.com',
        u.__user_id, u.__password_hash = 'pw-hash-v1', '{"ip": "203.0.113.5", "user_agent": "ExampleAgent/1.0"}') a;

-- Wrong password → 33001 (same as an unknown user), failure counted:
select a.*
from auth.get_user_by_email_for_authentication(1, 'ex01', 'donna.hayward@twinpeaks.com') u
   , auth.create_user_login_attempt('examples', 1, 'ex01', 'email', 'donna.hayward@twinpeaks.com',
        u.__user_id, u.__password_hash = 'wrong-hash', '{"ip": "203.0.113.9"}') a;


-- ── Aspect: password management ──────────────────────────────────────────────
-- Change the password hash …
select * from auth.update_user_password('examples', 1, 'ex01',
        _target_user_id := (select user_id from auth.user_info where email = 'donna.hayward@twinpeaks.com'),
        _password_hash  := 'pw-hash-v2',
        _request_context := '{"ip": "203.0.113.5"}');

-- … the OLD hash no longer authenticates (33001) …
select a.__event_id, a.__outcome_code
from auth.get_user_by_email_for_authentication(1, 'ex01', 'donna.hayward@twinpeaks.com') u
   , auth.create_user_login_attempt('examples', 1, 'ex01', 'email', 'donna.hayward@twinpeaks.com',
        u.__user_id, u.__password_hash = 'pw-hash-v1') a;

-- … and the NEW hash does (10010):
select a.__event_id, a.__outcome_code
from auth.get_user_by_email_for_authentication(1, 'ex01', 'donna.hayward@twinpeaks.com') u
   , auth.create_user_login_attempt('examples', 1, 'ex01', 'email', 'donna.hayward@twinpeaks.com',
        u.__user_id, u.__password_hash = 'pw-hash-v2') a;


-- ── Aspect: account status gates authentication ──────────────────────────────
-- Lock the account → login is refused even with the right password (33004) …
select * from auth.lock_user('examples', 1, 'ex01',
        (select user_id from auth.user_info where email = 'donna.hayward@twinpeaks.com'));
select a.__event_id, a.__outcome_code
from auth.get_user_by_email_for_authentication(1, 'ex01', 'donna.hayward@twinpeaks.com') u
   , auth.create_user_login_attempt('examples', 1, 'ex01', 'email', 'donna.hayward@twinpeaks.com',
        u.__user_id, u.__password_hash = 'pw-hash-v2') a;

-- … unlock → login works again …
select * from auth.unlock_user('examples', 1, 'ex01',
        (select user_id from auth.user_info where email = 'donna.hayward@twinpeaks.com'));
select a.__event_id, a.__outcome_code
from auth.get_user_by_email_for_authentication(1, 'ex01', 'donna.hayward@twinpeaks.com') u
   , auth.create_user_login_attempt('examples', 1, 'ex01', 'email', 'donna.hayward@twinpeaks.com',
        u.__user_id, u.__password_hash = 'pw-hash-v2') a;

-- … disable the whole account → login is refused (33003) …
select * from auth.disable_user('examples', 1, 'ex01',
        (select user_id from auth.user_info where email = 'donna.hayward@twinpeaks.com'));
select a.__event_id, a.__outcome_code
from auth.get_user_by_email_for_authentication(1, 'ex01', 'donna.hayward@twinpeaks.com') u
   , auth.create_user_login_attempt('examples', 1, 'ex01', 'email', 'donna.hayward@twinpeaks.com',
        u.__user_id, u.__password_hash = 'pw-hash-v2') a;

-- … re-enable → back to a good state.
select * from auth.enable_user('examples', 1, 'ex01',
        (select user_id from auth.user_info where email = 'donna.hayward@twinpeaks.com'));
select a.__event_id, a.__outcome_code
from auth.get_user_by_email_for_authentication(1, 'ex01', 'donna.hayward@twinpeaks.com') u
   , auth.create_user_login_attempt('examples', 1, 'ex01', 'email', 'donna.hayward@twinpeaks.com',
        u.__user_id, u.__password_hash = 'pw-hash-v2') a;
