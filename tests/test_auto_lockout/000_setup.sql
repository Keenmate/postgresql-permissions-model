set search_path = public, const, ext, stage, helpers, internal, unsecure, auth, triggers;

-- ============================================================================
-- SETUP: Create test user with email identity for auto-lockout tests
-- ============================================================================
DO $$
DECLARE
    __test_user_id   bigint;
    __system_user_id bigint := 1;
BEGIN
    RAISE NOTICE '==========================================';
    RAISE NOTICE 'Test: Auto-Lockout';
    RAISE NOTICE '==========================================';
    RAISE NOTICE '';
    RAISE NOTICE '-- Setup --';

    -- Create test user
    INSERT INTO auth.user_info (created_by, updated_by, username, original_username, email, display_name, user_type_code, is_active, is_locked, can_login)
    VALUES ('test', 'test', 'test_autolock_user', 'test_autolock_user', 'autolock@test.com', 'Test AutoLock User', 'normal', true, false, true)
    RETURNING user_id INTO __test_user_id;

    -- Create email identity for the user
    INSERT INTO auth.user_identity (created_by, updated_by, provider_code, user_id, uid, provider_oid, is_active, password_hash, password_salt)
    VALUES ('test', 'test', 'email', __test_user_id, 'autolock@test.com', 'autolock@test.com', true, 'fakehash', 'fakesalt');

    -- Store IDs for subsequent test files
    PERFORM set_config('test.autolock_user_id', __test_user_id::text, false);
    PERFORM set_config('test.system_user_id', __system_user_id::text, false);
    -- login functions are called by the authenticator service, not user 1
    PERFORM set_config('test.auth_svc_id', (SELECT user_id FROM auth.user_info WHERE username = 'svc_authenticator')::text, false);

    RAISE NOTICE 'Created test user: % (id: %)', 'autolock@test.com', __test_user_id;

    -- Verify required permissions exist
    PERFORM 1 FROM auth.permission WHERE full_code::text = 'authentication';
    IF NOT FOUND THEN RAISE EXCEPTION 'FAIL: Missing permission: authentication'; END IF;
    PERFORM 1 FROM auth.permission WHERE full_code::text = 'authentication.get_data';
    IF NOT FOUND THEN RAISE EXCEPTION 'FAIL: Missing permission: authentication.get_data'; END IF;
    PERFORM 1 FROM auth.permission WHERE full_code::text = 'authentication.create_user_login_attempt';
    IF NOT FOUND THEN RAISE EXCEPTION 'FAIL: Missing permission: authentication.create_user_login_attempt'; END IF;
    RAISE NOTICE 'PASS: All required permissions exist';

    -- Verify required event codes exist
    PERFORM 1 FROM const.event_code WHERE code = 'user_login_failed';
    IF NOT FOUND THEN RAISE EXCEPTION 'FAIL: Missing event code: user_login_failed'; END IF;
    PERFORM 1 FROM const.event_code WHERE code = 'user_auto_locked';
    IF NOT FOUND THEN RAISE EXCEPTION 'FAIL: Missing event code: user_auto_locked'; END IF;
    PERFORM 1 FROM const.event_code WHERE code = 'mfa_challenge_failed';
    IF NOT FOUND THEN RAISE EXCEPTION 'FAIL: Missing event code: mfa_challenge_failed'; END IF;
    RAISE NOTICE 'PASS: All required event codes exist';
END $$;
