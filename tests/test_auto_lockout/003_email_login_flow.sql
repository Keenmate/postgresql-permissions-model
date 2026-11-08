set search_path = public, const, ext, stage, helpers, internal, unsecure, auth, triggers;

-- The two-step email login: step 1 get_user_by_email_for_authentication (read
-- only, returns the hash), the app compares the hash, step 2
-- create_user_login_attempt records the result. The stored hash is 'fakehash'.

-- ============================================================================
-- Test 6: correct password -> user_logged_in, no failure event
-- ============================================================================
DO $$
DECLARE
    __auth_svc_id  bigint := current_setting('test.auth_svc_id')::bigint;
    __test_user_id bigint := current_setting('test.autolock_user_id')::bigint;
    __step1        record;
    __r            record;
BEGIN
    RAISE NOTICE '';
    RAISE NOTICE '-- Test 6: two-step login — correct password --';

    SELECT * INTO __step1
    FROM auth.get_user_by_email_for_authentication(__auth_svc_id, 'test-corr-06', 'autolock@test.com');

    SELECT * INTO __r
    FROM auth.create_user_login_attempt('test', __auth_svc_id, 'test-corr-06', 'email', 'autolock@test.com'
        , __step1.__user_id, __step1.__password_hash = 'fakehash');

    IF __step1.__user_id = __test_user_id AND __r.__event_id = 10010 THEN
        RAISE NOTICE 'PASS: step 1 returned the user and hash, step 2 returned 10010';
    ELSE
        RAISE EXCEPTION 'FAIL: step1 user %, step 2 %', __step1.__user_id, row_to_json(__r);
    END IF;

    IF EXISTS(SELECT 1 FROM auth.user_event WHERE correlation_id = 'test-corr-06' AND event_type_code = 'user_logged_in')
        AND NOT EXISTS(SELECT 1 FROM auth.user_event WHERE correlation_id = 'test-corr-06' AND event_type_code = 'user_login_failed') THEN
        RAISE NOTICE 'PASS: user_logged_in logged, no login failure event';
    ELSE
        RAISE EXCEPTION 'FAIL: wrong events for a successful login';
    END IF;
END $$;

-- ============================================================================
-- Test 7: wrong password -> 33001 and the failure event persists
--         (before v2.6 verify_user_by_email raised and rolled the event back)
-- ============================================================================
DO $$
DECLARE
    __auth_svc_id  bigint := current_setting('test.auth_svc_id')::bigint;
    __step1        record;
    __r            record;
BEGIN
    RAISE NOTICE '';
    RAISE NOTICE '-- Test 7: two-step login — wrong password --';

    SELECT * INTO __step1
    FROM auth.get_user_by_email_for_authentication(__auth_svc_id, 'test-corr-07', 'autolock@test.com');

    SELECT * INTO __r
    FROM auth.create_user_login_attempt('test', __auth_svc_id, 'test-corr-07', 'email', 'autolock@test.com'
        , __step1.__user_id, __step1.__password_hash = 'wrong_hash');

    IF __r.__event_id = 33001
        AND EXISTS(SELECT 1 FROM auth.user_event WHERE user_event_id = __r.__user_event_id
                   AND event_type_code = 'user_login_failed' AND event_data->>'reason' = 'wrong_password') THEN
        RAISE NOTICE 'PASS: wrong password returned 33001, user_login_failed persisted';
    ELSE
        RAISE EXCEPTION 'FAIL: wrong password: %', row_to_json(__r);
    END IF;
END $$;

-- ============================================================================
-- Test 8: repeated wrong passwords lock; step 1 then returns no hash
-- ============================================================================
DO $$
DECLARE
    __auth_svc_id  bigint := current_setting('test.auth_svc_id')::bigint;
    __step1        record;
    __r            record;
BEGIN
    RAISE NOTICE '';
    RAISE NOTICE '-- Test 8: two-step login — lockout --';

    -- Test 7 already counted one failure
    FOR __i IN 2..5 LOOP
        SELECT * INTO __step1
        FROM auth.get_user_by_email_for_authentication(__auth_svc_id, 'test-corr-08', 'autolock@test.com');
        SELECT * INTO __r
        FROM auth.create_user_login_attempt('test', __auth_svc_id, 'test-corr-08', 'email', 'autolock@test.com'
            , __step1.__user_id, __step1.__password_hash = 'wrong_hash');
    END LOOP;

    IF __r.__event_id <> 33004 THEN
        RAISE EXCEPTION 'FAIL: 5th wrong password should lock: %', row_to_json(__r);
    END IF;

    SELECT * INTO __step1
    FROM auth.get_user_by_email_for_authentication(__auth_svc_id, 'test-corr-08', 'autolock@test.com');
    IF __step1.__password_hash IS NULL AND __step1.__locked_until IS NOT NULL THEN
        RAISE NOTICE 'PASS: locked after 5 wrong passwords; step 1 returns no hash while locked';
    ELSE
        RAISE EXCEPTION 'FAIL: step 1 while locked: hash %, locked_until %', __step1.__password_hash, __step1.__locked_until;
    END IF;

    UPDATE auth.user_login_state SET locked_until = null, failed_login_count = 0, lockout_count = 0
    WHERE user_id = current_setting('test.autolock_user_id')::bigint;
END $$;

-- ============================================================================
-- Test 9: status outcomes - unknown email, disabled, admin-locked, can_login,
--         identity disabled
-- ============================================================================
DO $$
DECLARE
    __auth_svc_id  bigint := current_setting('test.auth_svc_id')::bigint;
    __test_user_id bigint := current_setting('test.autolock_user_id')::bigint;
    __case         record;
    __r            record;
BEGIN
    RAISE NOTICE '';
    RAISE NOTICE '-- Test 9: status outcomes --';

    SELECT * INTO __r
    FROM auth.create_user_login_attempt('test', __auth_svc_id, 'test-corr-09a', 'email', 'nonexistent@test.com', null, null);
    IF __r.__event_id <> 33001 THEN
        RAISE EXCEPTION 'FAIL: 9a non-existent email: %', row_to_json(__r);
    END IF;
    RAISE NOTICE 'PASS: 9a Non-existent email returned 33001';

    FOR __case IN
        SELECT * FROM (VALUES
            ('9b', 'update auth.user_info set is_active = false where user_id = %s', 'update auth.user_info set is_active = true where user_id = %s', 33003),
            ('9c', 'update auth.user_info set is_locked = true where user_id = %s', 'update auth.user_info set is_locked = false where user_id = %s', 33004),
            ('9d', 'update auth.user_info set can_login = false where user_id = %s', 'update auth.user_info set can_login = true where user_id = %s', 33005),
            ('9e', 'update auth.user_identity set is_active = false where provider_code = ''email'' and user_id = %s', 'update auth.user_identity set is_active = true where provider_code = ''email'' and user_id = %s', 33008)
        ) v(test_no, break_sql, fix_sql, expected_event_id)
    LOOP
        EXECUTE format(__case.break_sql, __test_user_id);

        SELECT * INTO __r
        FROM auth.create_user_login_attempt('test', __auth_svc_id, 'test-corr-' || __case.test_no, 'email', 'autolock@test.com'
            , __test_user_id, true);
        IF __r.__event_id IS DISTINCT FROM __case.expected_event_id THEN
            RAISE EXCEPTION 'FAIL: % expected %, got %', __case.test_no, __case.expected_event_id, row_to_json(__r);
        END IF;
        RAISE NOTICE 'PASS: % returned %', __case.test_no, __r.__event_id;

        EXECUTE format(__case.fix_sql, __test_user_id);
    END LOOP;
END $$;
