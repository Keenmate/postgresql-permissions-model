set search_path = public, const, ext, stage, helpers, internal, unsecure, auth, triggers;

-- Since v2.6 login failures are outcomes of auth.create_user_login_attempt, not
-- exceptions, so the user_login_failed event now persists and is asserted here.

-- ============================================================================
-- TEST 9: unknown email -> no row from step 1, outcome 33001 from step 2
-- ============================================================================
DO $$
DECLARE
    __rows int;
    __r record;
BEGIN
    RAISE NOTICE 'TEST 9: Login outcome 33001 on user not found';

    SELECT count(*) INTO __rows
    FROM auth.get_user_by_email_for_authentication(1, 'fail-notfound', 'regtest_nonexistent@test.com');

    SELECT * INTO __r
    FROM auth.create_user_login_attempt('reg_test', 1, 'fail-notfound', 'email', 'regtest_nonexistent@test.com', null, null);

    IF __rows = 0 AND __r.__event_id = 33001
        AND EXISTS(SELECT FROM auth.user_event WHERE user_event_id = __r.__user_event_id
                   AND event_data->>'reason' = 'user_not_found') THEN
        RAISE NOTICE '  PASS: no step-1 row, outcome 33001, event persisted';
    ELSE
        RAISE EXCEPTION '  FAIL: rows %, outcome %', __rows, __r.__event_id;
    END IF;
END $$;

-- ============================================================================
-- TESTS 10-13: disabled / locked / identity disabled / login disabled
--   step 1 returns the state without a password hash, step 2 the outcome
-- ============================================================================
DO $$
DECLARE
    __user_id bigint := current_setting('test.reg_user1_id')::bigint;
    __case record;
    __step1 record;
    __r record;
BEGIN
    RAISE NOTICE 'TESTS 10-13: Login outcomes for disabled, locked, identity disabled, login disabled';

    FOR __case IN
        SELECT * FROM (VALUES
            (10, 'update auth.user_info set is_active = false where user_id = %s', 'update auth.user_info set is_active = true where user_id = %s', 33003, 'user_disabled'),
            (11, 'update auth.user_info set is_locked = true where user_id = %s', 'update auth.user_info set is_locked = false where user_id = %s', 33004, 'user_locked'),
            (12, 'update auth.user_identity set is_active = false where provider_code = ''email'' and user_id = %s', 'update auth.user_identity set is_active = true where provider_code = ''email'' and user_id = %s', 33008, 'identity_disabled'),
            (13, 'update auth.user_info set can_login = false where user_id = %s', 'update auth.user_info set can_login = true where user_id = %s', 33005, 'login_disabled')
        ) v(test_no, break_sql, fix_sql, expected_event_id, expected_reason)
    LOOP
        EXECUTE format(__case.break_sql, __user_id);

        SELECT * INTO __step1
        FROM auth.get_user_by_email_for_authentication(1, 'fail-' || __case.test_no, 'regtest_user1@test.com');

        SELECT * INTO __r
        FROM auth.create_user_login_attempt('reg_test', 1, 'fail-' || __case.test_no, 'email'
            , 'regtest_user1@test.com', __user_id, null);

        IF __step1.__password_hash IS NOT NULL THEN
            RAISE EXCEPTION '  FAIL: TEST %: step 1 returned a hash', __case.test_no;
        END IF;
        IF __r.__event_id IS DISTINCT FROM __case.expected_event_id
            OR NOT EXISTS(SELECT FROM auth.user_event WHERE user_event_id = __r.__user_event_id
                          AND event_data->>'reason' = __case.expected_reason) THEN
            RAISE EXCEPTION '  FAIL: TEST %: expected % (%), got %', __case.test_no, __case.expected_event_id, __case.expected_reason, row_to_json(__r);
        END IF;

        RAISE NOTICE '  PASS: TEST %: no hash, outcome %, % event persisted', __case.test_no, __r.__event_id, __case.expected_reason;

        EXECUTE format(__case.fix_sql, __user_id);
    END LOOP;
END $$;
