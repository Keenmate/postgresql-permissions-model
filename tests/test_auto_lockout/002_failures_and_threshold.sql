set search_path = public, const, ext, stage, helpers, internal, unsecure, auth, triggers;

-- ============================================================================
-- Test 2: a single failure does not lock
-- ============================================================================
DO $$
DECLARE
    __auth_svc_id  bigint := current_setting('test.auth_svc_id')::bigint;
    __test_user_id bigint := current_setting('test.autolock_user_id')::bigint;
    __r            record;
BEGIN
    RAISE NOTICE '';
    RAISE NOTICE '-- Test 2: Single failure does not lock --';

    SELECT * INTO __r
    FROM auth.create_user_login_attempt('test', __auth_svc_id, 'test-corr-02', 'email', 'autolock@test.com', __test_user_id, false);

    IF __r.__event_id = 33001 AND __r.__failed_login_count = 1 AND __r.__locked_until IS NULL
        AND NOT (SELECT is_locked FROM auth.user_info WHERE user_id = __test_user_id) THEN
        RAISE NOTICE 'PASS: 1 failure counted, user not locked';
    ELSE
        RAISE EXCEPTION 'FAIL: after 1 failure: %', row_to_json(__r);
    END IF;
END $$;

-- ============================================================================
-- Test 3: reaching the threshold locks temporarily (not the admin lock) and
--         logs user_auto_locked
-- ============================================================================
DO $$
DECLARE
    __auth_svc_id  bigint := current_setting('test.auth_svc_id')::bigint;
    __test_user_id bigint := current_setting('test.autolock_user_id')::bigint;
    __r            record;
BEGIN
    RAISE NOTICE '';
    RAISE NOTICE '-- Test 3: Threshold triggers auto-lock --';

    FOR __i IN 2..5 LOOP
        SELECT * INTO __r
        FROM auth.create_user_login_attempt('test', __auth_svc_id, 'test-corr-03', 'email', 'autolock@test.com', __test_user_id, false);
    END LOOP;

    IF __r.__event_id <> 33004 OR __r.__locked_until IS DISTINCT FROM now() + interval '15 minutes' THEN
        RAISE EXCEPTION 'FAIL: 5th failure should lock for 15 minutes: %', row_to_json(__r);
    END IF;
    RAISE NOTICE 'PASS: 5th failure returned 33004, locked until now()+15m';

    IF (SELECT is_locked FROM auth.user_info WHERE user_id = __test_user_id) THEN
        RAISE EXCEPTION 'FAIL: auto-lock must not set the admin lock is_locked';
    END IF;
    RAISE NOTICE 'PASS: admin lock is_locked untouched';

    IF EXISTS(SELECT 1 FROM auth.user_event ue
              WHERE ue.target_user_id = __test_user_id
                AND ue.event_type_code = 'user_auto_locked'
                AND ue.correlation_id = 'test-corr-03') THEN
        RAISE NOTICE 'PASS: user_auto_locked event logged';
    ELSE
        RAISE EXCEPTION 'FAIL: user_auto_locked event not found';
    END IF;
END $$;

-- ============================================================================
-- Test 4: attempts while locked do not lock again or count
-- ============================================================================
DO $$
DECLARE
    __auth_svc_id  bigint := current_setting('test.auth_svc_id')::bigint;
    __test_user_id bigint := current_setting('test.autolock_user_id')::bigint;
    __r            record;
    __event_count  int;
BEGIN
    RAISE NOTICE '';
    RAISE NOTICE '-- Test 4: Already locked — no duplicate event --';

    FOR __i IN 1..3 LOOP
        SELECT * INTO __r
        FROM auth.create_user_login_attempt('test', __auth_svc_id, 'test-corr-04', 'email', 'autolock@test.com', __test_user_id, false);
    END LOOP;

    SELECT count(*) INTO __event_count
    FROM auth.user_event
    WHERE target_user_id = __test_user_id AND event_type_code = 'user_auto_locked';

    IF __r.__event_id = 33004 AND __event_count = 1
        AND (SELECT lockout_count FROM auth.user_login_state WHERE user_id = __test_user_id) = 1 THEN
        RAISE NOTICE 'PASS: No duplicate user_auto_locked event (count = %), lockout not escalated', __event_count;
    ELSE
        RAISE EXCEPTION 'FAIL: outcome %, user_auto_locked events %', __r.__event_id, __event_count;
    END IF;
END $$;

-- ============================================================================
-- Test 5: old failures outside the window are not counted
-- ============================================================================
DO $$
DECLARE
    __auth_svc_id  bigint := current_setting('test.auth_svc_id')::bigint;
    __test_user_id bigint := current_setting('test.autolock_user_id')::bigint;
    __r            record;
BEGIN
    RAISE NOTICE '';
    RAISE NOTICE '-- Test 5: Window expiry — old failures not counted --';

    UPDATE auth.user_login_state
    SET locked_until = null, failed_login_count = 4, last_failed_login_at = now() - interval '20 minutes'
    WHERE user_id = __test_user_id;

    SELECT * INTO __r
    FROM auth.create_user_login_attempt('test', __auth_svc_id, 'test-corr-05', 'email', 'autolock@test.com', __test_user_id, false);

    IF __r.__event_id = 33001 AND __r.__failed_login_count = 1 THEN
        RAISE NOTICE 'PASS: Old failures outside window not counted — user still unlocked';
    ELSE
        RAISE EXCEPTION 'FAIL: expected failure 1 without lock, got %', row_to_json(__r);
    END IF;

    UPDATE auth.user_login_state SET failed_login_count = 0, lockout_count = 0 WHERE user_id = __test_user_id;
END $$;
