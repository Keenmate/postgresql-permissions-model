set search_path = public, const, ext, stage, helpers, internal, unsecure, auth, triggers;

-- ============================================================================
-- Test 8: Invalid/expired token rejected, wrong type rejected
-- ============================================================================

-- 8a: Non-existent token -> outcome 30005 (since v2.6 an outcome, not an exception)
DO $$
DECLARE
    __test_user_id bigint := current_setting('test.mfa_user_id')::bigint;
    __r            record;
BEGIN
    RAISE NOTICE '';
    RAISE NOTICE '-- Test 8a: Non-existent token → 30005 --';

    SELECT * INTO __r
    FROM auth.create_mfa_challenge_attempt('test', 1, 'test-corr-mfa-08a', __test_user_id, 'NONEXISTENT_UID', true);

    IF __r.__event_id = 30005 AND __r.__outcome_code = 'err_token_not_found' THEN
        RAISE NOTICE 'PASS: Non-existent token rejected with outcome 30005';
    ELSE
        RAISE EXCEPTION 'FAIL: Expected outcome 30005, got %', row_to_json(__r);
    END IF;
END $$;

-- 8b: Invalid code + no recovery code → token marked failed (persisted), outcome 38004
DO $$
DECLARE
    __test_user_id bigint := current_setting('test.mfa_user_id')::bigint;
    __challenge    record;
    __result       record;
    __r            record;
    __token_record auth.token;
BEGIN
    RAISE NOTICE '';
    RAISE NOTICE '-- Test 8b: Invalid code with no recovery → 38004 --';

    -- Re-enroll MFA so we can create a challenge
    SELECT * INTO __result
    FROM auth.enroll_mfa('test', 1, 'test-corr-mfa-08b-e', __test_user_id, 'totp', 'secret_for_test_8');
    PERFORM auth.confirm_mfa_enrollment('test', 1, 'test-corr-mfa-08b-c', __test_user_id, 'totp', true);

    -- Create challenge
    SELECT * INTO __challenge
    FROM auth.create_mfa_challenge('test', 1, 'test-corr-mfa-08b', __test_user_id, 'totp');

    -- Verify with invalid code and no recovery
    SELECT * INTO __r
    FROM auth.create_mfa_challenge_attempt('test', 1, 'test-corr-mfa-08b-v', __test_user_id,
        __challenge.__token_uid, false, null);

    IF __r.__event_id <> 38004 THEN
        RAISE EXCEPTION 'FAIL: Expected outcome 38004, got %', row_to_json(__r);
    END IF;

    -- before v2.6 the raise rolled this state change back
    SELECT * INTO __token_record FROM auth.token t WHERE t.uid = __challenge.__token_uid;
    IF __token_record.token_state_code = 'failed' THEN
        RAISE NOTICE 'PASS: Invalid code without recovery: outcome 38004, token persisted as failed';
    ELSE
        RAISE EXCEPTION 'FAIL: Expected token state failed, got %', __token_record.token_state_code;
    END IF;
END $$;

-- 8c: MFA not enrolled raises 38002 on create_mfa_challenge
DO $$
DECLARE
    __fresh_user_id bigint;
    __error_code    text;
BEGIN
    RAISE NOTICE '';
    RAISE NOTICE '-- Test 8c: Challenge for non-enrolled user → 38002 --';

    -- Create a user without MFA
    INSERT INTO auth.user_info (created_by, updated_by, username, original_username, email, display_name, user_type_code, is_active, is_locked, can_login)
    VALUES ('test', 'test', 'test_mfa_no_enroll', 'test_mfa_no_enroll', 'mfa_noenroll@test.com', 'Test', 'normal', true, false, true)
    RETURNING user_id INTO __fresh_user_id;

    BEGIN
        PERFORM auth.create_mfa_challenge('test', 1, 'test-corr-mfa-08c', __fresh_user_id, 'totp');
        RAISE EXCEPTION 'FAIL: Should reject challenge for non-enrolled user';
    EXCEPTION WHEN OTHERS THEN
        GET STACKED DIAGNOSTICS __error_code = RETURNED_SQLSTATE;
        IF __error_code = '38002' THEN
            RAISE NOTICE 'PASS: Challenge for non-enrolled user rejected with error 38002';
        ELSE
            RAISE EXCEPTION 'FAIL: Expected error 38002, got % (%)', __error_code, SQLERRM;
        END IF;
    END;
END $$;

-- 8d: Invalid MFA type raises 38006
DO $$
DECLARE
    __test_user_id bigint := current_setting('test.mfa_user_id')::bigint;
    __error_code   text;
BEGIN
    RAISE NOTICE '';
    RAISE NOTICE '-- Test 8d: Invalid MFA type → 38006 --';

    BEGIN
        PERFORM auth.enroll_mfa('test', 1, 'test-corr-mfa-08d', __test_user_id, 'sms_otp', 'some_secret');
        RAISE EXCEPTION 'FAIL: Should reject invalid MFA type';
    EXCEPTION WHEN OTHERS THEN
        GET STACKED DIAGNOSTICS __error_code = RETURNED_SQLSTATE;
        IF __error_code = '38006' THEN
            RAISE NOTICE 'PASS: Invalid MFA type rejected with error 38006';
        ELSE
            RAISE EXCEPTION 'FAIL: Expected error 38006, got % (%)', __error_code, SQLERRM;
        END IF;
    END;
END $$;
