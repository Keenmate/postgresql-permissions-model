set search_path = public, const, ext, stage, helpers, internal, unsecure, auth, triggers;

-- ============================================================================
-- Test 6: Verify MFA challenge with recovery code, count decrements
-- ============================================================================
DO $$
DECLARE
    __test_user_id   bigint := current_setting('test.mfa_user_id')::bigint;
    __recovery_code  text := current_setting('test.mfa_recovery_code');
    __challenge      record;
    __status         record;
    __token_record   auth.token;
BEGIN
    RAISE NOTICE '';
    RAISE NOTICE '-- Test 6: Verify with recovery code --';

    -- Create a new MFA challenge
    SELECT * INTO __challenge
    FROM auth.create_mfa_challenge('test', 1, 'test-corr-mfa-06', __test_user_id, 'totp');

    RAISE NOTICE 'Challenge created: %', __challenge.__token_uid;

    -- Verify with recovery code (code_is_valid = false, recovery_code provided)
    PERFORM auth.create_mfa_challenge_attempt('test', 1, 'test-corr-mfa-06v', __test_user_id,
        __challenge.__token_uid, false, __recovery_code);

    -- Check token is used
    SELECT * INTO __token_record
    FROM auth.token t WHERE t.uid = __challenge.__token_uid;

    IF __token_record.token_state_code = 'used' THEN
        RAISE NOTICE 'PASS: Token marked as used after recovery code verification';
    ELSE
        RAISE EXCEPTION 'FAIL: Expected token state=used, got %', __token_record.token_state_code;
    END IF;

    -- Check recovery codes decremented
    SELECT * INTO __status
    FROM auth.get_mfa_status(1, 'test-corr-mfa-06s', __test_user_id);

    IF __status.__recovery_codes_remaining = 9 THEN
        RAISE NOTICE 'PASS: Recovery codes decremented to 9';
    ELSE
        RAISE EXCEPTION 'FAIL: Expected 9 recovery codes remaining, got %', __status.__recovery_codes_remaining;
    END IF;

    -- Verify mfa_recovery_used event was logged
    IF EXISTS(
        SELECT 1 FROM auth.user_event ue
        WHERE ue.target_user_id = __test_user_id
          AND ue.event_type_code = 'mfa_recovery_used'
    ) THEN
        RAISE NOTICE 'PASS: mfa_recovery_used event logged';
    ELSE
        RAISE EXCEPTION 'FAIL: mfa_recovery_used event not found';
    END IF;
END $$;
