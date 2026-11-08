set search_path = public, const, ext, stage, helpers, internal, unsecure, auth, triggers;

-- ============================================================================
-- Test 5: Create MFA challenge and verify with TOTP code
-- ============================================================================
DO $$
DECLARE
    __test_user_id bigint := current_setting('test.mfa_user_id')::bigint;
    __challenge    record;
    __token_record auth.token;
BEGIN
    RAISE NOTICE '';
    RAISE NOTICE '-- Test 5: Create challenge + verify with TOTP --';

    -- Create MFA challenge
    SELECT * INTO __challenge
    FROM auth.create_mfa_challenge('test', 1, 'test-corr-mfa-05', __test_user_id, 'totp');

    IF __challenge.__token_uid IS NULL THEN
        RAISE EXCEPTION 'FAIL: create_mfa_challenge should return a token_uid';
    END IF;

    RAISE NOTICE 'PASS: MFA challenge created (token_uid=%, expires_at=%)', __challenge.__token_uid, __challenge.__expires_at;

    -- Verify the token exists in auth.token
    SELECT * INTO __token_record
    FROM auth.token t
    WHERE t.uid = __challenge.__token_uid;

    IF __token_record.token_type_code = 'mfa' AND __token_record.token_state_code = 'valid' THEN
        RAISE NOTICE 'PASS: Token exists with type=mfa, state=valid';
    ELSE
        RAISE EXCEPTION 'FAIL: Expected type=mfa, state=valid, got type=%, state=%', __token_record.token_type_code, __token_record.token_state_code;
    END IF;

    -- Store token_uid for verify test
    PERFORM set_config('test.mfa_token_uid', __challenge.__token_uid, false);

    -- Verify the challenge with valid TOTP code
    PERFORM auth.create_mfa_challenge_attempt('test', 1, 'test-corr-mfa-05v', __test_user_id, __challenge.__token_uid, true);

    -- Check token is now used
    SELECT * INTO __token_record
    FROM auth.token t
    WHERE t.uid = __challenge.__token_uid;

    IF __token_record.token_state_code = 'used' THEN
        RAISE NOTICE 'PASS: Token marked as used after verification';
    ELSE
        RAISE EXCEPTION 'FAIL: Expected token state=used, got %', __token_record.token_state_code;
    END IF;

    -- Verify mfa_challenge_passed event was logged
    IF EXISTS(
        SELECT 1 FROM auth.user_event ue
        WHERE ue.target_user_id = __test_user_id
          AND ue.event_type_code = 'mfa_challenge_passed'
    ) THEN
        RAISE NOTICE 'PASS: mfa_challenge_passed event logged';
    ELSE
        RAISE EXCEPTION 'FAIL: mfa_challenge_passed event not found';
    END IF;
END $$;
