set search_path = public, const, ext, stage, helpers, internal, unsecure, auth, triggers;

-- ============================================================================
-- TEST 7: a successful email login (step 1 read, step 2 create_user_login_attempt)
--         fires exactly one user_logged_in event, from step 2
-- ============================================================================
DO $$
DECLARE
    __result record;
    __attempt record;
    __event_count int;
    __corr_id text := 'login-test-' || gen_random_uuid()::text;
BEGIN
    RAISE NOTICE 'TEST 7: email login fires user_logged_in on success';

    SELECT * INTO __result
    FROM auth.get_user_by_email_for_authentication(1, __corr_id, 'regtest_user1@test.com');

    SELECT count(*) INTO __event_count
    FROM auth.user_event
    WHERE event_type_code = 'user_logged_in'
      AND correlation_id = __corr_id;
    IF __event_count <> 0 THEN
        RAISE EXCEPTION '  FAIL: step 1 must not log user_logged_in, found %', __event_count;
    END IF;

    SELECT * INTO __attempt
    FROM auth.create_user_login_attempt('reg_test', 1, __corr_id, 'email', 'regtest_user1@test.com', __result.__user_id, true);

    SELECT count(*) INTO __event_count
    FROM auth.user_event
    WHERE event_type_code = 'user_logged_in'
      AND target_user_id = __result.__user_id
      AND correlation_id = __corr_id;

    IF __attempt.__event_id = 10010 AND __event_count = 1 THEN
        RAISE NOTICE '  PASS: user_logged_in event created by create_user_login_attempt';
    ELSE
        RAISE EXCEPTION '  FAIL: outcome %, user_logged_in events %', __attempt.__event_id, __event_count;
    END IF;
END $$;

-- ============================================================================
-- TEST 8: Login passes request_context to success event
-- ============================================================================
DO $$
DECLARE
    __ctx jsonb;
    __corr_id text := 'login-meta-' || gen_random_uuid()::text;
BEGIN
    RAISE NOTICE 'TEST 8: login passes request_context to user_logged_in event';

    PERFORM auth.create_user_login_attempt('reg_test', 1, __corr_id, 'email', 'regtest_user1@test.com'
        , current_setting('test.reg_user1_id')::bigint, true,
        _request_context := '{"ip_address": "10.0.0.1", "user_agent": "LoginAgent/2.0", "origin": "https://app.test.com"}'::jsonb);

    SELECT ue.request_context
    INTO __ctx
    FROM auth.user_event ue
    WHERE event_type_code = 'user_logged_in'
      AND correlation_id = __corr_id;

    IF __ctx->>'ip_address' = '10.0.0.1' AND __ctx->>'user_agent' = 'LoginAgent/2.0' AND __ctx->>'origin' = 'https://app.test.com' THEN
        RAISE NOTICE '  PASS: request_context=%', __ctx;
    ELSE
        RAISE EXCEPTION '  FAIL: request_context=%', __ctx;
    END IF;
END $$;
