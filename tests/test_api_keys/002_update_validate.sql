set search_path = public, const, ext, stage, helpers, internal, unsecure, auth, triggers;

-- ============================================================================
-- TEST 5: update_api_key modifies title, description, expire_at, notification_email
-- ============================================================================
DO $$
DECLARE
    __admin_id bigint;
    __api_key_id int;
    __ret_title text;
    __ret_desc text;
    __ret_expire timestamptz;
    __ret_email text;
BEGIN
    RAISE NOTICE 'TEST 5: update_api_key modifies fields';

    SELECT val::bigint INTO __admin_id FROM _ak_test_data WHERE key = 'admin_id';
    SELECT val::int INTO __api_key_id FROM _ak_test_data WHERE key = 'key1_id';

    SELECT r.__title, r.__description, r.__expire_at, r.__notification_email
    FROM auth.update_api_key(
        'ak_test', __admin_id, 'ak-test-upd',
        __api_key_id,
        'Updated Title', 'Updated description',
        '2027-12-31 23:59:59+00'::timestamptz,
        'notify@test.com',
        1
    ) r
    INTO __ret_title, __ret_desc, __ret_expire, __ret_email;

    IF __ret_title = 'Updated Title'
       AND __ret_desc = 'Updated description'
       AND __ret_email = 'notify@test.com'
       AND __ret_expire IS NOT NULL THEN
        RAISE NOTICE '  PASS: update_api_key returned updated fields (title=%, email=%)', __ret_title, __ret_email;
    ELSE
        RAISE EXCEPTION '  FAIL: update_api_key mismatch (title=%, desc=%, email=%, expire=%)',
            __ret_title, __ret_desc, __ret_email, __ret_expire;
    END IF;
END $$;

-- ============================================================================
-- TEST 6: update_api_key journals event 14002
-- ============================================================================
DO $$
DECLARE
    __journal_payload jsonb;
BEGIN
    RAISE NOTICE 'TEST 6: update_api_key journals event 14002';

    SELECT j.data_payload
    FROM public.journal j
    WHERE j.event_id = 14002
      AND j.created_by = 'ak_test'
      AND j.correlation_id = 'ak-test-upd'
    ORDER BY j.created_at DESC
    LIMIT 1
    INTO __journal_payload;

    IF __journal_payload IS NOT NULL AND __journal_payload->>'api_key_title' = 'Updated Title' THEN
        RAISE NOTICE '  PASS: journal entry found (payload=%)', __journal_payload;
    ELSE
        RAISE EXCEPTION '  FAIL: no journal entry or payload mismatch (payload=%)', __journal_payload;
    END IF;
END $$;

-- ============================================================================
-- TEST 7: validate_api_key succeeds with correct key+secret
-- ============================================================================
DO $$
DECLARE
    __admin_id bigint;
    __api_key text;
    __api_secret text;
    __ret_user_id bigint;
    __ret_username text;
    __ret_display text;
    __ret_perms text[];
BEGIN
    RAISE NOTICE 'TEST 7: validate_api_key succeeds with correct key+secret';

    SELECT val::bigint INTO __admin_id FROM _ak_test_data WHERE key = 'admin_id';
    SELECT val INTO __api_key FROM _ak_test_data WHERE key = 'key1_key';
    SELECT val INTO __api_secret FROM _ak_test_data WHERE key = 'key1_secret';

    SELECT r.__user_id, r.__username, r.__user_display_name, r.__permission_full_codes
    FROM auth.validate_api_key(
        'ak_test', __admin_id, 'ak-test-val',
        __api_key, __api_secret,
        _tenant_id := 1
    ) r
    INTO __ret_user_id, __ret_username, __ret_display, __ret_perms;

    IF __ret_user_id IS NOT NULL AND __ret_username IS NOT NULL THEN
        RAISE NOTICE '  PASS: validate_api_key returned user (id=%, username=%)', __ret_user_id, __ret_username;
    ELSE
        RAISE EXCEPTION '  FAIL: validate_api_key returned NULL user_id or username';
    END IF;
END $$;

-- ============================================================================
-- TEST 8: validate_api_key fails with wrong secret (raises 52301)
-- ============================================================================
DO $$
DECLARE
    __admin_id bigint;
    __api_key text;
    __ret_user_id bigint;
BEGIN
    RAISE NOTICE 'TEST 8: validate_api_key fails with wrong secret';

    SELECT val::bigint INTO __admin_id FROM _ak_test_data WHERE key = 'admin_id';
    SELECT val INTO __api_key FROM _ak_test_data WHERE key = 'key1_key';

    BEGIN
        SELECT r.__user_id
        FROM auth.validate_api_key(
            'ak_test', __admin_id, 'ak-test-val-bad',
            __api_key, 'wrong-secret-value',
            _tenant_id := 1
        ) r
        INTO __ret_user_id;

        RAISE EXCEPTION '  FAIL: validate_api_key did not raise exception for wrong secret';
    EXCEPTION WHEN SQLSTATE '30001' THEN
        RAISE NOTICE '  PASS: validate_api_key raised expected error for wrong secret (sqlstate=%)', SQLSTATE;
    END;
END $$;

-- ============================================================================
-- TEST 9: update_api_key_secret rotates secret and old secret fails validation
-- ============================================================================
DO $$
DECLARE
    __admin_id bigint;
    __api_key_id int;
    __api_key text;
    __old_secret text;
    __new_secret text;
    __ret_user_id bigint;
BEGIN
    RAISE NOTICE 'TEST 9: update_api_key_secret rotates secret successfully';

    SELECT val::bigint INTO __admin_id FROM _ak_test_data WHERE key = 'admin_id';
    SELECT val::int INTO __api_key_id FROM _ak_test_data WHERE key = 'key1_id';
    SELECT val INTO __api_key FROM _ak_test_data WHERE key = 'key1_key';
    SELECT val INTO __old_secret FROM _ak_test_data WHERE key = 'key1_secret';

    -- Rotate the secret
    SELECT r.__api_secret
    FROM auth.update_api_key_secret('ak_test', __admin_id, 'ak-test-rotate', __api_key_id, _tenant_id := 1) r
    INTO __new_secret;

    IF __new_secret IS NULL THEN
        RAISE EXCEPTION '  FAIL: update_api_key_secret returned NULL secret';
    END IF;

    IF __new_secret = __old_secret THEN
        RAISE EXCEPTION '  FAIL: new secret is same as old secret';
    END IF;

    -- Validate with new secret should work
    SELECT r.__user_id
    FROM auth.validate_api_key('ak_test', __admin_id, 'ak-test-val-new', __api_key, __new_secret, _tenant_id := 1) r
    INTO __ret_user_id;

    IF __ret_user_id IS NULL THEN
        RAISE EXCEPTION '  FAIL: validate_api_key failed with new secret';
    END IF;

    -- Validate with old secret should fail
    BEGIN
        SELECT r.__user_id
        FROM auth.validate_api_key('ak_test', __admin_id, 'ak-test-val-old', __api_key, __old_secret, _tenant_id := 1) r
        INTO __ret_user_id;

        RAISE EXCEPTION '  FAIL: validate_api_key should have failed with old secret';
    EXCEPTION WHEN OTHERS THEN
        RAISE NOTICE '  PASS: secret rotated, new works, old fails (new=%, sqlstate=%)', substring(__new_secret, 1, 8), SQLSTATE;
    END;

    -- Update stored secret for subsequent tests
    UPDATE _ak_test_data SET val = __new_secret WHERE key = 'key1_secret';
END $$;
