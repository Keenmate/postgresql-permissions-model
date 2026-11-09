set search_path = public, const, ext, stage, helpers, internal, unsecure, auth, triggers;

-- ============================================================================
-- SETUP: Clean leftover test data, create test provider and users
-- ============================================================================
DO $$
BEGIN
    RAISE NOTICE '';
    RAISE NOTICE '=================================================================';
    RAISE NOTICE 'Identity and Provider Reads Tests - Starting';
    RAISE NOTICE '=================================================================';
    RAISE NOTICE '';
END $$;

DO $$
BEGIN
    RAISE NOTICE 'SETUP: Cleaning leftover test data...';

    DELETE FROM auth.user_event WHERE created_by = 'idp_test';
    DELETE FROM public.journal WHERE created_by = 'idp_test';
    DELETE FROM auth.user_identity WHERE uid LIKE 'idp_test_%';
    DELETE FROM auth.user_data WHERE user_id IN (SELECT user_id FROM auth.user_info WHERE username LIKE 'idp_test_%');
    DELETE FROM auth.user_info WHERE username LIKE 'idp_test_%';
    DELETE FROM auth.provider WHERE code = 'test_idp';

    RAISE NOTICE 'SETUP: Done cleaning';
END $$;

-- ============================================================================
-- SETUP: Create test provider
-- ============================================================================
DO $$
BEGIN
    RAISE NOTICE 'SETUP: Creating test provider...';

    INSERT INTO auth.provider (created_by, updated_by, code, is_active, allows_group_mapping)
    VALUES ('idp_test', 'idp_test', 'test_idp', true, true)
    ON CONFLICT DO NOTHING;

    RAISE NOTICE 'SETUP: test_idp provider created';
END $$;

-- ============================================================================
-- SETUP: Create test user via ensure_user_from_provider
-- ============================================================================
DO $$
DECLARE
    __result record;
    __corr_id text := 'idp-setup-' || gen_random_uuid()::text;
BEGIN
    RAISE NOTICE 'SETUP: Creating test user via ensure_user_from_provider...';

    SELECT * INTO __result
    FROM auth.ensure_user_from_provider(
        'idp_test', 1, __corr_id, 'test_idp',
        'idp_test_uid_1', 'idp_test_oid_1',
        'idp_test_user1', 'IDP Test User 1', 'idp_test_user1@test.com'
    );

    IF __result.__user_id IS NULL THEN
        RAISE EXCEPTION 'SETUP FAIL: ensure_user_from_provider returned NULL user_id';
    END IF;

    PERFORM set_config('test.idp_user_id', __result.__user_id::text, false);

    RAISE NOTICE 'SETUP: Test user created (id=%)', __result.__user_id;
    RAISE NOTICE '';
END $$;
