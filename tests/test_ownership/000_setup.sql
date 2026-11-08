set search_path = public, const, ext, stage, helpers, internal, unsecure, auth, triggers;

-- ============================================================================
-- SETUP: Create test data for ownership tests
-- ============================================================================
DO $$
DECLARE
    __admin_user_id bigint;
    __test_user_id bigint;
    __test_tenant_id integer;
    __test_group_id integer;
BEGIN
    RAISE NOTICE '';
    RAISE NOTICE '=================================================================';
    RAISE NOTICE 'Ownership Tests - Starting';
    RAISE NOTICE '=================================================================';
    RAISE NOTICE '';
    RAISE NOTICE 'SETUP: Creating test data...';

    -- Use system user (id=1) as admin — already has system_admin perm set
    SELECT user_id INTO __admin_user_id FROM auth.user_info WHERE user_id = 1;
    IF __admin_user_id IS NULL THEN
        RAISE EXCEPTION 'SETUP FAILED: System user (id=1) not found';
    END IF;

    -- Create test user to be assigned as owner
    INSERT INTO auth.user_info (created_by, updated_by, user_type_code, username, original_username, display_name, email)
    VALUES ('test_own', 'test_own', 'normal', 'own_test_user', 'own_test_user', 'Ownership Test User', 'own_test@test.com')
    ON CONFLICT (username) DO UPDATE SET display_name = 'Ownership Test User'
    RETURNING user_id INTO __test_user_id;

    -- Create test tenant
    INSERT INTO auth.tenant (created_by, updated_by, title, code, is_removable, is_assignable)
    VALUES ('test_own', 'test_own', 'Ownership Test Tenant', 'own_test_tenant', true, true)
    ON CONFLICT DO NOTHING;

    SELECT tenant_id INTO __test_tenant_id FROM auth.tenant WHERE code = 'own_test_tenant';

    -- Create test group
    INSERT INTO auth.user_group (created_by, updated_by, tenant_id, title, code, is_assignable, is_active, is_external, is_system)
    VALUES ('test_own', 'test_own', __test_tenant_id, 'Ownership Test Group', 'own_test_group', true, true, false, false)
    ON CONFLICT DO NOTHING;

    SELECT user_group_id INTO __test_group_id FROM auth.user_group WHERE code = 'own_test_group';

    -- Store IDs for subsequent tests
    PERFORM set_config('test_own.admin_user_id', __admin_user_id::text, false);
    PERFORM set_config('test_own.test_user_id', __test_user_id::text, false);
    PERFORM set_config('test_own.tenant_id', __test_tenant_id::text, false);
    PERFORM set_config('test_own.group_id', __test_group_id::text, false);

    RAISE NOTICE 'SETUP: admin_user_id=%, test_user_id=%, tenant_id=%, group_id=%',
        __admin_user_id, __test_user_id, __test_tenant_id, __test_group_id;
    RAISE NOTICE '';
END $$;
