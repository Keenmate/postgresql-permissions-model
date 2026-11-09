set search_path = public, const, ext, stage, helpers, internal, unsecure, auth, triggers;

DO $$
BEGIN
    RAISE NOTICE '';
    RAISE NOTICE '=================================================================';
    RAISE NOTICE 'User Blacklist Tests - Starting';
    RAISE NOTICE '=================================================================';
    RAISE NOTICE '';
END $$;

-- ============================================================================
-- SETUP: Create test user, test provider, store IDs
-- ============================================================================
DO $$
DECLARE
    __test_user_id bigint;
BEGIN
    RAISE NOTICE 'SETUP: Creating test data...';

    -- Using system user (id=1) which bypasses all permission checks
    PERFORM set_config('test_bl.user_id', '1', false);
    PERFORM set_config('test_bl.correlation_id', 'test_blacklist', false);

    -- Create a test provider for OAuth blacklist tests
    INSERT INTO auth.provider (created_by, updated_by, code, is_active, allows_group_mapping)
    VALUES ('test_bl', 'test_bl', 'test_bl_aad', true, true)
    ON CONFLICT DO NOTHING;

    -- Create a test user to act as admin for permission-checked operations
    SELECT user_id INTO __test_user_id
    FROM unsecure.create_user_info('test_bl', 1, 'test_blacklist', 'bl_admin_user@test.com', 'bl_admin@test.com', 'Blacklist Admin', null);

    -- Assign manage_blacklist and search_blacklist permissions directly
    INSERT INTO auth.permission_assignment (created_by, tenant_id, user_id, permission_id)
    SELECT 'test_bl', 1, __test_user_id, p.permission_id
    FROM auth.permission p
    WHERE p.full_code IN ('users.manage_blacklist'::ltree, 'users.search_blacklist'::ltree)
    ON CONFLICT DO NOTHING;

    -- Clear permission cache so it rebuilds with new permissions
    PERFORM unsecure.clear_permission_cache('test_bl', __test_user_id, 1);

    PERFORM set_config('test_bl.admin_user_id', __test_user_id::text, false);

    RAISE NOTICE 'SETUP: admin_user_id=%, provider=test_bl_aad', __test_user_id;
    RAISE NOTICE '';
END $$;
