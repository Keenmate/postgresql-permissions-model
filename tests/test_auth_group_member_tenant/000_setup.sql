set search_path = public, const, ext, stage, helpers, internal, unsecure, auth, triggers;

-- ============================================================================
-- SETUP: Create test user and group using system user (id=1)
-- ============================================================================
DO $$
DECLARE
    __test_user_id bigint;
    __test_target_id bigint;
    __test_group_id int;
BEGIN
    RAISE NOTICE 'SETUP: Creating test data...';

    -- Create test user who will perform operations (needs permissions)
    -- Use system user (id=1) which has system_admin perm set
    SELECT user_id INTO __test_user_id FROM auth.user_info WHERE user_id = 1;
    IF __test_user_id IS NULL THEN
        RAISE EXCEPTION 'SETUP FAILED: System user (id=1) not found';
    END IF;

    -- Create target user to be added/removed from groups
    INSERT INTO auth.user_info (created_by, updated_by, user_type_code, username, original_username, display_name, email)
    VALUES ('test_agmt', 'test_agmt', 'normal', 'agmt_target_user', 'agmt_target_user', 'AGMT Target User', 'agmt_target@test.com')
    ON CONFLICT (username) DO UPDATE SET display_name = 'AGMT Target User'
    RETURNING user_id INTO __test_target_id;

    -- Create test group (non-system, assignable, active)
    INSERT INTO auth.user_group (created_by, updated_by, tenant_id, title, code, is_assignable, is_active, is_external, is_system)
    VALUES ('test_agmt', 'test_agmt', 1, 'AGMT Test Group', 'agmt_test_group', true, true, false, false)
    ON CONFLICT DO NOTHING;

    SELECT user_group_id INTO __test_group_id FROM auth.user_group WHERE code = 'agmt_test_group';

    -- The group must grant something, or its members are not tenant members (v2.19)
    PERFORM unsecure.assign_permission('test_agmt', 1, null, __test_group_id, null, 'tenant_member', _tenant_id := 1);

    -- Store IDs for subsequent tests
    PERFORM set_config('test_agmt.user_id', __test_user_id::text, false);
    PERFORM set_config('test_agmt.target_id', __test_target_id::text, false);
    PERFORM set_config('test_agmt.group_id', __test_group_id::text, false);

    RAISE NOTICE 'SETUP: user_id=%, target_id=%, group_id=%', __test_user_id, __test_target_id, __test_group_id;
    RAISE NOTICE '';
END $$;
