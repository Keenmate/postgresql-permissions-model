set search_path = public, const, ext, stage, helpers, internal, unsecure, auth, triggers;

-- ============================================================================
-- SETUP: Create test users, groups, permissions, perm sets for permission checks
-- ============================================================================
DO $$
DECLARE
    __test_user_id bigint;
    __test_user2_id bigint;
    __test_user_delete_id bigint;
    __test_user_delete_bl_id bigint;
    __test_group_id int;
    __default_group_id int;
    __test_perm_id int;
    __test_perm2_id int;
    __test_perm_set_id int;
BEGIN
    RAISE NOTICE 'SETUP: Creating test data for permission checks...';

    -- Create test user with permissions (for has_permission tests)
    INSERT INTO auth.user_info (created_by, updated_by, user_type_code, username, original_username, display_name, email, is_active, can_login)
    VALUES ('pchk_test', 'pchk_test', 'normal', 'pchk_user1', 'pchk_user1', 'Perm Check User 1', 'pchk1@test.com', true, true)
    RETURNING user_id INTO __test_user_id;

    -- Create test user without permissions (for denied tests)
    INSERT INTO auth.user_info (created_by, updated_by, user_type_code, username, original_username, display_name, email, is_active, can_login)
    VALUES ('pchk_test', 'pchk_test', 'normal', 'pchk_user2', 'pchk_user2', 'Perm Check User 2', 'pchk2@test.com', true, true)
    RETURNING user_id INTO __test_user2_id;

    -- Create user to be deleted (no blacklist)
    INSERT INTO auth.user_info (created_by, updated_by, user_type_code, username, original_username, display_name, email, is_active, can_login)
    VALUES ('pchk_test', 'pchk_test', 'normal', 'pchk_del_user', 'pchk_del_user', 'Perm Check Delete User', 'pchk_del@test.com', true, true)
    RETURNING user_id INTO __test_user_delete_id;

    -- Create user to be deleted (with blacklist)
    INSERT INTO auth.user_info (created_by, updated_by, user_type_code, username, original_username, display_name, email, is_active, can_login)
    VALUES ('pchk_test', 'pchk_test', 'normal', 'pchk_del_bl_user', 'pchk_del_bl_user', 'Perm Check Delete BL User', 'pchk_del_bl@test.com', true, true)
    RETURNING user_id INTO __test_user_delete_bl_id;

    -- Create test permissions
    INSERT INTO auth.permission (created_by, updated_by, code, full_code, node_path, is_assignable)
    VALUES ('pchk_test', 'pchk_test', 'pchk_test_perm_a', 'pchk_test_perm_a'::ltree, '998'::ltree, true)
    ON CONFLICT DO NOTHING;
    SELECT permission_id INTO __test_perm_id FROM auth.permission WHERE code = 'pchk_test_perm_a';

    INSERT INTO auth.permission (created_by, updated_by, code, full_code, node_path, is_assignable)
    VALUES ('pchk_test', 'pchk_test', 'pchk_test_perm_b', 'pchk_test_perm_b'::ltree, '997'::ltree, true)
    ON CONFLICT DO NOTHING;
    SELECT permission_id INTO __test_perm2_id FROM auth.permission WHERE code = 'pchk_test_perm_b';

    -- Create test perm_set
    INSERT INTO auth.perm_set (created_by, updated_by, tenant_id, code, is_assignable)
    VALUES ('pchk_test', 'pchk_test', 1, 'pchk_test_perm_set', true)
    ON CONFLICT DO NOTHING;
    SELECT perm_set_id INTO __test_perm_set_id FROM auth.perm_set WHERE code = 'pchk_test_perm_set' AND tenant_id = 1;

    -- Add permissions to perm_set
    INSERT INTO auth.perm_set_perm (created_by, perm_set_id, permission_id)
    VALUES ('pchk_test', __test_perm_set_id, __test_perm_id)
    ON CONFLICT DO NOTHING;
    INSERT INTO auth.perm_set_perm (created_by, perm_set_id, permission_id)
    VALUES ('pchk_test', __test_perm_set_id, __test_perm2_id)
    ON CONFLICT DO NOTHING;

    -- Assign perm_set to user1 (so they have both permissions)
    INSERT INTO auth.permission_assignment (created_by, tenant_id, user_id, perm_set_id)
    VALUES ('pchk_test', 1, __test_user_id, __test_perm_set_id)
    ON CONFLICT DO NOTHING;

    -- Create a test group (non-default)
    INSERT INTO auth.user_group (created_by, updated_by, tenant_id, title, code, is_assignable, is_active, is_default)
    VALUES ('pchk_test', 'pchk_test', 1, 'Perm Check Group', 'pchk_test_group', true, true, false)
    ON CONFLICT DO NOTHING;
    SELECT user_group_id INTO __test_group_id FROM auth.user_group WHERE code = 'pchk_test_group';

    -- Create a default group (for assign_user_default_groups tests)
    INSERT INTO auth.user_group (created_by, updated_by, tenant_id, title, code, is_assignable, is_active, is_default)
    VALUES ('pchk_test', 'pchk_test', 1, 'Perm Check Default Group', 'pchk_default_group', true, true, true)
    ON CONFLICT DO NOTHING;
    SELECT user_group_id INTO __default_group_id FROM auth.user_group WHERE code = 'pchk_default_group';

    -- Store IDs in session config
    PERFORM set_config('pchk.user1_id', __test_user_id::text, false);
    PERFORM set_config('pchk.user2_id', __test_user2_id::text, false);
    PERFORM set_config('pchk.delete_user_id', __test_user_delete_id::text, false);
    PERFORM set_config('pchk.delete_bl_user_id', __test_user_delete_bl_id::text, false);
    PERFORM set_config('pchk.group_id', __test_group_id::text, false);
    PERFORM set_config('pchk.default_group_id', __default_group_id::text, false);
    PERFORM set_config('pchk.perm_id', __test_perm_id::text, false);
    PERFORM set_config('pchk.perm2_id', __test_perm2_id::text, false);
    PERFORM set_config('pchk.perm_set_id', __test_perm_set_id::text, false);

    RAISE NOTICE 'SETUP: user1=%, user2=%, del_user=%, del_bl_user=%, group=%, default_group=%, perm_a=%, perm_b=%, perm_set=%',
        __test_user_id, __test_user2_id, __test_user_delete_id, __test_user_delete_bl_id,
        __test_group_id, __default_group_id, __test_perm_id, __test_perm2_id, __test_perm_set_id;
    RAISE NOTICE '';
END $$;
