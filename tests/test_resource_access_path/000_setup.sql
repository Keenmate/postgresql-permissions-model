set search_path = public, const, ext, stage, helpers, internal, unsecure, auth, triggers;

DO $$
BEGIN
    RAISE NOTICE '';
    RAISE NOTICE '=================================================================';
    RAISE NOTICE 'Path-based Resource Access Test Suite - Starting';
    RAISE NOTICE '=================================================================';
    RAISE NOTICE '';
END $$;

-- ============================================================================
-- SETUP: Create users, groups, second tenant, and path-using resource type
-- ============================================================================
DO $$
DECLARE
    __user_id_1 bigint;
    __user_id_2 bigint;
    __user_id_3 bigint;
    __group_id_1 integer;
    __group_id_2 integer;
    __tenant_id_2 integer;
BEGIN
    RAISE NOTICE 'SETUP: Creating test users, groups, tenant, resource types...';

    INSERT INTO auth.user_info (created_by, updated_by, display_name, code, username, original_username, email, can_login)
    VALUES ('test', 'test', 'RAP Test User 1', 'rap_test_user_1', 'rap_test_user_1@test.com', 'rap_test_user_1@test.com', 'rap_test_user_1@test.com', true)
    RETURNING user_id INTO __user_id_1;

    INSERT INTO auth.user_info (created_by, updated_by, display_name, code, username, original_username, email, can_login)
    VALUES ('test', 'test', 'RAP Test User 2', 'rap_test_user_2', 'rap_test_user_2@test.com', 'rap_test_user_2@test.com', 'rap_test_user_2@test.com', true)
    RETURNING user_id INTO __user_id_2;

    INSERT INTO auth.user_info (created_by, updated_by, display_name, code, username, original_username, email, can_login)
    VALUES ('test', 'test', 'RAP Test User 3', 'rap_test_user_3', 'rap_test_user_3@test.com', 'rap_test_user_3@test.com', 'rap_test_user_3@test.com', true)
    RETURNING user_id INTO __user_id_3;

    INSERT INTO auth.user_group (created_by, updated_by, tenant_id, title, code, is_active, is_assignable)
    VALUES ('test', 'test', 1, 'RAP Test Group Editors', 'rap_test_group_editors', true, true)
    RETURNING user_group_id INTO __group_id_1;

    INSERT INTO auth.user_group (created_by, updated_by, tenant_id, title, code, is_active, is_assignable)
    VALUES ('test', 'test', 1, 'RAP Test Group Viewers', 'rap_test_group_viewers', true, true)
    RETURNING user_group_id INTO __group_id_2;

    INSERT INTO auth.user_group_member (created_by, user_group_id, user_id, member_type_code)
    VALUES ('test', __group_id_1, __user_id_2, 'manual');

    INSERT INTO auth.user_group_member (created_by, user_group_id, user_id, member_type_code)
    VALUES ('test', __group_id_2, __user_id_3, 'manual');

    INSERT INTO auth.tenant (created_by, updated_by, title, code)
    VALUES ('test', 'test', 'RAP Test Tenant 2', 'rap_test_tenant_2')
    RETURNING tenant_id INTO __tenant_id_2;

    -- 'fsitem' — path-first resource type (empty key_schema, paths are identity)
    INSERT INTO const.resource_type (code, source, path, key_schema)
    VALUES ('fsitem', 'test', 'fsitem'::ext.ltree, '{}'::jsonb)
    ON CONFLICT DO NOTHING;

    -- 'fsitem.file' — child type (still path-based)
    INSERT INTO const.resource_type (code, source, path, key_schema)
    VALUES ('fsitem.file', 'test', 'fsitem.file'::ext.ltree, '{}'::jsonb)
    ON CONFLICT DO NOTHING;

    -- 'proj' — composite-key resource type (coexistence test)
    INSERT INTO const.resource_type (code, source, path, key_schema)
    VALUES ('proj', 'test', 'proj'::ext.ltree, '{"project_id": "bigint"}'::jsonb)
    ON CONFLICT DO NOTHING;

    INSERT INTO const.resource_type_flag (resource_type_code, access_flag_code) VALUES
        ('fsitem', 'read'), ('fsitem', 'write'), ('fsitem', 'delete'), ('fsitem', 'share'),
        ('fsitem.file', 'read'), ('fsitem.file', 'write'), ('fsitem.file', 'delete'), ('fsitem.file', 'share'),
        ('proj', 'read'), ('proj', 'write')
    ON CONFLICT DO NOTHING;

    -- Register a role on fsitem for role-based path tests
    INSERT INTO const.resource_role (code, resource_type, source, is_active)
    VALUES ('fsitem_editor', 'fsitem', 'test', true)
    ON CONFLICT DO NOTHING;

    INSERT INTO const.resource_role_flag (resource_role_code, access_flag_code) VALUES
        ('fsitem_editor', 'read'), ('fsitem_editor', 'write')
    ON CONFLICT DO NOTHING;

    PERFORM unsecure.ensure_resource_access_partition('fsitem');
    PERFORM unsecure.ensure_resource_access_partition('proj');

    -- Acting user needs resources.* permissions
    PERFORM unsecure.assign_permission_as_system(null::integer, __user_id_1, 'system_admin');

    CREATE TEMP TABLE IF NOT EXISTS _rap_test_data (
        key text PRIMARY KEY,
        val bigint
    );
    DELETE FROM _rap_test_data;
    INSERT INTO _rap_test_data VALUES
        ('user_id_1',   __user_id_1),
        ('user_id_2',   __user_id_2),
        ('user_id_3',   __user_id_3),
        ('group_id_1',  __group_id_1),
        ('group_id_2',  __group_id_2),
        ('tenant_id_2', __tenant_id_2);

    RAISE NOTICE 'SETUP: users=(%, %, %), groups=(%, %), tenant_2=%',
        __user_id_1, __user_id_2, __user_id_3, __group_id_1, __group_id_2, __tenant_id_2;
    RAISE NOTICE 'SETUP: Done';
    RAISE NOTICE '';
END $$;
