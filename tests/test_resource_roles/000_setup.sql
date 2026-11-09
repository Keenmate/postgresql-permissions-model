set search_path = public, const, ext, stage, helpers, internal, unsecure, auth, triggers;

DO $$
BEGIN
    RAISE NOTICE '';
    RAISE NOTICE '=================================================================';
    RAISE NOTICE 'Resource Roles Test Suite - Starting';
    RAISE NOTICE '=================================================================';
    RAISE NOTICE '';
END $$;

-- ============================================================================
-- SETUP: Create test data
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
    RAISE NOTICE 'SETUP: Creating test users, groups, tenants, resource types, and roles...';

    -- Create test users
    INSERT INTO auth.user_info (created_by, updated_by, display_name, code, username, original_username, email, can_login)
    VALUES ('test', 'test', 'RR Test User 1', 'rr_test_user_1', 'rr_test_user_1@test.com', 'rr_test_user_1@test.com', 'rr_test_user_1@test.com', true)
    RETURNING user_id INTO __user_id_1;

    INSERT INTO auth.user_info (created_by, updated_by, display_name, code, username, original_username, email, can_login)
    VALUES ('test', 'test', 'RR Test User 2', 'rr_test_user_2', 'rr_test_user_2@test.com', 'rr_test_user_2@test.com', 'rr_test_user_2@test.com', true)
    RETURNING user_id INTO __user_id_2;

    INSERT INTO auth.user_info (created_by, updated_by, display_name, code, username, original_username, email, can_login)
    VALUES ('test', 'test', 'RR Test User 3', 'rr_test_user_3', 'rr_test_user_3@test.com', 'rr_test_user_3@test.com', 'rr_test_user_3@test.com', true)
    RETURNING user_id INTO __user_id_3;

    -- Create test groups (simulating Entra groups)
    INSERT INTO auth.user_group (created_by, updated_by, tenant_id, title, code, is_active, is_assignable)
    VALUES ('test', 'test', 1, 'RR Test Entra Editors', 'rr_test_entra_editors', true, true)
    RETURNING user_group_id INTO __group_id_1;

    INSERT INTO auth.user_group (created_by, updated_by, tenant_id, title, code, is_active, is_assignable)
    VALUES ('test', 'test', 1, 'RR Test Entra Viewers', 'rr_test_entra_viewers', true, true)
    RETURNING user_group_id INTO __group_id_2;

    -- Add user 2 to editors, user 3 to viewers
    INSERT INTO auth.user_group_member (created_by, user_group_id, user_id, member_type_code)
    VALUES ('test', __group_id_1, __user_id_2, 'manual');

    INSERT INTO auth.user_group_member (created_by, user_group_id, user_id, member_type_code)
    VALUES ('test', __group_id_2, __user_id_3, 'manual');

    -- Second tenant for isolation tests
    INSERT INTO auth.tenant (created_by, updated_by, title, code)
    VALUES ('test', 'test', 'RR Test Tenant 2', 'rr_test_tenant_2')
    RETURNING tenant_id INTO __tenant_id_2;

    -- Resource types (reuse existing if present, or create)
    INSERT INTO const.resource_type (code, source, path, key_schema)
    VALUES ('asset', 'test_roles', 'asset'::ext.ltree, '{"id": "bigint"}'::jsonb)
    ON CONFLICT DO NOTHING;

    INSERT INTO const.resource_type (code, source, path, key_schema)
    VALUES ('asset.file', 'test_roles', 'asset.file'::ext.ltree, '{"id": "bigint", "file_id": "bigint"}'::jsonb)
    ON CONFLICT DO NOTHING;

    -- Per-type flags for 'asset'
    INSERT INTO const.resource_type_flag (resource_type_code, access_flag_code) VALUES
        ('asset', 'read'), ('asset', 'write'), ('asset', 'delete'), ('asset', 'export'), ('asset', 'share')
    ON CONFLICT DO NOTHING;

    -- Per-type flags for 'asset.file'
    INSERT INTO const.resource_type_flag (resource_type_code, access_flag_code) VALUES
        ('asset.file', 'read'), ('asset.file', 'write'), ('asset.file', 'delete'), ('asset.file', 'export')
    ON CONFLICT DO NOTHING;

    -- Create partitions
    PERFORM unsecure.ensure_resource_access_partition('asset');

    -- Grant system admin to user 1 (acting user)
    PERFORM unsecure.assign_permission_as_system(null::integer, __user_id_1, 'system_admin');

    -- Create resource roles
    INSERT INTO const.resource_role (code, resource_type, source)
    VALUES ('asset_reader', 'asset', 'test_roles');

    INSERT INTO const.resource_role_flag (resource_role_code, access_flag_code) VALUES
        ('asset_reader', 'read');

    INSERT INTO const.resource_role (code, resource_type, source)
    VALUES ('asset_editor', 'asset', 'test_roles');

    INSERT INTO const.resource_role_flag (resource_role_code, access_flag_code) VALUES
        ('asset_editor', 'read'),
        ('asset_editor', 'write'),
        ('asset_editor', 'delete'),
        ('asset_editor', 'export');

    INSERT INTO const.resource_role (code, resource_type, source)
    VALUES ('asset_file_viewer', 'asset.file', 'test_roles');

    INSERT INTO const.resource_role_flag (resource_role_code, access_flag_code) VALUES
        ('asset_file_viewer', 'read');

    -- Store test data IDs
    CREATE TEMP TABLE IF NOT EXISTS _rr_test_data (
        key text PRIMARY KEY,
        val bigint
    );
    DELETE FROM _rr_test_data;
    INSERT INTO _rr_test_data VALUES
        ('user_id_1', __user_id_1),
        ('user_id_2', __user_id_2),
        ('user_id_3', __user_id_3),
        ('group_id_1', __group_id_1),
        ('group_id_2', __group_id_2),
        ('tenant_id_2', __tenant_id_2);

    RAISE NOTICE 'SETUP: Created users (%, %, %), groups (%, %), tenant_2 (%)',
        __user_id_1, __user_id_2, __user_id_3, __group_id_1, __group_id_2, __tenant_id_2;
    RAISE NOTICE 'SETUP: Created roles: asset_reader, asset_editor, asset_file_viewer';
    RAISE NOTICE 'SETUP: Done';
    RAISE NOTICE '';
END $$;
