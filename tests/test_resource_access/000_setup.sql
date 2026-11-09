set search_path = public, const, ext, stage, helpers, internal, unsecure, auth, triggers;

DO $$
BEGIN
    RAISE NOTICE '';
    RAISE NOTICE '=================================================================';
    RAISE NOTICE 'Resource Access (ACL) Test Suite - Starting';
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
    RAISE NOTICE 'SETUP: Creating test users, groups, tenants, and resource types...';

    -- Create test users (system user_id=1 already exists)
    INSERT INTO auth.user_info (created_by, updated_by, display_name, code, username, original_username, email, can_login)
    VALUES ('test', 'test', 'RA Test User 1', 'ra_test_user_1', 'ra_test_user_1@test.com', 'ra_test_user_1@test.com', 'ra_test_user_1@test.com', true)
    RETURNING user_id INTO __user_id_1;

    INSERT INTO auth.user_info (created_by, updated_by, display_name, code, username, original_username, email, can_login)
    VALUES ('test', 'test', 'RA Test User 2', 'ra_test_user_2', 'ra_test_user_2@test.com', 'ra_test_user_2@test.com', 'ra_test_user_2@test.com', true)
    RETURNING user_id INTO __user_id_2;

    INSERT INTO auth.user_info (created_by, updated_by, display_name, code, username, original_username, email, can_login)
    VALUES ('test', 'test', 'RA Test User 3', 'ra_test_user_3', 'ra_test_user_3@test.com', 'ra_test_user_3@test.com', 'ra_test_user_3@test.com', true)
    RETURNING user_id INTO __user_id_3;

    -- Create test groups
    INSERT INTO auth.user_group (created_by, updated_by, tenant_id, title, code, is_active, is_assignable)
    VALUES ('test', 'test', 1, 'RA Test Group Editors', 'ra_test_group_editors', true, true)
    RETURNING user_group_id INTO __group_id_1;

    INSERT INTO auth.user_group (created_by, updated_by, tenant_id, title, code, is_active, is_assignable)
    VALUES ('test', 'test', 1, 'RA Test Group Viewers', 'ra_test_group_viewers', true, true)
    RETURNING user_group_id INTO __group_id_2;

    -- Add user 2 to editors group, user 3 to viewers group
    INSERT INTO auth.user_group_member (created_by, user_group_id, user_id, member_type_code)
    VALUES ('test', __group_id_1, __user_id_2, 'manual');

    INSERT INTO auth.user_group_member (created_by, user_group_id, user_id, member_type_code)
    VALUES ('test', __group_id_2, __user_id_3, 'manual');

    -- Create second tenant for isolation tests
    INSERT INTO auth.tenant (created_by, updated_by, title, code)
    VALUES ('test', 'test', 'RA Test Tenant 2', 'ra_test_tenant_2')
    RETURNING tenant_id INTO __tenant_id_2;

    -- Create resource types (with ltree path for hierarchy support)
    -- key_schema defines the expected jsonb structure for resource_id
    INSERT INTO const.resource_type (code, source, path, key_schema)
    VALUES ('document', 'test', 'document'::ext.ltree, '{"id": "bigint"}'::jsonb)
    ON CONFLICT DO NOTHING;

    INSERT INTO const.resource_type (code, source, path, key_schema)
    VALUES ('folder', 'test', 'folder'::ext.ltree, '{"id": "bigint"}'::jsonb)
    ON CONFLICT DO NOTHING;

    -- Register per-type access flags
    -- 'document' allows: read, write, delete, share, export
    INSERT INTO const.resource_type_flag (resource_type_code, access_flag_code) VALUES
        ('document', 'read'), ('document', 'write'), ('document', 'delete'),
        ('document', 'share'), ('document', 'export')
    ON CONFLICT DO NOTHING;

    -- 'folder' allows: read, write, delete, share
    INSERT INTO const.resource_type_flag (resource_type_code, access_flag_code) VALUES
        ('folder', 'read'), ('folder', 'write'), ('folder', 'delete'), ('folder', 'share')
    ON CONFLICT DO NOTHING;

    -- Create partitions for test resource types
    PERFORM unsecure.ensure_resource_access_partition('document');
    PERFORM unsecure.ensure_resource_access_partition('folder');

    -- Grant resource permissions to test user 1 (acting user for most tests)
    -- We need to give user 1 the resources permissions via the system admin perm set
    -- or directly assign individual permissions
    PERFORM unsecure.assign_permission_as_system(null::integer, __user_id_1, 'system_admin');

    -- Store test data IDs in temp table for later tests
    CREATE TEMP TABLE IF NOT EXISTS _ra_test_data (
        key text PRIMARY KEY,
        val bigint
    );
    DELETE FROM _ra_test_data;
    INSERT INTO _ra_test_data VALUES
        ('user_id_1', __user_id_1),
        ('user_id_2', __user_id_2),
        ('user_id_3', __user_id_3),
        ('group_id_1', __group_id_1),
        ('group_id_2', __group_id_2),
        ('tenant_id_2', __tenant_id_2);

    RAISE NOTICE 'SETUP: Created users (%, %, %), groups (%, %), tenant_2 (%)',
        __user_id_1, __user_id_2, __user_id_3, __group_id_1, __group_id_2, __tenant_id_2;
    RAISE NOTICE 'SETUP: Done';
    RAISE NOTICE '';
END $$;
