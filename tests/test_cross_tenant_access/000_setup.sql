set search_path = public, const, ext, stage, helpers, internal, unsecure, auth, triggers;

DO $$
BEGIN
    RAISE NOTICE '';
    RAISE NOTICE '=================================================================';
    RAISE NOTICE 'Cross-Tenant Data Access Tests - Starting';
    RAISE NOTICE '=================================================================';
    RAISE NOTICE '';
END $$;

-- ============================================================================
-- SETUP: Create 3 tenants, 3 users, assign permissions
-- ============================================================================
DO $$
DECLARE
    __tenant2_id integer;
    __tenant3_id integer;
    __admin_user_id bigint;
    __user2_id bigint;
    __user3_id bigint;
    __group_t1_id integer;
    __group_t2_id integer;
    __group_t3_id integer;
BEGIN
    RAISE NOTICE 'SETUP: Creating tenants, users, groups, and permission assignments...';

    -- -----------------------------------------------------------------------
    -- Tenants: tenant 1 already exists (admin tenant), create tenants 2 and 3
    -- -----------------------------------------------------------------------
    INSERT INTO auth.tenant (created_by, updated_by, title, code, is_removable, is_assignable)
    VALUES ('test_ct', 'test_ct', 'Cross-Tenant Test Tenant 2', 'ct_tenant_2', true, true)
    RETURNING tenant_id INTO __tenant2_id;

    INSERT INTO auth.tenant (created_by, updated_by, title, code, is_removable, is_assignable)
    VALUES ('test_ct', 'test_ct', 'Cross-Tenant Test Tenant 3', 'ct_tenant_3', true, true)
    RETURNING tenant_id INTO __tenant3_id;

    PERFORM set_config('test_ct.tenant2_id', __tenant2_id::text, false);
    PERFORM set_config('test_ct.tenant3_id', __tenant3_id::text, false);

    -- -----------------------------------------------------------------------
    -- Users: admin user in tenant 1, regular users in tenants 2 and 3
    -- -----------------------------------------------------------------------
    INSERT INTO auth.user_info (created_by, updated_by, user_type_code, username, original_username, display_name, email, is_active, can_login)
    VALUES ('test_ct', 'test_ct', 'normal', 'ct_admin_user', 'ct_admin_user', 'CT Admin User', 'ct_admin@test.com', true, true)
    RETURNING user_id INTO __admin_user_id;

    INSERT INTO auth.user_info (created_by, updated_by, user_type_code, username, original_username, display_name, email, is_active, can_login)
    VALUES ('test_ct', 'test_ct', 'normal', 'ct_regular_user2', 'ct_regular_user2', 'CT Regular User 2', 'ct_user2@test.com', true, true)
    RETURNING user_id INTO __user2_id;

    INSERT INTO auth.user_info (created_by, updated_by, user_type_code, username, original_username, display_name, email, is_active, can_login)
    VALUES ('test_ct', 'test_ct', 'normal', 'ct_regular_user3', 'ct_regular_user3', 'CT Regular User 3', 'ct_user3@test.com', true, true)
    RETURNING user_id INTO __user3_id;

    PERFORM set_config('test_ct.admin_user_id', __admin_user_id::text, false);
    PERFORM set_config('test_ct.user2_id', __user2_id::text, false);
    PERFORM set_config('test_ct.user3_id', __user3_id::text, false);

    -- -----------------------------------------------------------------------
    -- Users belong to their tenants through the permission assignments below (v2.17)
    -- -----------------------------------------------------------------------
    -- Admin user in all tenants (admin console user needs access to target tenants)

    -- Regular user 2 in tenant 2

    -- Regular user 3 in tenant 3

    -- -----------------------------------------------------------------------
    -- Create test groups in each tenant (for search_user_groups tests)
    -- -----------------------------------------------------------------------
    INSERT INTO auth.user_group (created_by, updated_by, tenant_id, title, code, is_assignable, is_active, is_external, is_system)
    VALUES ('test_ct', 'test_ct', 1, 'CT Admin Group', 'ct_admin_group', true, true, false, false)
    RETURNING user_group_id INTO __group_t1_id;

    INSERT INTO auth.user_group (created_by, updated_by, tenant_id, title, code, is_assignable, is_active, is_external, is_system)
    VALUES ('test_ct', 'test_ct', __tenant2_id, 'CT Tenant2 Group', 'ct_tenant2_group', true, true, false, false)
    RETURNING user_group_id INTO __group_t2_id;

    INSERT INTO auth.user_group (created_by, updated_by, tenant_id, title, code, is_assignable, is_active, is_external, is_system)
    VALUES ('test_ct', 'test_ct', __tenant3_id, 'CT Tenant3 Group', 'ct_tenant3_group', true, true, false, false)
    RETURNING user_group_id INTO __group_t3_id;

    PERFORM set_config('test_ct.group_t1_id', __group_t1_id::text, false);
    PERFORM set_config('test_ct.group_t2_id', __group_t2_id::text, false);
    PERFORM set_config('test_ct.group_t3_id', __group_t3_id::text, false);

    -- -----------------------------------------------------------------------
    -- Create test permission sets in each tenant (for get_perm_sets tests)
    -- -----------------------------------------------------------------------
    INSERT INTO auth.perm_set (created_by, updated_by, tenant_id, code, is_assignable, is_system)
    VALUES ('test_ct', 'test_ct', 1, 'ct_perm_set_t1', true, false);

    INSERT INTO auth.perm_set (created_by, updated_by, tenant_id, code, is_assignable, is_system)
    VALUES ('test_ct', 'test_ct', __tenant2_id, 'ct_perm_set_t2', true, false);

    INSERT INTO auth.perm_set (created_by, updated_by, tenant_id, code, is_assignable, is_system)
    VALUES ('test_ct', 'test_ct', __tenant3_id, 'ct_perm_set_t3', true, false);

    -- Add at least one permission to each perm set (get_perm_sets uses INNER JOIN on perm_set_perm)
    INSERT INTO auth.perm_set_perm (created_by, perm_set_id, permission_id)
    SELECT 'test_ct', ps.perm_set_id, (SELECT permission_id FROM auth.permission LIMIT 1)
    FROM auth.perm_set ps
    WHERE ps.code IN ('ct_perm_set_t1', 'ct_perm_set_t2', 'ct_perm_set_t3');

    -- -----------------------------------------------------------------------
    -- Assign read_all_* permissions to admin user in ALL tenants
    -- (permission is checked against _target_tenant_id, so admin needs it there)
    -- -----------------------------------------------------------------------
    INSERT INTO auth.permission_assignment (created_by, tenant_id, user_id, permission_id)
    SELECT 'test_ct', t.tid, __admin_user_id, p.permission_id
    FROM auth.permission p
    CROSS JOIN (VALUES (1), (__tenant2_id), (__tenant3_id)) AS t(tid)
    WHERE p.full_code IN (
        'users.read_all_users'::ltree,
        'groups.get_all_groups'::ltree,
        'groups.get_all_mappings'::ltree,
        'tenants.get_all_tenants'::ltree,
        'tenants.read_all_tenants'::ltree,
        'permissions.get_all_perm_sets'::ltree
    );

    -- -----------------------------------------------------------------------
    -- Assign permissions to user 2 (tenant 2): regular read_* variants
    -- -----------------------------------------------------------------------
    INSERT INTO auth.permission_assignment (created_by, tenant_id, user_id, permission_id)
    SELECT 'test_ct', __tenant2_id, __user2_id, p.permission_id
    FROM auth.permission p
    WHERE p.full_code IN (
        'users.read_users'::ltree,
        'groups.get_group'::ltree,
        'groups.get_mapping'::ltree,
        'tenants.get_tenants'::ltree,
        'tenants.read_tenants'::ltree,
        'permissions.get_perm_sets'::ltree
    );

    -- -----------------------------------------------------------------------
    -- Assign permissions to user 3 (tenant 3): regular read_* variants
    -- -----------------------------------------------------------------------
    INSERT INTO auth.permission_assignment (created_by, tenant_id, user_id, permission_id)
    SELECT 'test_ct', __tenant3_id, __user3_id, p.permission_id
    FROM auth.permission p
    WHERE p.full_code IN (
        'users.read_users'::ltree,
        'groups.get_group'::ltree,
        'groups.get_mapping'::ltree,
        'tenants.get_tenants'::ltree,
        'tenants.read_tenants'::ltree,
        'permissions.get_perm_sets'::ltree
    );

    -- -----------------------------------------------------------------------
    -- Clear permission caches so they rebuild with new permissions
    -- -----------------------------------------------------------------------
    PERFORM unsecure.clear_permission_cache('test_ct', __admin_user_id, null);
    PERFORM unsecure.clear_permission_cache('test_ct', __user2_id, __tenant2_id);
    PERFORM unsecure.clear_permission_cache('test_ct', __user3_id, __tenant3_id);

    RAISE NOTICE 'SETUP: admin_user_id=% (tenant 1), user2_id=% (tenant %), user3_id=% (tenant %)',
        __admin_user_id, __user2_id, __tenant2_id, __user3_id, __tenant3_id;
    RAISE NOTICE 'SETUP: groups: t1=%, t2=%, t3=%', __group_t1_id, __group_t2_id, __group_t3_id;
    RAISE NOTICE '';
END $$;
