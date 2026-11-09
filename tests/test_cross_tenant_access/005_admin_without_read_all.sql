set search_path = public, const, ext, stage, helpers, internal, unsecure, auth, triggers;

-- ============================================================================
-- Tests: User in tenant 1 WITHOUT read_all_* permissions cannot use cross-tenant
-- Having tenant_id = 1 is necessary but not sufficient - you also need the permission
-- ============================================================================

-- ============================================================================
-- TEST 21: Setup - create a user in tenant 1 with only regular permissions
-- ============================================================================
DO $$
DECLARE
    __limited_admin_id bigint;
BEGIN
    RAISE NOTICE 'TEST 21: Setup - create admin-tenant user without read_all_* permissions';

    INSERT INTO auth.user_info (created_by, updated_by, user_type_code, username, original_username, display_name, email, is_active, can_login)
    VALUES ('test_ct', 'test_ct', 'normal', 'ct_limited_admin', 'ct_limited_admin', 'CT Limited Admin', 'ct_limited@test.com', true, true)
    RETURNING user_id INTO __limited_admin_id;

    -- Only assign regular read permissions in tenant 1, NOT read_all_*
    -- When _tenant_id = 1 without target, the system checks read_all_* which this user lacks
    INSERT INTO auth.permission_assignment (created_by, tenant_id, user_id, permission_id)
    SELECT 'test_ct', 1, __limited_admin_id, p.permission_id
    FROM auth.permission p
    WHERE p.full_code IN (
        'users.read_users'::ltree,
        'groups.get_group'::ltree,
        'tenants.get_tenants'::ltree,
        'tenants.read_tenants'::ltree,
        'permissions.get_perm_sets'::ltree
    );

    PERFORM unsecure.clear_permission_cache('test_ct', __limited_admin_id, null);
    PERFORM set_config('test_ct.limited_admin_id', __limited_admin_id::text, false);

    RAISE NOTICE '  PASS: created limited admin user % in tenant 1', __limited_admin_id;
END $$;

-- ============================================================================
-- TEST 22: Limited admin in tenant 1 without target - uses read_all_*, fails
-- ============================================================================
DO $$
DECLARE
    __limited_admin_id bigint := current_setting('test_ct.limited_admin_id')::bigint;
    __err_code text;
BEGIN
    RAISE NOTICE 'TEST 22: search_users - admin-tenant user without read_all_users is denied (no target)';

    BEGIN
        PERFORM * FROM auth.search_users(__limited_admin_id, 'test_ct', _tenant_id := 1);
        RAISE EXCEPTION '  FAIL: expected permission error, but call succeeded';
    EXCEPTION WHEN OTHERS THEN
        GET STACKED DIAGNOSTICS __err_code = RETURNED_SQLSTATE;
        IF __err_code = '32001' THEN
            RAISE NOTICE '  PASS: permission denied (52002) for user without read_all_users in tenant 1';
        ELSE
            RAISE EXCEPTION '  FAIL: expected error 32001 (no permission), got % (%)', __err_code, SQLERRM;
        END IF;
    END;
END $$;

-- ============================================================================
-- TEST 23: Limited admin with _target_tenant_id - also denied (no read_all_*)
-- ============================================================================
DO $$
DECLARE
    __limited_admin_id bigint := current_setting('test_ct.limited_admin_id')::bigint;
    __tenant2_id integer := current_setting('test_ct.tenant2_id')::integer;
    __err_code text;
BEGIN
    RAISE NOTICE 'TEST 23: search_users - admin-tenant user without read_all_users is denied (with target)';

    BEGIN
        PERFORM * FROM auth.search_users(__limited_admin_id, 'test_ct',
                                         _tenant_id := 1,
                                         _target_tenant_id := __tenant2_id);
        RAISE EXCEPTION '  FAIL: expected permission error, but call succeeded';
    EXCEPTION WHEN OTHERS THEN
        GET STACKED DIAGNOSTICS __err_code = RETURNED_SQLSTATE;
        IF __err_code = '32001' THEN
            RAISE NOTICE '  PASS: permission denied (52002) for user without read_all_users targeting tenant %', __tenant2_id;
        ELSE
            RAISE EXCEPTION '  FAIL: expected error 32001 (no permission), got % (%)', __err_code, SQLERRM;
        END IF;
    END;
END $$;

-- ============================================================================
-- TEST 24: Limited admin - search_user_groups without read_all also denied
-- ============================================================================
DO $$
DECLARE
    __limited_admin_id bigint := current_setting('test_ct.limited_admin_id')::bigint;
    __err_code text;
BEGIN
    RAISE NOTICE 'TEST 24: search_user_groups - admin-tenant user without get_all_groups is denied';

    BEGIN
        PERFORM * FROM auth.search_user_groups(__limited_admin_id, 'test_ct', _tenant_id := 1);
        RAISE EXCEPTION '  FAIL: expected permission error, but call succeeded';
    EXCEPTION WHEN OTHERS THEN
        GET STACKED DIAGNOSTICS __err_code = RETURNED_SQLSTATE;
        IF __err_code = '32001' THEN
            RAISE NOTICE '  PASS: permission denied (52002) for user without get_all_groups in tenant 1';
        ELSE
            RAISE EXCEPTION '  FAIL: expected error 32001 (no permission), got % (%)', __err_code, SQLERRM;
        END IF;
    END;
END $$;
