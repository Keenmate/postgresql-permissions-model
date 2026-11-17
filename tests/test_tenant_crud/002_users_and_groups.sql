set search_path = public, const, ext, stage, helpers, internal, unsecure, auth, triggers;

-- ============================================================================
-- TEST 11: Create a new tenant for user/group tests
-- ============================================================================
DO $$
DECLARE
    __admin_id bigint := current_setting('test_tenant.admin_id')::bigint;
    __tenant_id int;
    __tenant_uuid uuid;
BEGIN
    RAISE NOTICE 'TEST 11: Create tenant for user/group tests';

    SELECT ct.__tenant_id, ct.__uuid
    FROM auth.create_tenant('tenant_test', 1, 'tenant-test-ug', 'Test Tenant UG', 'test_tenant_ug') ct
    INTO __tenant_id, __tenant_uuid;

    IF __tenant_id IS NULL THEN
        RAISE EXCEPTION '  FAIL: create_tenant returned NULL';
    END IF;

    PERFORM set_config('test_tenant.ug_tenant_id', __tenant_id::text, false);
    PERFORM set_config('test_tenant.ug_tenant_uuid', __tenant_uuid::text, false);

    RAISE NOTICE '  PASS: tenant created (id=%, uuid=%)', __tenant_id, __tenant_uuid;
END $$;

-- ============================================================================
-- TEST 12: Add user to tenant via group membership
-- ============================================================================
DO $$
DECLARE
    __admin_id bigint := current_setting('test_tenant.admin_id')::bigint;
    __target_user_id bigint := current_setting('test_tenant.target_user_id')::bigint;
    __tenant_id int := current_setting('test_tenant.ug_tenant_id')::int;
    __group_id int;
    __member_id bigint;
BEGIN
    RAISE NOTICE 'TEST 12: Add user to tenant via group membership';

    -- Get the auto-created "Tenant Members" group for the new tenant
    SELECT user_group_id FROM auth.user_group
    WHERE tenant_id = __tenant_id AND title = 'Tenant Members'
    INTO __group_id;

    IF __group_id IS NULL THEN
        RAISE EXCEPTION '  FAIL: Tenant Members group not found for tenant %', __tenant_id;
    END IF;

    -- Add target user to the group
    SELECT ugm.__user_group_member_id
    FROM auth.create_user_group_member('tenant_test', 1, 'tenant-test-ug-member', __group_id, __target_user_id, __tenant_id) ugm
    INTO __member_id;

    IF __member_id IS NOT NULL THEN
        RAISE NOTICE '  PASS: user added to group (member_id=%, group_id=%)', __member_id, __group_id;
    ELSE
        RAISE EXCEPTION '  FAIL: create_user_group_member returned NULL';
    END IF;

    PERFORM set_config('test_tenant.ug_group_id', __group_id::text, false);
END $$;

-- ============================================================================
-- TEST 13: get_tenant_users returns the added user
-- ============================================================================
DO $$
DECLARE
    __admin_id bigint := current_setting('test_tenant.admin_id')::bigint;
    __target_user_id bigint := current_setting('test_tenant.target_user_id')::bigint;
    __tenant_id int := current_setting('test_tenant.ug_tenant_id')::int;
    __found_user_id bigint;
    __found_display text;
BEGIN
    RAISE NOTICE 'TEST 13: get_tenant_users returns the added user';

    SELECT tu.__user_id, tu.__display_name
    FROM auth.get_tenant_users('tenant_test', 1, 'tenant-test-ug-users', 1, __tenant_id) tu
    WHERE tu.__user_id = __target_user_id
    INTO __found_user_id, __found_display;

    IF __found_user_id = __target_user_id THEN
        RAISE NOTICE '  PASS: user found in tenant users (id=%, display=%)', __found_user_id, __found_display;
    ELSE
        RAISE EXCEPTION '  FAIL: user not found in get_tenant_users (expected user_id=%)', __target_user_id;
    END IF;
END $$;

-- ============================================================================
-- TEST 14: Create additional group and verify get_tenant_groups
-- ============================================================================
DO $$
DECLARE
    __admin_id bigint := current_setting('test_tenant.admin_id')::bigint;
    __tenant_id int := current_setting('test_tenant.ug_tenant_id')::int;
    __extra_group_id int;
    __group_count int;
BEGIN
    RAISE NOTICE 'TEST 14: Create additional group and verify get_tenant_groups';

    -- Create an extra group in this tenant
    SELECT ug.__user_group_id
    FROM auth.create_user_group('tenant_test', 1, 'tenant-test-ug-grp', 'Test Extra Group',
                                true, true, false, __tenant_id) ug
    INTO __extra_group_id;

    IF __extra_group_id IS NULL THEN
        RAISE EXCEPTION '  FAIL: create_user_group returned NULL';
    END IF;

    PERFORM set_config('test_tenant.ug_extra_group_id', __extra_group_id::text, false);

    RAISE NOTICE '  PASS: extra group created (id=%)', __extra_group_id;
END $$;

-- ============================================================================
-- TEST 15: get_tenant_groups returns groups for the tenant
-- ============================================================================
DO $$
DECLARE
    __admin_id bigint := current_setting('test_tenant.admin_id')::bigint;
    __target_user_id bigint := current_setting('test_tenant.target_user_id')::bigint;
    __tenant_id int := current_setting('test_tenant.ug_tenant_id')::int;
    __group_count int;
    __found_members boolean := false;
BEGIN
    RAISE NOTICE 'TEST 15: get_tenant_groups returns groups for the tenant';

    -- get_tenant_groups uses user_group_members view which requires at least one member
    -- The "Tenant Members" group has our target user, so it should appear
    SELECT count(*)
    FROM auth.get_tenant_groups('tenant_test', 1, 'tenant-test-ug-groups', 1, __tenant_id) tg
    INTO __group_count;

    -- We should see at least the "Tenant Members" group (it has a member)
    IF __group_count >= 1 THEN
        RAISE NOTICE '  PASS: get_tenant_groups returned % group(s)', __group_count;
    ELSE
        RAISE EXCEPTION '  FAIL: get_tenant_groups returned % groups (expected >= 1)', __group_count;
    END IF;
END $$;
