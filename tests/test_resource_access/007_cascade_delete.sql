set search_path = public, const, ext, stage, helpers, internal, unsecure, auth, triggers;

-- ============================================================================
-- TEST 1: FK cascade on user delete removes user grants
-- ============================================================================
DO $$
DECLARE
    __user_id_1 bigint;
    __temp_user_id bigint;
    __count_before integer;
    __count_after integer;
BEGIN
    RAISE NOTICE 'TEST 1: FK cascade on user delete removes user grants';

    SELECT val FROM _ra_test_data WHERE key = 'user_id_1' INTO __user_id_1;

    -- Create a temporary user
    INSERT INTO auth.user_info (created_by, updated_by, display_name, code, username, original_username, email, can_login)
    VALUES ('test', 'test', 'RA Temp Delete User', 'ra_temp_delete', 'ra_temp_delete@test.com', 'ra_temp_delete@test.com', 'ra_temp_delete@test.com', true)
    RETURNING user_id INTO __temp_user_id;

    -- Grant access
    PERFORM auth.assign_resource_access('test', __user_id_1, 'test-corr-cascade-1a', 'document', '{"id": 4001}'::jsonb,
        _target_user_id := __temp_user_id, _access_flags := array['read', 'write']);

    SELECT count(*) FROM auth.resource_access WHERE user_id = __temp_user_id INTO __count_before;

    -- Delete the user
    DELETE FROM auth.user_info WHERE user_id = __temp_user_id;

    SELECT count(*) FROM auth.resource_access WHERE user_id = __temp_user_id INTO __count_after;

    IF __count_before = 2 AND __count_after = 0 THEN
        RAISE NOTICE '  PASS: User delete cascaded to resource_access (before=%, after=%)', __count_before, __count_after;
    ELSE
        RAISE EXCEPTION '  FAIL: Expected before=2, after=0, got before=%, after=%', __count_before, __count_after;
    END IF;
END $$;

-- ============================================================================
-- TEST 2: FK cascade on group delete removes group grants
-- ============================================================================
DO $$
DECLARE
    __user_id_1 bigint;
    __temp_group_id integer;
    __count_before integer;
    __count_after integer;
BEGIN
    RAISE NOTICE 'TEST 2: FK cascade on group delete removes group grants';

    SELECT val FROM _ra_test_data WHERE key = 'user_id_1' INTO __user_id_1;

    -- Create a temporary group
    INSERT INTO auth.user_group (created_by, updated_by, tenant_id, title, code, is_active, is_assignable)
    VALUES ('test', 'test', 1, 'RA Temp Delete Group', 'ra_temp_delete_group', true, true)
    RETURNING user_group_id INTO __temp_group_id;

    -- Grant access to the group
    PERFORM auth.assign_resource_access('test', __user_id_1, 'test-corr-cascade-2a', 'document', '{"id": 4002}'::jsonb,
        _user_group_id := __temp_group_id, _access_flags := array['read', 'write', 'share']);

    SELECT count(*) FROM auth.resource_access WHERE user_group_id = __temp_group_id INTO __count_before;

    -- Delete the group
    DELETE FROM auth.user_group WHERE user_group_id = __temp_group_id;

    SELECT count(*) FROM auth.resource_access WHERE user_group_id = __temp_group_id INTO __count_after;

    IF __count_before = 3 AND __count_after = 0 THEN
        RAISE NOTICE '  PASS: Group delete cascaded to resource_access (before=%, after=%)', __count_before, __count_after;
    ELSE
        RAISE EXCEPTION '  FAIL: Expected before=3, after=0, got before=%, after=%', __count_before, __count_after;
    END IF;
END $$;

-- ============================================================================
-- TEST 3: FK cascade on tenant delete removes all tenant grants
-- ============================================================================
DO $$
DECLARE
    __user_id_1 bigint;
    __temp_tenant_id integer;
    __temp_user_id bigint;
    __count_before integer;
    __count_after integer;
BEGIN
    RAISE NOTICE 'TEST 3: FK cascade on tenant delete removes all tenant grants';

    SELECT val FROM _ra_test_data WHERE key = 'user_id_1' INTO __user_id_1;

    -- Create a temporary tenant
    INSERT INTO auth.tenant (created_by, updated_by, title, code)
    VALUES ('test', 'test', 'RA Temp Delete Tenant', 'ra_temp_delete_tenant')
    RETURNING tenant_id INTO __temp_tenant_id;

    -- Create a user in that tenant
    INSERT INTO auth.user_info (created_by, updated_by, display_name, code, username, original_username, email, can_login)
    VALUES ('test', 'test', 'RA Temp Tenant User', 'ra_temp_tenant_user', 'ra_temp_tenant_user@test.com', 'ra_temp_tenant_user@test.com', 'ra_temp_tenant_user@test.com', true)
    RETURNING user_id INTO __temp_user_id;

    -- Create system_admin perm set in temp tenant (only exists in tenant 1 by default)
    PERFORM unsecure.create_perm_set_as_system('System admin', true, _is_assignable := true,
        _permissions := array['resources'], _tenant_id := __temp_tenant_id);
    PERFORM unsecure.assign_permission_as_system(null::integer, __user_id_1, 'system_admin', _tenant_id := __temp_tenant_id);

    -- Grant access in temp tenant
    PERFORM auth.assign_resource_access('test', __user_id_1, 'test-corr-cascade-3a', 'document', '{"id": 4003}'::jsonb,
        _target_user_id := __temp_user_id, _access_flags := array['read'], _tenant_id := __temp_tenant_id);

    SELECT count(*) FROM auth.resource_access WHERE tenant_id = __temp_tenant_id INTO __count_before;

    -- Clear dependent tables before deleting tenant (not all FKs cascade)
    DELETE FROM auth.user_permission_cache WHERE tenant_id = __temp_tenant_id;
    DELETE FROM auth.user_group_id_cache WHERE tenant_id = __temp_tenant_id;
    DELETE FROM auth.permission_assignment WHERE tenant_id = __temp_tenant_id;
    DELETE FROM auth.perm_set_perm WHERE perm_set_id IN (SELECT perm_set_id FROM auth.perm_set WHERE tenant_id = __temp_tenant_id);
    DELETE FROM auth.perm_set WHERE tenant_id = __temp_tenant_id;
    DELETE FROM auth.user_group_member WHERE user_group_id IN (SELECT user_group_id FROM auth.user_group WHERE tenant_id = __temp_tenant_id);
    DELETE FROM auth.user_group WHERE tenant_id = __temp_tenant_id;
    DELETE FROM public.journal WHERE tenant_id = __temp_tenant_id;
    -- Delete the tenant (should cascade to resource_access)
    DELETE FROM auth.tenant WHERE tenant_id = __temp_tenant_id;

    SELECT count(*) FROM auth.resource_access WHERE tenant_id = __temp_tenant_id INTO __count_after;

    IF __count_before >= 1 AND __count_after = 0 THEN
        RAISE NOTICE '  PASS: Tenant delete cascaded (before=%, after=%)', __count_before, __count_after;
    ELSE
        RAISE EXCEPTION '  FAIL: Expected before>=1, after=0, got before=%, after=%', __count_before, __count_after;
    END IF;
END $$;

-- ============================================================================
-- TEST 4: granted_by set to null on granting user delete (ON DELETE SET NULL)
-- ============================================================================
DO $$
DECLARE
    __user_id_1 bigint;
    __user_id_2 bigint;
    __temp_granter_id bigint;
    __granted_by_before bigint;
    __granted_by_after bigint;
BEGIN
    RAISE NOTICE 'TEST 4: granted_by set to null on granting user delete';

    SELECT val FROM _ra_test_data WHERE key = 'user_id_1' INTO __user_id_1;
    SELECT val FROM _ra_test_data WHERE key = 'user_id_2' INTO __user_id_2;

    -- Create a temporary granter
    INSERT INTO auth.user_info (created_by, updated_by, display_name, code, username, original_username, email, can_login)
    VALUES ('test', 'test', 'RA Temp Granter', 'ra_temp_granter', 'ra_temp_granter@test.com', 'ra_temp_granter@test.com', 'ra_temp_granter@test.com', true)
    RETURNING user_id INTO __temp_granter_id;

    -- Give granter permissions
    PERFORM unsecure.assign_permission_as_system(null::integer, __temp_granter_id, 'system_admin');

    -- Grant with temp granter as the acting user
    PERFORM auth.assign_resource_access('test', __temp_granter_id, 'test-corr-cascade-4a', 'document', '{"id": 4004}'::jsonb,
        _target_user_id := __user_id_2, _access_flags := array['read']);

    SELECT granted_by FROM auth.resource_access
    WHERE resource_type = 'document' AND resource_id = '{"id": 4004}'::jsonb AND user_id = __user_id_2
    INTO __granted_by_before;

    -- Clear dependent data before deleting the granter
    DELETE FROM auth.permission_assignment WHERE user_id = __temp_granter_id;
    DELETE FROM auth.user_permission_cache WHERE user_id = __temp_granter_id;
    DELETE FROM auth.user_group_id_cache WHERE user_id = __temp_granter_id;

    -- Delete the granter
    DELETE FROM auth.user_info WHERE user_id = __temp_granter_id;

    SELECT granted_by FROM auth.resource_access
    WHERE resource_type = 'document' AND resource_id = '{"id": 4004}'::jsonb AND user_id = __user_id_2
    INTO __granted_by_after;

    IF __granted_by_before = __temp_granter_id AND __granted_by_after IS NULL THEN
        RAISE NOTICE '  PASS: granted_by set to null after granter delete (before=%, after=%)', __granted_by_before, __granted_by_after;
    ELSE
        RAISE EXCEPTION '  FAIL: Expected before=%, after=null, got before=%, after=%', __temp_granter_id, __granted_by_before, __granted_by_after;
    END IF;
END $$;
