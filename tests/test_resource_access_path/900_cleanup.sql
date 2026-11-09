set search_path = public, const, ext, stage, helpers, internal, unsecure, auth, triggers;

-- ============================================================================
-- CLEANUP
-- ============================================================================
DO $$
BEGIN
    RAISE NOTICE '';
    RAISE NOTICE 'CLEANUP: Removing test data...';

    DELETE FROM auth.resource_access WHERE root_type IN ('fsitem', 'proj');
    DELETE FROM auth.resource_role_assignment WHERE root_type IN ('fsitem', 'proj');
    DELETE FROM auth.user_group_id_cache WHERE created_by IN ('cache', 'test');
    DELETE FROM auth.owner WHERE created_by = 'test';
    DELETE FROM auth.permission_assignment WHERE created_by = 'test';
    DELETE FROM auth.permission_assignment
    WHERE user_id IN (SELECT user_id FROM auth.user_info WHERE code LIKE 'rap_test_%');
    DELETE FROM auth.user_group_member WHERE created_by = 'test';
    DELETE FROM auth.user_group WHERE code LIKE 'rap_test_%';
    DELETE FROM auth.user_info WHERE code LIKE 'rap_test_%';
    DELETE FROM auth.tenant WHERE code = 'rap_test_tenant_2';
    DELETE FROM const.resource_role_flag WHERE resource_role_code = 'fsitem_editor';
    DELETE FROM const.resource_role WHERE code = 'fsitem_editor';
    DELETE FROM const.resource_type_flag WHERE resource_type_code IN ('fsitem', 'fsitem.file', 'proj');
    DELETE FROM const.resource_type WHERE code IN ('fsitem.file', 'fsitem', 'proj');

    DROP TABLE IF EXISTS _rap_test_data;

    RAISE NOTICE 'CLEANUP: Done';
END $$;

DO $$
BEGIN
    RAISE NOTICE '';
    RAISE NOTICE '=================================================================';
    RAISE NOTICE 'Path-based Resource Access Test Suite - COMPLETED SUCCESSFULLY';
    RAISE NOTICE '=================================================================';
    RAISE NOTICE '';
END $$;
