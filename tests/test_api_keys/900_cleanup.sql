set search_path = public, const, ext, stage, helpers, internal, unsecure, auth, triggers;

-- ============================================================================
-- CLEANUP: Remove test data
-- ============================================================================
DO $$
BEGIN
    RAISE NOTICE '';
    RAISE NOTICE 'CLEANUP: Removing test data...';

    -- Delete API key technical users (permission assignments cascade via delete_api_key logic)
    DELETE FROM auth.permission_assignment
    WHERE user_id IN (
        SELECT ui.user_id FROM auth.user_info ui
        WHERE ui.user_type_code = 'api' AND ui.code LIKE 'api_key_%'
        AND ui.created_by = 'ak_test'
    );

    DELETE FROM auth.user_info
    WHERE user_type_code = 'api' AND code LIKE 'api_key_%'
    AND created_by = 'ak_test';

    -- Delete API keys
    DELETE FROM auth.api_key WHERE created_by = 'ak_test';

    -- Delete journal entries
    DELETE FROM public.journal WHERE created_by = 'ak_test';

    -- Delete user events
    DELETE FROM auth.user_event WHERE created_by = 'ak_test';

    -- Delete admin user permission assignments
    DELETE FROM auth.permission_assignment
    WHERE user_id IN (SELECT user_id FROM auth.user_info WHERE code = 'ak_test_admin');

    -- Delete admin user
    DELETE FROM auth.user_info WHERE code = 'ak_test_admin';

    -- Drop temp table
    DROP TABLE IF EXISTS _ak_test_data;

    RAISE NOTICE 'CLEANUP: Done';
END $$;

-- ============================================================================
-- Summary
-- ============================================================================
DO $$
BEGIN
    RAISE NOTICE '';
    RAISE NOTICE '=================================================================';
    RAISE NOTICE 'API Keys Tests - COMPLETED SUCCESSFULLY';
    RAISE NOTICE '=================================================================';
    RAISE NOTICE '';
    RAISE NOTICE 'All 19 tests passed:';
    RAISE NOTICE '  1.  create_api_key returns api_key_id, api_key, and api_secret';
    RAISE NOTICE '  2.  create_api_key creates a technical user';
    RAISE NOTICE '  3.  create_api_key journals event 14001';
    RAISE NOTICE '  4.  delete_api_key removes key and technical user';
    RAISE NOTICE '  5.  update_api_key modifies fields';
    RAISE NOTICE '  6.  update_api_key journals event 14002';
    RAISE NOTICE '  7.  create_api_key_validation_attempt succeeds with correct key+secret';
    RAISE NOTICE '  8.  create_api_key_validation_attempt rejects a wrong secret (30001, persisted)';
    RAISE NOTICE '  9.  update_api_key_secret rotates secret successfully';
    RAISE NOTICE '  10. assign_api_key_permissions with perm_set_code';
    RAISE NOTICE '  11. get_api_key_permissions returns 11 columns';
    RAISE NOTICE '  12. assign_api_key_permissions with individual permission_codes';
    RAISE NOTICE '  13. unassign_api_key_permissions removes perm_set';
    RAISE NOTICE '  14. unassign_api_key_permissions removes individual permissions';
    RAISE NOTICE '  15. search_api_keys returns created keys';
    RAISE NOTICE '  16. search_api_keys filters by search_text';
    RAISE NOTICE '  17. search_api_keys pagination works';
    RAISE NOTICE '  18. search_api_keys returns 12 columns';
    RAISE NOTICE '  19. search_api_keys with no matches returns empty';
    RAISE NOTICE '';
END $$;
