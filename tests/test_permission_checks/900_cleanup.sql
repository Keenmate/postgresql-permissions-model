set search_path = public, const, ext, stage, helpers, internal, unsecure, auth, triggers;

-- ============================================================================
-- CLEANUP: Remove test data
-- ============================================================================
DO $$
BEGIN
    RAISE NOTICE '';
    RAISE NOTICE 'CLEANUP: Removing permission checks test data...';

    -- Clean up in reverse dependency order
    DELETE FROM auth.user_permission_cache WHERE created_by = 'pchk_test';
    DELETE FROM auth.permission_assignment WHERE created_by = 'pchk_test';
    DELETE FROM auth.user_group_member WHERE created_by = 'pchk_test';
    DELETE FROM auth.perm_set_perm WHERE created_by = 'pchk_test';
    DELETE FROM auth.perm_set WHERE code = 'pchk_test_perm_set';
    DELETE FROM auth.permission WHERE code IN ('pchk_test_perm_a', 'pchk_test_perm_b');
    DELETE FROM auth.user_group WHERE code IN ('pchk_test_group');
    DELETE FROM public.journal WHERE created_by = 'pchk_test';
    DELETE FROM auth.user_blacklist WHERE username IN ('pchk_del_bl_user', 'pchk_del_user');
    DELETE FROM auth.user_info WHERE username LIKE 'pchk_%';

    RAISE NOTICE 'CLEANUP: Done';
END $$;
