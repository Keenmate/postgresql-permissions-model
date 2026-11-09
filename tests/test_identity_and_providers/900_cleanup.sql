set search_path = public, const, ext, stage, helpers, internal, unsecure, auth, triggers;

-- ============================================================================
-- CLEANUP: Remove test data
-- ============================================================================
DO $$
BEGIN
    RAISE NOTICE '';
    RAISE NOTICE 'CLEANUP: Removing test data...';

    DELETE FROM auth.user_event WHERE created_by = 'idp_test';
    DELETE FROM public.journal WHERE created_by = 'idp_test';
    DELETE FROM auth.user_identity WHERE uid LIKE 'idp_test_%';
    DELETE FROM auth.user_data WHERE user_id IN (SELECT user_id FROM auth.user_info WHERE username LIKE 'idp_test_%');
    DELETE FROM auth.user_info WHERE username LIKE 'idp_test_%';
    DELETE FROM auth.provider WHERE code = 'test_idp';

    RAISE NOTICE 'CLEANUP: Done';
END $$;

-- ============================================================================
-- Summary
-- ============================================================================
DO $$
BEGIN
    RAISE NOTICE '';
    RAISE NOTICE '=================================================================';
    RAISE NOTICE 'Identity and Provider Reads Tests - COMPLETED SUCCESSFULLY';
    RAISE NOTICE '=================================================================';
    RAISE NOTICE '';
    RAISE NOTICE 'All 14 tests passed:';
    RAISE NOTICE '  1.  disable_user_identity sets is_active=false';
    RAISE NOTICE '  2.  verify disabled identity in user_identity table';
    RAISE NOTICE '  3.  enable_user_identity sets is_active=true';
    RAISE NOTICE '  4.  verify enabled identity in user_identity table';
    RAISE NOTICE '  5.  verify_user_identity marks identity as verified';
    RAISE NOTICE '  6.  get_user_identity returns correct identity data';
    RAISE NOTICE '  7.  get_user_identity_by_email returns identity by email';
    RAISE NOTICE '  8.  get_user_by_id returns user data';
    RAISE NOTICE '  9.  get_user_by_provider_oid returns user by OID';
    RAISE NOTICE '  10. get_user_last_selected_tenant returns last selected tenant';
    RAISE NOTICE '  11. get_user_last_selected_tenant returns empty when not set';
    RAISE NOTICE '  12. get_providers returns at least the email provider';
    RAISE NOTICE '  13. get_providers returns test_idp provider';
    RAISE NOTICE '  14. get_providers filters by is_active';
    RAISE NOTICE '';
END $$;
