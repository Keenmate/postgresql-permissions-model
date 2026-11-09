set search_path = public, const, ext, stage, helpers, internal, unsecure, auth, triggers;

-- ============================================================================
-- CLEANUP: Remove test data
-- ============================================================================
DO $$
BEGIN
    RAISE NOTICE '';
    RAISE NOTICE 'CLEANUP: Removing test data...';

    -- Resource access rows are cleaned up by transaction rollback (isolation: transaction)
    -- but clean up explicitly for safety
    DELETE FROM auth.resource_access WHERE root_type IN ('document', 'folder', 'project', 'ptf_untyped', 'ptf_ensured', 'ptf_created', 'ptf_clearable');
    DELETE FROM auth.user_group_id_cache WHERE created_by IN ('cache', 'test');
    DELETE FROM auth.owner WHERE created_by = 'test';
    DELETE FROM auth.permission_assignment WHERE created_by = 'test';
    -- Also clean up system-created assignments for test users
    DELETE FROM auth.permission_assignment
    WHERE user_id IN (SELECT user_id FROM auth.user_info WHERE code LIKE 'ra_test_%' OR code LIKE 'ra_temp_%');
    DELETE FROM auth.user_group_member WHERE created_by = 'test';
    DELETE FROM auth.user_group WHERE code LIKE 'ra_test_%';
    DELETE FROM auth.user_info WHERE code LIKE 'ra_test_%' OR code LIKE 'ra_temp_%';
    DELETE FROM auth.tenant WHERE code = 'ra_test_tenant_2';
    -- Delete per-type flag mappings before resource types
    DELETE FROM const.resource_type_flag WHERE resource_type_code IN (SELECT code FROM const.resource_type WHERE source = 'test');
    -- Delete test access flags
    DELETE FROM const.resource_access_flag WHERE source = 'test';
    -- Delete child types before parent types (by path depth)
    DELETE FROM const.resource_type WHERE source = 'test' AND nlevel(path) > 1;
    DELETE FROM const.resource_type WHERE source = 'test';

    -- Drop temp table
    DROP TABLE IF EXISTS _ra_test_data;

    RAISE NOTICE 'CLEANUP: Done';
END $$;

-- ============================================================================
-- Summary
-- ============================================================================
DO $$
BEGIN
    RAISE NOTICE '';
    RAISE NOTICE '=================================================================';
    RAISE NOTICE 'Resource Access (ACL) Test Suite - COMPLETED SUCCESSFULLY';
    RAISE NOTICE '=================================================================';
    RAISE NOTICE '';
    RAISE NOTICE 'All tests passed:';
    RAISE NOTICE '  001 Grant/Revoke:';
    RAISE NOTICE '    1. Grant read flag to a user';
    RAISE NOTICE '    2. Grant multiple flags at once';
    RAISE NOTICE '    3. Grant flags to a group';
    RAISE NOTICE '    4. Revoke specific flag';
    RAISE NOTICE '    5. Revoke all flags for a user on a resource';
    RAISE NOTICE '    6. Revoke all resource access for a resource';
    RAISE NOTICE '    7. Grant idempotency';
    RAISE NOTICE '  002 has_resource_access:';
    RAISE NOTICE '    1. Direct user grant returns true';
    RAISE NOTICE '    2. No grant returns false';
    RAISE NOTICE '    3. No grant throws error';
    RAISE NOTICE '    4. Group grant inheritance';
    RAISE NOTICE '    5. System user bypass';
    RAISE NOTICE '    6. Tenant owner bypass';
    RAISE NOTICE '    7. Wrong flag returns false';
    RAISE NOTICE '  003 Deny Overrides:';
    RAISE NOTICE '    1. User deny overrides group grant';
    RAISE NOTICE '    2. Deny only affects denied flag';
    RAISE NOTICE '    3. Revoking deny restores access';
    RAISE NOTICE '    4. Grant flips deny to grant';
    RAISE NOTICE '  004 Filter Accessible:';
    RAISE NOTICE '    1. Mixed grants filter';
    RAISE NOTICE '    2. Denied resources excluded';
    RAISE NOTICE '    3. Group grants included';
    RAISE NOTICE '    4. System user sees all';
    RAISE NOTICE '  005 Flags and Grants:';
    RAISE NOTICE '    1. Direct grants returned';
    RAISE NOTICE '    2. Denied flag excluded';
    RAISE NOTICE '    3. Source attribution';
    RAISE NOTICE '    4. List all grants/denies';
    RAISE NOTICE '    5. Display names included';
    RAISE NOTICE '  006 Tenant Isolation:';
    RAISE NOTICE '    1. Cross-tenant access prevented';
    RAISE NOTICE '    2. Filter respects boundaries';
    RAISE NOTICE '    3. Grants are independent per tenant';
    RAISE NOTICE '  007 Cascade Delete:';
    RAISE NOTICE '    1. User delete cascades';
    RAISE NOTICE '    2. Group delete cascades';
    RAISE NOTICE '    3. Tenant delete cascades';
    RAISE NOTICE '    4. Granter delete sets null';
    RAISE NOTICE '  008 Hierarchical Types (dot-delimited codes):';
    RAISE NOTICE '    1. Register parent + child types';
    RAISE NOTICE '    2. Grant on parent, child inherits read';
    RAISE NOTICE '    3. Direct child grant works independently';
    RAISE NOTICE '    4. Deny on child overrides parent grant';
    RAISE NOTICE '    5. Group grant on parent cascades to child';
    RAISE NOTICE '  009 Matrix Query:';
    RAISE NOTICE '    1. Matrix returns all sub-types with flags';
    RAISE NOTICE '    2. Denied flags excluded from matrix';
    RAISE NOTICE '    3. System user gets full matrix';
    RAISE NOTICE '    4. Inherited + direct flags combined';
    RAISE NOTICE '  010 Group Cache:';
    RAISE NOTICE '    1. Cache populated on first access';
    RAISE NOTICE '    2. Cache hit on second access';
    RAISE NOTICE '    3. Soft invalidation on group member change';
    RAISE NOTICE '    4. Hard invalidation on user disable';
    RAISE NOTICE '  011 Per-Type Access Flags:';
    RAISE NOTICE '    1. Grant with invalid flag raises 35006';
    RAISE NOTICE '    2. Deny with invalid flag raises 35006';
    RAISE NOTICE '    3. Grant with valid flags succeeds';
    RAISE NOTICE '    4. Mixed valid + invalid flags — entire grant fails';
    RAISE NOTICE '    5. Type with no flag mappings allows all flags (backward compat)';
    RAISE NOTICE '    6. get_resource_types returns access_flags';
    RAISE NOTICE '    7. ensure_resource_types registers per-type flags';
    RAISE NOTICE '    8. create_resource_type registers per-type flags';
    RAISE NOTICE '    9. Hierarchical types — child validates its own flags';
    RAISE NOTICE '    10. Matrix respects per-type flags for system user';
    RAISE NOTICE '    11. Grant valid child-specific flag succeeds';
    RAISE NOTICE '    12. ensure_access_flags creates new global flags';
    RAISE NOTICE '    13. ensure_access_flags is idempotent';
    RAISE NOTICE '    14. get_access_flags lists all flags';
    RAISE NOTICE '    15. ensure_resource_type_flags sets exact flag set';
    RAISE NOTICE '    16. ensure_resource_type_flags with empty array clears all';
    RAISE NOTICE '    17. ensure_resource_type_flags with null is no-op';
    RAISE NOTICE '';
END $$;
