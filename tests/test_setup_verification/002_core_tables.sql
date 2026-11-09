set search_path = public, const, ext, stage, helpers, internal, unsecure, auth, triggers;

-- ============================================================================
-- Verify all core tables exist
-- ============================================================================
DO $$
DECLARE
    __missing text;
BEGIN
    RAISE NOTICE '-- Core Tables --';

    -- auth schema tables
    SELECT string_agg(t, ', ')
    FROM unnest(ARRAY[
        'user_info', 'user_identity', 'user_data', 'user_group', 'user_group_member',
        'user_group_mapping', 'user_event', 'user_permission_cache',
        'tenant', 'user_tenant_preference',
        'permission', 'perm_set', 'perm_set_perm', 'permission_assignment',
        'provider', 'token', 'api_key', 'owner',
        'user_mfa', 'mfa_policy'
    ]) AS t
    WHERE NOT EXISTS (
        SELECT 1 FROM information_schema.tables tbl
        WHERE tbl.table_schema = 'auth' AND tbl.table_name = t
    )
    INTO __missing;

    IF __missing IS NOT NULL THEN
        RAISE EXCEPTION 'FAIL: Missing auth tables: %', __missing;
    END IF;
    RAISE NOTICE 'PASS: All auth tables exist';

    -- const schema tables
    SELECT string_agg(t, ', ')
    FROM unnest(ARRAY['event_category', 'event_code', 'sys_param', 'mfa_type']) AS t
    WHERE NOT EXISTS (
        SELECT 1 FROM information_schema.tables tbl
        WHERE tbl.table_schema = 'const' AND tbl.table_name = t
    )
    INTO __missing;

    IF __missing IS NOT NULL THEN
        RAISE EXCEPTION 'FAIL: Missing const tables: %', __missing;
    END IF;
    RAISE NOTICE 'PASS: All const tables exist';
END $$;
