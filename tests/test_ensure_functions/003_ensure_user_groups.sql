set search_path = public, const, ext, stage, helpers, internal, unsecure, auth, triggers;

-- ============================================================================
-- TEST 15: Create new user groups
-- ============================================================================
DO $$
DECLARE
    __user_id        bigint := current_setting('test_ef.user_id')::bigint;
    __correlation_id text   := current_setting('test_ef.correlation_id');
    __returned       int;
    __editors_exists boolean;
    __viewers_exists boolean;
BEGIN
    RAISE NOTICE 'TEST 15: ensure_user_groups - create new groups';

    SELECT count(*) INTO __returned
    FROM auth.ensure_user_groups(
        'test_ef', __user_id, __correlation_id,
        '[
            {"title": "Test Editors"},
            {"title": "Test Viewers"}
        ]'::jsonb
    );

    SELECT
        exists(SELECT 1 FROM auth.user_group WHERE code = 'test_editors' AND tenant_id = 1),
        exists(SELECT 1 FROM auth.user_group WHERE code = 'test_viewers' AND tenant_id = 1)
    INTO __editors_exists, __viewers_exists;

    IF __returned = 2 AND __editors_exists AND __viewers_exists THEN
        RAISE NOTICE '  PASS: Created 2 groups (returned=%, editors=%, viewers=%)', __returned, __editors_exists, __viewers_exists;
    ELSE
        RAISE EXCEPTION '  FAIL: Group creation failed (returned=%, editors=%, viewers=%)', __returned, __editors_exists, __viewers_exists;
    END IF;
END $$;

-- ============================================================================
-- TEST 16: ensure_user_groups is idempotent
-- ============================================================================
DO $$
DECLARE
    __user_id        bigint := current_setting('test_ef.user_id')::bigint;
    __correlation_id text   := current_setting('test_ef.correlation_id');
    __count_before   int;
    __count_after    int;
    __returned       int;
BEGIN
    RAISE NOTICE 'TEST 16: ensure_user_groups - idempotent (no duplicates on re-call)';

    SELECT count(*) INTO __count_before
    FROM auth.user_group WHERE code in ('test_editors', 'test_viewers') AND tenant_id = 1;

    SELECT count(*) INTO __returned
    FROM auth.ensure_user_groups(
        'test_ef', __user_id, __correlation_id,
        '[
            {"title": "Test Editors"},
            {"title": "Test Viewers"}
        ]'::jsonb
    );

    SELECT count(*) INTO __count_after
    FROM auth.user_group WHERE code in ('test_editors', 'test_viewers') AND tenant_id = 1;

    IF __count_before = __count_after AND __returned = 2 THEN
        RAISE NOTICE '  PASS: Idempotent (before=%, after=%, returned=%)', __count_before, __count_after, __returned;
    ELSE
        RAISE EXCEPTION '  FAIL: Not idempotent (before=%, after=%, returned=%)', __count_before, __count_after, __returned;
    END IF;
END $$;

-- ============================================================================
-- TEST 17: Groups with various flags (is_external, is_active, is_assignable)
-- ============================================================================
DO $$
DECLARE
    __user_id        bigint := current_setting('test_ef.user_id')::bigint;
    __correlation_id text   := current_setting('test_ef.correlation_id');
    __is_external    boolean;
    __is_active      boolean;
    __is_assignable  boolean;
    __is_system      boolean;
BEGIN
    RAISE NOTICE 'TEST 17: ensure_user_groups - groups with various flags';

    PERFORM auth.ensure_user_groups(
        'test_ef', __user_id, __correlation_id,
        '[
            {"title": "Test External Group", "is_external": true, "is_assignable": false}
        ]'::jsonb
    );

    SELECT ug.is_external, ug.is_active, ug.is_assignable, ug.is_system
    FROM auth.user_group ug
    WHERE ug.code = 'test_external_group' AND ug.tenant_id = 1
    INTO __is_external, __is_active, __is_assignable, __is_system;

    IF __is_external = true AND __is_active = true AND __is_assignable = false AND __is_system = false THEN
        RAISE NOTICE '  PASS: Flags correct (external=%, active=%, assignable=%, system=%)', __is_external, __is_active, __is_assignable, __is_system;
    ELSE
        RAISE EXCEPTION '  FAIL: Flags wrong (external=%, active=%, assignable=%, system=%)', __is_external, __is_active, __is_assignable, __is_system;
    END IF;
END $$;

-- ============================================================================
-- TEST 18: Mix of existing and new groups
-- ============================================================================
DO $$
DECLARE
    __user_id         bigint := current_setting('test_ef.user_id')::bigint;
    __correlation_id  text   := current_setting('test_ef.correlation_id');
    __returned        int;
    __managers_exists  boolean;
BEGIN
    RAISE NOTICE 'TEST 18: ensure_user_groups - mix of existing and new';

    SELECT count(*) INTO __returned
    FROM auth.ensure_user_groups(
        'test_ef', __user_id, __correlation_id,
        '[
            {"title": "Test Editors"},
            {"title": "Test Managers"}
        ]'::jsonb
    );

    SELECT exists(SELECT 1 FROM auth.user_group WHERE code = 'test_managers' AND tenant_id = 1)
    INTO __managers_exists;

    IF __returned = 2 AND __managers_exists THEN
        RAISE NOTICE '  PASS: Mix of existing+new (returned=%, new_managers=%)', __returned, __managers_exists;
    ELSE
        RAISE EXCEPTION '  FAIL: Mix failed (returned=%, new_managers=%)', __returned, __managers_exists;
    END IF;
END $$;

-- ============================================================================
-- TEST 19: is_system is always false (cannot create system groups via ensure)
-- ============================================================================
DO $$
DECLARE
    __user_id        bigint := current_setting('test_ef.user_id')::bigint;
    __correlation_id text   := current_setting('test_ef.correlation_id');
    __is_system      boolean;
BEGIN
    RAISE NOTICE 'TEST 19: ensure_user_groups - is_system always false';

    -- The function always passes is_system=false to unsecure.create_user_group
    SELECT ug.is_system
    FROM auth.user_group ug
    WHERE ug.code = 'test_editors' AND ug.tenant_id = 1
    INTO __is_system;

    IF __is_system = false THEN
        RAISE NOTICE '  PASS: is_system=false as expected';
    ELSE
        RAISE EXCEPTION '  FAIL: Expected is_system=false, got %', __is_system;
    END IF;
END $$;

-- ============================================================================
-- TEST 20: Returns all requested groups including pre-existing
-- ============================================================================
DO $$
DECLARE
    __user_id        bigint := current_setting('test_ef.user_id')::bigint;
    __correlation_id text   := current_setting('test_ef.correlation_id');
    __returned       int;
BEGIN
    RAISE NOTICE 'TEST 20: ensure_user_groups - returns all requested (existing + new)';

    SELECT count(*) INTO __returned
    FROM auth.ensure_user_groups(
        'test_ef', __user_id, __correlation_id,
        '[
            {"title": "Test Editors"},
            {"title": "Test Viewers"},
            {"title": "Test Analysts"}
        ]'::jsonb
    );

    -- Editors and Viewers already exist, Analysts is new
    IF __returned = 3 THEN
        RAISE NOTICE '  PASS: Returns all 3 requested groups (returned=%)', __returned;
    ELSE
        RAISE EXCEPTION '  FAIL: Expected 3 returned, got %', __returned;
    END IF;
END $$;
