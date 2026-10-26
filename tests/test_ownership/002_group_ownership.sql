set search_path = public, const, ext, stage, helpers, internal, unsecure, auth, triggers;

-- ============================================================================
-- TEST 10: create_owner assigns group owner
-- ============================================================================
DO $$
DECLARE
    __admin_user_id bigint := current_setting('test_own.admin_user_id')::bigint;
    __test_user_id bigint := current_setting('test_own.test_user_id')::bigint;
    __tenant_id integer := current_setting('test_own.tenant_id')::integer;
    __group_id integer := current_setting('test_own.group_id')::integer;
    __owner_id bigint;
BEGIN
    RAISE NOTICE 'TEST 10: create_owner assigns group owner';

    SELECT o.__owner_id
    FROM auth.create_owner('test_own', __admin_user_id, 'own-corr-4', __test_user_id, __group_id, __tenant_id) o
    INTO __owner_id;

    IF __owner_id IS NULL THEN
        RAISE EXCEPTION '  FAIL: create_owner returned NULL owner_id for group owner';
    END IF;

    RAISE NOTICE '  PASS: group owner created (owner_id=%)', __owner_id;
END $$;

-- ============================================================================
-- TEST 11: is_owner returns true for group owner
-- ============================================================================
DO $$
DECLARE
    __test_user_id bigint := current_setting('test_own.test_user_id')::bigint;
    __tenant_id integer := current_setting('test_own.tenant_id')::integer;
    __group_id integer := current_setting('test_own.group_id')::integer;
    __result boolean;
BEGIN
    RAISE NOTICE 'TEST 11: is_owner returns true for group owner';

    SELECT auth.is_owner(__test_user_id, 'own-corr-5', __group_id, __tenant_id) INTO __result;

    IF __result = true THEN
        RAISE NOTICE '  PASS: is_owner returned true for group owner';
    ELSE
        RAISE EXCEPTION '  FAIL: is_owner returned false, expected true';
    END IF;
END $$;

-- ============================================================================
-- TEST 12: a group owner is NOT a tenant-wide owner (null group_id = tenant-wide only)
-- ============================================================================
DO $$
DECLARE
    __test_user_id bigint := current_setting('test_own.test_user_id')::bigint;
    __tenant_id integer := current_setting('test_own.tenant_id')::integer;
    __result boolean;
BEGIN
    RAISE NOTICE 'TEST 12: is_owner with NULL group_id does not match a group-only owner';

    -- User owns only a group here. A null group asks "tenant-wide owner?", which
    -- auth.has_permissions treats as "passes every check" — it must be false.
    SELECT auth.is_owner(__test_user_id, 'own-corr-6', null, __tenant_id) INTO __result;

    IF __result = false THEN
        RAISE NOTICE '  PASS: is_owner with null group_id returns false for a group-only owner';
    ELSE
        RAISE EXCEPTION '  FAIL: is_owner returned true — a group owner was treated as tenant-wide owner';
    END IF;
END $$;

-- ============================================================================
-- TEST 13: has_owner returns true for group with owner
-- ============================================================================
DO $$
DECLARE
    __tenant_id integer := current_setting('test_own.tenant_id')::integer;
    __group_id integer := current_setting('test_own.group_id')::integer;
    __result boolean;
BEGIN
    RAISE NOTICE 'TEST 13: has_owner returns true for group with owner';

    SELECT auth.has_owner(__group_id, __tenant_id) INTO __result;

    IF __result = true THEN
        RAISE NOTICE '  PASS: has_owner returned true for group';
    ELSE
        RAISE EXCEPTION '  FAIL: has_owner returned false, expected true';
    END IF;
END $$;

-- ============================================================================
-- TEST 14: create_owner journals event 11010 for group owner
-- ============================================================================
DO $$
DECLARE
    __group_id integer := current_setting('test_own.group_id')::integer;
    __journal_payload jsonb;
BEGIN
    RAISE NOTICE 'TEST 14: create_owner journals event 11010 for group owner';

    SELECT j.data_payload
    FROM public.journal j
    WHERE j.event_id = 11010
      AND j.created_by = 'test_own'
      AND j.correlation_id = 'own-corr-4'
    ORDER BY j.created_at DESC
    LIMIT 1
    INTO __journal_payload;

    IF __journal_payload IS NULL THEN
        RAISE EXCEPTION '  FAIL: No journal entry found for group owner event 11010';
    END IF;

    IF __journal_payload->>'action' = 'owner_added'
       AND (__journal_payload->>'user_group_id')::int = __group_id THEN
        RAISE NOTICE '  PASS: journal entry found with action=owner_added and group_id=%, payload=%', __group_id, __journal_payload;
    ELSE
        RAISE EXCEPTION '  FAIL: journal mismatch, payload=%', __journal_payload;
    END IF;
END $$;

-- ============================================================================
-- TEST 15: delete_owner removes group owner and journals event 11011
-- ============================================================================
DO $$
DECLARE
    __admin_user_id bigint := current_setting('test_own.admin_user_id')::bigint;
    __test_user_id bigint := current_setting('test_own.test_user_id')::bigint;
    __tenant_id integer := current_setting('test_own.tenant_id')::integer;
    __group_id integer := current_setting('test_own.group_id')::integer;
    __result boolean;
    __journal_payload jsonb;
BEGIN
    RAISE NOTICE 'TEST 15: delete_owner removes group owner and journals 11011';

    PERFORM auth.delete_owner('test_own', __admin_user_id, 'own-corr-7', __test_user_id, __group_id, __tenant_id);

    SELECT auth.is_owner(__test_user_id, 'own-corr-8', __group_id, __tenant_id) INTO __result;

    IF __result = true THEN
        RAISE EXCEPTION '  FAIL: is_owner still true after delete_owner';
    END IF;

    SELECT j.data_payload
    FROM public.journal j
    WHERE j.event_id = 11011
      AND j.created_by = 'test_own'
      AND j.correlation_id = 'own-corr-7'
    ORDER BY j.created_at DESC
    LIMIT 1
    INTO __journal_payload;

    IF __journal_payload IS NOT NULL THEN
        RAISE NOTICE '  PASS: group owner removed and journal entry found, payload=%', __journal_payload;
    ELSE
        RAISE EXCEPTION '  FAIL: delete_owner journal entry missing';
    END IF;
END $$;

-- ============================================================================
-- TEST 16: has_owner returns false after group owner removed
-- ============================================================================
DO $$
DECLARE
    __tenant_id integer := current_setting('test_own.tenant_id')::integer;
    __group_id integer := current_setting('test_own.group_id')::integer;
    __result boolean;
BEGIN
    RAISE NOTICE 'TEST 16: has_owner returns false after group owner removed';

    SELECT auth.has_owner(__group_id, __tenant_id) INTO __result;

    IF __result = false THEN
        RAISE NOTICE '  PASS: has_owner returned false for group without owners';
    ELSE
        RAISE EXCEPTION '  FAIL: has_owner returned true, expected false';
    END IF;
END $$;
