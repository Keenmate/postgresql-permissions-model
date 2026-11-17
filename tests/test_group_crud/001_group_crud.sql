set search_path = public, const, ext, stage, helpers, internal, unsecure, auth, triggers;

-- ============================================================================
-- TEST 1: auth.create_user_group creates a group
-- ============================================================================
DO $$
DECLARE
    __user_id bigint := current_setting('test_gc.user_id')::bigint;
    __group_id int;
    __db_code text;
    __db_active boolean;
BEGIN
    RAISE NOTICE 'TEST 1: auth.create_user_group - create group';

    SELECT g.__user_group_id
    FROM auth.create_user_group('grp_crud_test', __user_id, 'gc-corr-1', 'GC Test Group') g
    INTO __group_id;

    IF __group_id IS NULL THEN
        RAISE EXCEPTION '  FAIL: create_user_group returned NULL';
    END IF;

    SELECT code, is_active
    FROM auth.user_group
    WHERE user_group_id = __group_id
    INTO __db_code, __db_active;

    IF __db_code IS NOT NULL AND __db_active = true THEN
        PERFORM set_config('test_gc.group_id', __group_id::text, false);
        PERFORM set_config('test_gc.group_code', __db_code, false);
        RAISE NOTICE '  PASS: group created (id=%, code=%, active=%)', __group_id, __db_code, __db_active;
    ELSE
        RAISE EXCEPTION '  FAIL: group data mismatch (code=%, active=%)', __db_code, __db_active;
    END IF;
END $$;

-- ============================================================================
-- TEST 2: auth.update_user_group updates group fields
-- ============================================================================
DO $$
DECLARE
    __user_id bigint := current_setting('test_gc.user_id')::bigint;
    __group_id int := current_setting('test_gc.group_id')::int;
    __result_id int;
    __db_title text;
BEGIN
    RAISE NOTICE 'TEST 2: auth.update_user_group - update group title';

    SELECT g.__user_group_id
    FROM auth.update_user_group('grp_crud_test', __user_id, 'gc-corr-2',
        __group_id, 'GC Test Group Updated', true, true, false) g
    INTO __result_id;

    SELECT title INTO __db_title FROM auth.user_group WHERE user_group_id = __group_id;

    IF __result_id = __group_id AND __db_title = 'GC Test Group Updated' THEN
        RAISE NOTICE '  PASS: group updated (id=%, title=%)', __result_id, __db_title;
    ELSE
        RAISE EXCEPTION '  FAIL: update mismatch (result_id=%, title=%)', __result_id, __db_title;
    END IF;
END $$;

-- ============================================================================
-- TEST 3: auth.create_user_group_member adds member to group
-- ============================================================================
DO $$
DECLARE
    __user_id bigint := current_setting('test_gc.user_id')::bigint;
    __target_id bigint := current_setting('test_gc.target_id')::bigint;
    __group_id int := current_setting('test_gc.group_id')::int;
    __member_id bigint;
BEGIN
    RAISE NOTICE 'TEST 3: auth.create_user_group_member - add member';

    SELECT m.__user_group_member_id
    FROM auth.create_user_group_member('grp_crud_test', __user_id, 'gc-corr-3', __group_id, __target_id) m
    INTO __member_id;

    IF __member_id IS NOT NULL THEN
        RAISE NOTICE '  PASS: member added (member_id=%)', __member_id;
    ELSE
        RAISE EXCEPTION '  FAIL: create_user_group_member returned NULL';
    END IF;
END $$;

-- ============================================================================
-- TEST 4: auth.delete_user_group_member removes member from group
-- ============================================================================
DO $$
DECLARE
    __user_id bigint := current_setting('test_gc.user_id')::bigint;
    __target_id bigint := current_setting('test_gc.target_id')::bigint;
    __group_id int := current_setting('test_gc.group_id')::int;
    __still_member boolean;
BEGIN
    RAISE NOTICE 'TEST 4: auth.delete_user_group_member - remove member';

    PERFORM auth.delete_user_group_member('grp_crud_test', __user_id, 'gc-corr-4', __group_id, __target_id);

    SELECT exists(
        SELECT FROM auth.user_group_member
        WHERE user_group_id = __group_id AND user_id = __target_id
    ) INTO __still_member;

    IF NOT __still_member THEN
        RAISE NOTICE '  PASS: member removed from group';
    ELSE
        RAISE EXCEPTION '  FAIL: member still exists in group after delete';
    END IF;
END $$;

-- ============================================================================
-- TEST 5: auth.create_user_group_mapping + auth.delete_user_group_mapping
-- ============================================================================
DO $$
DECLARE
    __user_id bigint := current_setting('test_gc.user_id')::bigint;
    __group_id int := current_setting('test_gc.group_id')::int;
    __mapping_id int;
    __still_exists boolean;
BEGIN
    RAISE NOTICE 'TEST 5: auth.delete_user_group_mapping - create then delete mapping';

    -- Create mapping first
    SELECT m.__user_group_mapping_id
    FROM auth.create_user_group_mapping('grp_crud_test', __user_id, 'gc-corr-5',
        __group_id, 'grp_crud_prov', 'test-object-id', 'Test Mapping') m
    INTO __mapping_id;

    IF __mapping_id IS NULL THEN
        RAISE EXCEPTION '  FAIL: create_user_group_mapping returned NULL';
    END IF;

    -- Delete it
    PERFORM auth.delete_user_group_mapping('grp_crud_test', __user_id, 'gc-corr-5', __mapping_id);

    SELECT exists(
        SELECT FROM auth.user_group_mapping WHERE user_group_mapping_id = __mapping_id
    ) INTO __still_exists;

    IF NOT __still_exists THEN
        RAISE NOTICE '  PASS: mapping created (id=%) and then deleted', __mapping_id;
    ELSE
        RAISE EXCEPTION '  FAIL: mapping still exists after delete (id=%)', __mapping_id;
    END IF;
END $$;

-- ============================================================================
-- TEST 6: auth.delete_user_group deletes a non-system group
-- ============================================================================
DO $$
DECLARE
    __user_id bigint := current_setting('test_gc.user_id')::bigint;
    __group_id int;
    __result_id int;
    __still_exists boolean;
BEGIN
    RAISE NOTICE 'TEST 6: auth.delete_user_group - delete group';

    -- Create a throwaway group to delete
    SELECT g.__user_group_id
    FROM auth.create_user_group('grp_crud_test', __user_id, 'gc-corr-6a', 'GC Delete Me Group') g
    INTO __group_id;

    SELECT g.__user_group_id
    FROM auth.delete_user_group('grp_crud_test', __user_id, 'gc-corr-6b', __group_id) g
    INTO __result_id;

    SELECT exists(SELECT FROM auth.user_group WHERE user_group_id = __group_id)
    INTO __still_exists;

    IF __result_id = __group_id AND NOT __still_exists THEN
        RAISE NOTICE '  PASS: group deleted (id=%)', __group_id;
    ELSE
        RAISE EXCEPTION '  FAIL: delete mismatch (result=%, still_exists=%)', __result_id, __still_exists;
    END IF;
END $$;
