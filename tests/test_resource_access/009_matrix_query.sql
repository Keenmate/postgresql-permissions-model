set search_path = public, const, ext, stage, helpers, internal, unsecure, auth, triggers;

-- ============================================================================
-- TEST 1: Matrix returns all sub-types with flags
-- ============================================================================
DO $$
DECLARE
    __user_id_1 bigint;
    __user_id_2 bigint;
    __count integer;
BEGIN
    RAISE NOTICE 'TEST 1: Matrix returns all sub-types with flags';

    SELECT val FROM _ra_test_data WHERE key = 'user_id_1' INTO __user_id_1;
    SELECT val FROM _ra_test_data WHERE key = 'user_id_2' INTO __user_id_2;

    -- User 2 has read on 'project' (from 008 TEST 2) for resource {"project_id": 1000}
    -- Matrix should show read inherited across all sub-types
    SELECT count(*)
    FROM auth.get_resource_access_matrix(__user_id_2, 'test-matrix-1', 'project', '{"project_id": 1000}'::jsonb)
    WHERE __access_flag = 'read'
    INTO __count;

    -- Should have read on project + project.documents (project.invoices is denied from 008 TEST 4)
    IF __count >= 2 THEN
        RAISE NOTICE '  PASS: Matrix returned read flag for >= 2 types (count=%)', __count;
    ELSE
        RAISE EXCEPTION '  FAIL: Expected >= 2 types with read flag, got %', __count;
    END IF;
END $$;

-- ============================================================================
-- TEST 2: Denied flags excluded from matrix
-- ============================================================================
DO $$
DECLARE
    __user_id_2 bigint;
    __count integer;
BEGIN
    RAISE NOTICE 'TEST 2: Denied flags excluded from matrix';

    SELECT val FROM _ra_test_data WHERE key = 'user_id_2' INTO __user_id_2;

    -- 008 TEST 4 denied one specific invoice; that does not deny "invoices of the
    -- project" (v2.13). Deny read on every invoice of project 1000 (partial key).
    PERFORM auth.deny_resource_access('test', 1, 'test-matrix-2', 'project.invoices',
        '{"project_id": 1000}'::jsonb, __user_id_2, array['read']);

    SELECT count(*)
    FROM auth.get_resource_access_matrix(__user_id_2, 'test-matrix-2', 'project', '{"project_id": 1000}'::jsonb)
    WHERE __resource_type = 'project.invoices' AND __access_flag = 'read'
    INTO __count;

    IF __count = 0 THEN
        RAISE NOTICE '  PASS: Denied flag excluded from matrix';
    ELSE
        RAISE EXCEPTION '  FAIL: Expected 0 (denied flag should be excluded), got %', __count;
    END IF;
END $$;

-- ============================================================================
-- TEST 3: System user gets full matrix
-- ============================================================================
DO $$
DECLARE
    __count integer;
    __expected integer;
BEGIN
    RAISE NOTICE 'TEST 3: System user gets full matrix';

    -- System user (id=1) should get ALL types × valid flags per type
    SELECT count(*)
    FROM auth.get_resource_access_matrix(1, 'test-matrix-3', 'project', '{"project_id": 9999}'::jsonb)
    INTO __count;

    -- Sum of per-type flag counts (project:4 + project.documents:4 + project.invoices:3 = 11)
    SELECT coalesce(sum(flag_count), 0)::integer
    FROM (
        SELECT rt.code,
            (SELECT count(*) FROM const.resource_type_flag rtf WHERE rtf.resource_type_code = rt.code) as flag_count
        FROM const.resource_type rt
        WHERE rt.path <@ 'project'::ext.ltree AND rt.is_active = true
    ) sub
    INTO __expected;

    IF __count = __expected THEN
        RAISE NOTICE '  PASS: System user gets full matrix (% entries)', __count;
    ELSE
        RAISE EXCEPTION '  FAIL: Expected % entries for system user, got %', __expected, __count;
    END IF;
END $$;

-- ============================================================================
-- TEST 4: Inherited + direct flags combined
-- ============================================================================
DO $$
DECLARE
    __user_id_1 bigint;
    __user_id_3 bigint;
    __count_total integer;
    __has_parent_read boolean;
    __has_child_write boolean;
BEGIN
    RAISE NOTICE 'TEST 4: Inherited + direct flags combined in matrix';

    SELECT val FROM _ra_test_data WHERE key = 'user_id_1' INTO __user_id_1;
    SELECT val FROM _ra_test_data WHERE key = 'user_id_3' INTO __user_id_3;

    -- Give user_3 read on parent project for resource {"project_id": 3000}
    PERFORM auth.assign_resource_access('test', __user_id_1, 'test-matrix-4a', 'project', '{"project_id": 3000}'::jsonb,
        _target_user_id := __user_id_3, _access_flags := array['read']);

    -- Give user_3 write on project.documents only for resource {"project_id": 3000, "folder_id": 1}
    PERFORM auth.assign_resource_access('test', __user_id_1, 'test-matrix-4b', 'project.documents',
        '{"project_id": 3000, "folder_id": 1}'::jsonb,
        _target_user_id := __user_id_3, _access_flags := array['write']);

    -- The matrix shows what applies to every resource of each type under the asked
    -- resource (v2.13). For project 3000:
    -- project: read (direct)
    -- project.documents: read (inherited from project); the write is for folder 1 only
    -- project.invoices: read (inherited from project)

    SELECT count(*)
    FROM auth.get_resource_access_matrix(__user_id_3, 'test-matrix-4', 'project', '{"project_id": 3000}'::jsonb)
    INTO __count_total;

    IF __count_total = 3 THEN
        RAISE NOTICE '  PASS: Matrix for the project has 3 entries (count=%)', __count_total;
    ELSE
        RAISE EXCEPTION '  FAIL: Expected 3 entries for the project, got %', __count_total;
    END IF;

    -- Project level: documents readable (inherited), not writable (folder 1 only)
    SELECT exists(
        SELECT 1 FROM auth.get_resource_access_matrix(__user_id_3, 'test-matrix-4', 'project', '{"project_id": 3000}'::jsonb)
        WHERE __resource_type = 'project.documents' AND __access_flag = 'read'
    ) INTO __has_parent_read;

    SELECT exists(
        SELECT 1 FROM auth.get_resource_access_matrix(__user_id_3, 'test-matrix-4', 'project', '{"project_id": 3000}'::jsonb)
        WHERE __resource_type = 'project.documents' AND __access_flag = 'write'
    ) INTO __has_child_write;

    IF __has_parent_read AND NOT __has_child_write THEN
        RAISE NOTICE '  PASS: project level: documents read inherited, write not (it is for folder 1 only)';
    ELSE
        RAISE EXCEPTION '  FAIL: project level documents flags wrong (read=%, write=%)', __has_parent_read, __has_child_write;
    END IF;

    -- Folder 1 level: documents writable and readable
    SELECT exists(
        SELECT 1 FROM auth.get_resource_access_matrix(__user_id_3, 'test-matrix-4', 'project.documents', '{"project_id": 3000, "folder_id": 1}'::jsonb)
        WHERE __resource_type = 'project.documents' AND __access_flag = 'write'
    ) INTO __has_child_write;

    IF __has_child_write THEN
        RAISE NOTICE '  PASS: folder 1 level: documents write';
    ELSE
        RAISE EXCEPTION '  FAIL: folder 1 level: documents write missing';
    END IF;
END $$;
