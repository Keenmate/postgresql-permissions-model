set search_path = public, const, ext, stage, helpers, internal, unsecure, auth, triggers;

-- ============================================================================
-- TEST 8: Revoke invitation — all actions skipped
-- ============================================================================
DO $$
DECLARE
    __inviter_id bigint;
    __inv_id bigint;
    __inv_uuid uuid;
    __on_create jsonb;
    __status text;
    __count integer;
BEGIN
    RAISE NOTICE 'TEST 8: Revoke invitation';

    SELECT val FROM _inv_test_data WHERE key = 'inviter_id' INTO __inviter_id;

    SELECT __invitation_id, __uuid, __on_create_actions
    FROM auth.create_invitation(
        'svc_app', __inviter_id, 'inv-corr-rev-1', 1,
        'revoke_me@test.com',
        _actions := '[
            {"action_type_code": "add_tenant_user", "phase_code": "on_accept", "sequence": 0},
            {"action_type_code": "notify_inviter",  "phase_code": "on_reject", "sequence": 0}
        ]'::jsonb
    ) INTO __inv_id, __inv_uuid, __on_create;

    -- Revoke
    PERFORM auth.revoke_invitation('svc_app', __inviter_id, 'inv-corr-rev-2', __inv_id);

    -- Verify invitation is revoked
    SELECT status_code FROM auth.invitation WHERE invitation_id = __inv_id INTO __status;
    IF __status = 'revoked' THEN
        RAISE NOTICE '  PASS: Invitation status is revoked';
    ELSE
        RAISE EXCEPTION '  FAIL: Expected revoked, got %', __status;
    END IF;

    -- All actions should be skipped
    SELECT count(*) FROM auth.invitation_action WHERE invitation_id = __inv_id AND status_code = 'skipped' INTO __count;
    IF __count = 2 THEN
        RAISE NOTICE '  PASS: All 2 actions skipped';
    ELSE
        RAISE EXCEPTION '  FAIL: Expected 2 skipped actions, got %', __count;
    END IF;

    RAISE NOTICE 'TEST 8: Done';
    RAISE NOTICE '';
END $$;

-- ============================================================================
-- TEST 9: Accept expired invitation — should error
-- ============================================================================
DO $$
DECLARE
    __inviter_id bigint;
    __target_id bigint;
    __inv_id bigint;
    __inv_uuid uuid;
    __on_create jsonb;
    __caught boolean := false;
BEGIN
    RAISE NOTICE 'TEST 9: Accept expired invitation fails with error';

    SELECT val FROM _inv_test_data WHERE key = 'inviter_id' INTO __inviter_id;
    SELECT val FROM _inv_test_data WHERE key = 'target_id' INTO __target_id;

    -- Create invitation that already expired (1 second ago)
    SELECT __invitation_id, __uuid, __on_create_actions
    FROM auth.create_invitation(
        'svc_app', __inviter_id, 'inv-corr-exp-1', 1,
        'expired@test.com',
        _expires_at := now() - interval '1 second'
    ) INTO __inv_id, __inv_uuid, __on_create;

    -- Try to accept — should fail with 39003 (expired)
    BEGIN
        PERFORM auth.accept_invitation('svc_app', __inviter_id, 'inv-corr-exp-2', (select uuid from auth.invitation where invitation_id = __inv_id), __target_id);
    EXCEPTION WHEN OTHERS THEN
        IF SQLSTATE = '39003' THEN
            __caught := true;
        ELSE
            RAISE EXCEPTION '  FAIL: Expected error 39003, got % - %', SQLSTATE, SQLERRM;
        END IF;
    END;

    IF __caught THEN
        RAISE NOTICE '  PASS: Expired invitation raises error 39003';
    ELSE
        RAISE EXCEPTION '  FAIL: Expected error 39003, but no exception raised';
    END IF;

    RAISE NOTICE 'TEST 9: Done';
    RAISE NOTICE '';
END $$;

-- ============================================================================
-- TEST 10: Cannot accept already-rejected invitation
-- ============================================================================
DO $$
DECLARE
    __inviter_id bigint;
    __target_id bigint;
    __inv_id bigint;
    __inv_uuid uuid;
    __on_create jsonb;
    __caught boolean := false;
BEGIN
    RAISE NOTICE 'TEST 10: Cannot accept already-rejected invitation';

    SELECT val FROM _inv_test_data WHERE key = 'inviter_id' INTO __inviter_id;
    SELECT val FROM _inv_test_data WHERE key = 'target_id' INTO __target_id;

    SELECT __invitation_id, __uuid, __on_create_actions
    FROM auth.create_invitation(
        'svc_app', __inviter_id, 'inv-corr-dbl-1', 1,
        'double@test.com'
    ) INTO __inv_id, __inv_uuid, __on_create;

    -- Reject first
    PERFORM auth.reject_invitation('svc_app', __inviter_id, 'inv-corr-dbl-2', (select uuid from auth.invitation where invitation_id = __inv_id));

    -- Try to accept — should fail with 39002 (not pending)
    BEGIN
        PERFORM auth.accept_invitation('svc_app', __inviter_id, 'inv-corr-dbl-3', (select uuid from auth.invitation where invitation_id = __inv_id), __target_id);
    EXCEPTION WHEN OTHERS THEN
        IF SQLSTATE = '39002' THEN
            __caught := true;
        ELSE
            RAISE EXCEPTION '  FAIL: Expected error 39002, got % - %', SQLSTATE, SQLERRM;
        END IF;
    END;

    IF __caught THEN
        RAISE NOTICE '  PASS: Already-rejected invitation raises error 39002';
    ELSE
        RAISE EXCEPTION '  FAIL: Expected error 39002, but no exception raised';
    END IF;

    RAISE NOTICE 'TEST 10: Done';
    RAISE NOTICE '';
END $$;
