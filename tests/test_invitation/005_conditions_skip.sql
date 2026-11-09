set search_path = public, const, ext, stage, helpers, internal, unsecure, auth, triggers;

-- ============================================================================
-- TEST 6: Condition evaluation — user_not_in_tenant skips when already member
-- ============================================================================
DO $$
DECLARE
    __inviter_id bigint;
    __target_id bigint;
    __group_id integer;
    __inv_id bigint;
    __inv_uuid uuid;
    __on_create jsonb;
    __count integer;
    __status text;
BEGIN
    RAISE NOTICE 'TEST 6: Condition skip — user already in tenant';

    SELECT val FROM _inv_test_data WHERE key = 'inviter_id' INTO __inviter_id;
    SELECT val FROM _inv_test_data WHERE key = 'target_id' INTO __target_id;
    SELECT val FROM _inv_test_data WHERE key = 'group_id' INTO __group_id;

    -- Ensure target is already in tenant 1 (membership is computed: a group of tenant 1)
    INSERT INTO auth.user_group_member (created_by, user_group_id, user_id, member_type_code)
    SELECT 'test_inv', ug.user_group_id, __target_id, 'manual'
    FROM auth.user_group ug WHERE ug.tenant_id = 1 AND ug.code = 'tenant_members'
    ON CONFLICT DO NOTHING;

    -- Create invitation with condition: add_tenant_user only if NOT in tenant
    SELECT __invitation_id, __uuid, __on_create_actions
    FROM auth.create_invitation(
        'svc_app', __inviter_id, 'inv-corr-cond-1', 1,
        'inv_target@test.com',
        _actions := ('[
            {"action_type_code": "add_tenant_user",  "phase_code": "on_accept", "sequence": 0,
             "condition_code": "user_not_in_tenant"},
            {"action_type_code": "add_group_member",  "phase_code": "on_accept", "sequence": 1,
             "condition_code": "user_not_in_group", "payload": {"user_group_id": ' || __group_id || '}}
        ]')::jsonb
    ) INTO __inv_id, __inv_uuid, __on_create;

    -- Accept
    PERFORM auth.accept_invitation('svc_app', __inviter_id, 'inv-corr-cond-2', (select uuid from auth.invitation where invitation_id = __inv_id), __target_id);

    -- add_tenant_user should have been SKIPPED (user already in tenant)
    SELECT status_code FROM auth.invitation_action
    WHERE invitation_id = __inv_id AND action_type_code = 'add_tenant_user'
    INTO __status;
    IF __status = 'skipped' THEN
        RAISE NOTICE '  PASS: add_tenant_user skipped (user already in tenant)';
    ELSE
        RAISE EXCEPTION '  FAIL: Expected skipped, got %', __status;
    END IF;

    -- add_group_member should have COMPLETED (user not yet in group — unless added by test 1/4)
    -- We check it ran (completed or skipped based on prior test state)
    SELECT status_code FROM auth.invitation_action
    WHERE invitation_id = __inv_id AND action_type_code = 'add_group_member'
    INTO __status;
    IF __status IN ('completed', 'skipped') THEN
        RAISE NOTICE '  PASS: add_group_member status=% (condition evaluated)', __status;
    ELSE
        RAISE EXCEPTION '  FAIL: Expected completed or skipped, got %', __status;
    END IF;

    -- Invitation should be completed
    SELECT status_code FROM auth.invitation WHERE invitation_id = __inv_id INTO __status;
    IF __status = 'completed' THEN
        RAISE NOTICE '  PASS: Invitation completed';
    ELSE
        RAISE EXCEPTION '  FAIL: Expected completed, got %', __status;
    END IF;

    RAISE NOTICE 'TEST 6: Done';
    RAISE NOTICE '';
END $$;
