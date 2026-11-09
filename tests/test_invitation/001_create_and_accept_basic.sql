set search_path = public, const, ext, stage, helpers, internal, unsecure, auth, triggers;

-- ============================================================================
-- TEST 1: Create invitation with inline actions and accept — database actions execute
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
BEGIN
    RAISE NOTICE 'TEST 1: Create invitation with database actions, accept, verify execution';

    SELECT val FROM _inv_test_data WHERE key = 'inviter_id' INTO __inviter_id;
    SELECT val FROM _inv_test_data WHERE key = 'target_id' INTO __target_id;
    SELECT val FROM _inv_test_data WHERE key = 'group_id' INTO __group_id;

    -- Create invitation with on_accept actions: add to tenant + add to group
    SELECT __invitation_id, __uuid, __on_create_actions
    FROM auth.create_invitation(
        'test_inv', __inviter_id, 'inv-corr-1', 1,
        'inv_target@test.com',
        _actions := ('[
            {"action_type_code": "add_tenant_user",  "phase_code": "on_accept", "sequence": 0, "condition_code": "user_not_in_tenant"},
            {"action_type_code": "add_group_member",  "phase_code": "on_accept", "sequence": 1, "payload": {"user_group_id": ' || __group_id || '}}
        ]')::jsonb,
        _message := 'Welcome aboard!'
    ) INTO __inv_id, __inv_uuid, __on_create;

    IF __inv_id IS NOT NULL AND __inv_uuid IS NOT NULL THEN
        RAISE NOTICE '  PASS: Invitation created (id=%, uuid=%)', __inv_id, __inv_uuid;
    ELSE
        RAISE EXCEPTION '  FAIL: Invitation creation returned nulls';
    END IF;

    -- No on_create actions => should be empty array
    IF __on_create = '[]'::jsonb THEN
        RAISE NOTICE '  PASS: No on_create actions returned (as expected)';
    ELSE
        RAISE EXCEPTION '  FAIL: Expected empty on_create actions, got %', __on_create;
    END IF;

    -- Verify invitation is pending
    SELECT count(*) FROM auth.invitation WHERE invitation_id = __inv_id AND status_code = 'pending' INTO __count;
    IF __count = 1 THEN
        RAISE NOTICE '  PASS: Invitation status is pending';
    ELSE
        RAISE EXCEPTION '  FAIL: Expected pending invitation, count=%', __count;
    END IF;

    -- Verify 2 actions created, both pending
    SELECT count(*) FROM auth.invitation_action WHERE invitation_id = __inv_id AND status_code = 'pending' INTO __count;
    IF __count = 2 THEN
        RAISE NOTICE '  PASS: 2 pending actions created';
    ELSE
        RAISE EXCEPTION '  FAIL: Expected 2 pending actions, got %', __count;
    END IF;

    -- Accept the invitation
    PERFORM auth.accept_invitation('test_inv', __inviter_id, 'inv-corr-2', (select uuid from auth.invitation where invitation_id = __inv_id), __target_id);

    -- Verify target user was added to tenant 1
    SELECT count(*) FROM auth.user_group_member ugm
    INNER JOIN auth.user_group ug ON ug.user_group_id = ugm.user_group_id
    WHERE ug.tenant_id = 1 AND ug.code = 'tenant_members' AND ugm.user_id = __target_id INTO __count;
    IF __count = 1 THEN
        RAISE NOTICE '  PASS: Target user added to tenant';
    ELSE
        RAISE EXCEPTION '  FAIL: Expected target in tenant, count=%', __count;
    END IF;

    -- Verify target user was added to group
    SELECT count(*) FROM auth.user_group_member WHERE user_group_id = __group_id AND user_id = __target_id INTO __count;
    IF __count = 1 THEN
        RAISE NOTICE '  PASS: Target user added to group';
    ELSE
        RAISE EXCEPTION '  FAIL: Expected target in group, count=%', __count;
    END IF;

    -- Verify all actions completed
    SELECT count(*) FROM auth.invitation_action WHERE invitation_id = __inv_id AND status_code = 'completed' INTO __count;
    IF __count = 2 THEN
        RAISE NOTICE '  PASS: All 2 actions completed';
    ELSE
        RAISE EXCEPTION '  FAIL: Expected 2 completed actions, got %', __count;
    END IF;

    -- Verify invitation is completed
    SELECT count(*) FROM auth.invitation WHERE invitation_id = __inv_id AND status_code = 'completed' INTO __count;
    IF __count = 1 THEN
        RAISE NOTICE '  PASS: Invitation status is completed';
    ELSE
        RAISE EXCEPTION '  FAIL: Expected completed invitation, count=%', __count;
    END IF;

    -- Store invitation id for later tests
    INSERT INTO _inv_test_data VALUES ('inv_id_1', __inv_id) ON CONFLICT (key) DO UPDATE SET val = EXCLUDED.val;

    RAISE NOTICE 'TEST 1: Done';
    RAISE NOTICE '';
END $$;
