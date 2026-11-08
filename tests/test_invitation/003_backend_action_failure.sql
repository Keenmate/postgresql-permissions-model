set search_path = public, const, ext, stage, helpers, internal, unsecure, auth, triggers;

-- ============================================================================
-- TEST 3: Backend simulates a REQUIRED on_create action failure
--          — invitation should fail, later-sequence actions skipped
-- ============================================================================
DO $$
DECLARE
    __inviter_id bigint;
    __group_id integer;
    __inv_id bigint;
    __inv_uuid uuid;
    __on_create jsonb;
    __sms_action_id bigint;
    __status text;
    __count integer;
BEGIN
    RAISE NOTICE 'TEST 3: Backend required action failure — invitation fails';

    SELECT val FROM _inv_test_data WHERE key = 'inviter_id' INTO __inviter_id;
    SELECT val FROM _inv_test_data WHERE key = 'group_id' INTO __group_id;

    -- Create invitation: on_create SMS (required, seq 0) + on_accept group add (seq 1)
    SELECT __invitation_id, __uuid, __on_create_actions
    FROM auth.create_invitation(
        'svc_app', __inviter_id, 'inv-corr-fail-1', 1,
        '+420999888777',
        _actions := ('[
            {"action_type_code": "send_sms_invite", "phase_code": "on_create", "sequence": 0, "is_required": true},
            {"action_type_code": "add_group_member", "phase_code": "on_accept", "sequence": 1, "payload": {"user_group_id": ' || __group_id || '}}
        ]')::jsonb,
        _message := 'This will fail'
    ) INTO __inv_id, __inv_uuid, __on_create;

    -- Extract the SMS action
    __sms_action_id := (__on_create->0->>'invitation_action_id')::bigint;

    IF __sms_action_id IS NOT NULL THEN
        RAISE NOTICE '  PASS: SMS action returned (id=%)', __sms_action_id;
    ELSE
        RAISE EXCEPTION '  FAIL: No on_create action returned';
    END IF;

    -- Backend fails to send SMS
    PERFORM unsecure.fail_invitation_action('svc_app', __inviter_id, 'inv-corr-fail-2',
        __sms_action_id, 'SMS gateway timeout: provider unreachable');

    -- Verify SMS action is failed with error message
    SELECT status_code FROM auth.invitation_action WHERE invitation_action_id = __sms_action_id INTO __status;
    IF __status = 'failed' THEN
        RAISE NOTICE '  PASS: SMS action marked as failed';
    ELSE
        RAISE EXCEPTION '  FAIL: Expected failed, got %', __status;
    END IF;

    SELECT count(*) FROM auth.invitation_action
    WHERE invitation_action_id = __sms_action_id
      AND error_message = 'SMS gateway timeout: provider unreachable'
    INTO __count;
    IF __count = 1 THEN
        RAISE NOTICE '  PASS: Error message stored correctly';
    ELSE
        RAISE EXCEPTION '  FAIL: Error message not found';
    END IF;

    -- Since the SMS action was required, invitation should be failed
    SELECT status_code FROM auth.invitation WHERE invitation_id = __inv_id INTO __status;
    IF __status = 'failed' THEN
        RAISE NOTICE '  PASS: Invitation status is failed (required action failed)';
    ELSE
        RAISE EXCEPTION '  FAIL: Expected failed invitation, got %', __status;
    END IF;

    RAISE NOTICE 'TEST 3: Done';
    RAISE NOTICE '';
END $$;

-- ============================================================================
-- TEST 4: Backend simulates a NON-REQUIRED on_create action failure
--          — invitation stays pending, can still be accepted
-- ============================================================================
DO $$
DECLARE
    __inviter_id bigint;
    __target_id bigint;
    __group_id integer;
    __inv_id bigint;
    __inv_uuid uuid;
    __on_create jsonb;
    __sms_action_id bigint;
    __status text;
    __count integer;
BEGIN
    RAISE NOTICE 'TEST 4: Backend non-required action failure — invitation continues';

    SELECT val FROM _inv_test_data WHERE key = 'inviter_id' INTO __inviter_id;
    SELECT val FROM _inv_test_data WHERE key = 'target_id' INTO __target_id;
    SELECT val FROM _inv_test_data WHERE key = 'group_id' INTO __group_id;

    -- Create invitation: on_create SMS (NOT required) + on_accept group add
    SELECT __invitation_id, __uuid, __on_create_actions
    FROM auth.create_invitation(
        'svc_app', __inviter_id, 'inv-corr-opt-1', 1,
        '+420111222333',
        _actions := ('[
            {"action_type_code": "send_sms_invite", "phase_code": "on_create", "sequence": 0, "is_required": false},
            {"action_type_code": "add_group_member", "phase_code": "on_accept", "sequence": 0,
             "condition_code": "user_not_in_group", "payload": {"user_group_id": ' || __group_id || '}}
        ]')::jsonb,
        _message := 'SMS optional'
    ) INTO __inv_id, __inv_uuid, __on_create;

    __sms_action_id := (__on_create->0->>'invitation_action_id')::bigint;

    -- Backend fails the SMS — but it's not required
    PERFORM unsecure.fail_invitation_action('svc_app', __inviter_id, 'inv-corr-opt-2',
        __sms_action_id, 'SMS provider down');

    -- Invitation should still be pending (non-required failure doesn't kill it)
    SELECT status_code FROM auth.invitation WHERE invitation_id = __inv_id INTO __status;
    IF __status = 'pending' THEN
        RAISE NOTICE '  PASS: Invitation still pending after non-required action failure';
    ELSE
        RAISE EXCEPTION '  FAIL: Expected pending, got %', __status;
    END IF;

    -- Now accept the invitation — on_accept actions should still work
    PERFORM auth.accept_invitation('svc_app', __inviter_id, 'inv-corr-opt-3', (select uuid from auth.invitation where invitation_id = __inv_id), __target_id);

    -- Verify target was added to group
    SELECT count(*) FROM auth.user_group_member WHERE user_group_id = __group_id AND user_id = __target_id INTO __count;
    IF __count >= 1 THEN
        RAISE NOTICE '  PASS: Target added to group despite earlier SMS failure';
    ELSE
        RAISE EXCEPTION '  FAIL: Expected target in group, count=%', __count;
    END IF;

    -- Verify invitation completed (SMS failed but was optional, group add succeeded)
    SELECT status_code FROM auth.invitation WHERE invitation_id = __inv_id INTO __status;
    IF __status = 'completed' THEN
        RAISE NOTICE '  PASS: Invitation completed (non-required failure + successful accept)';
    ELSE
        RAISE EXCEPTION '  FAIL: Expected completed, got %', __status;
    END IF;

    RAISE NOTICE 'TEST 4: Done';
    RAISE NOTICE '';
END $$;
