set search_path = public, const, ext, stage, helpers, internal, unsecure, auth, triggers;

-- ============================================================================
-- TEST 5: Reject invitation — on_accept skipped, on_reject fires
-- ============================================================================
DO $$
DECLARE
    __inviter_id bigint;
    __inv_id bigint;
    __inv_uuid uuid;
    __on_create jsonb;
    __reject_actions record;
    __action_id bigint;
    ___payload jsonb;
    __status text;
    __count integer;
BEGIN
    RAISE NOTICE 'TEST 5: Reject invitation — on_reject notifies inviter';

    SELECT val FROM _inv_test_data WHERE key = 'inviter_id' INTO __inviter_id;

    -- Create invitation with on_accept + on_reject actions
    SELECT __invitation_id, __uuid, __on_create_actions
    FROM auth.create_invitation(
        'svc_app', __inviter_id, 'inv-corr-rej-1', 1,
        'someone@external.com',
        _actions := '[
            {"action_type_code": "add_tenant_user", "phase_code": "on_accept", "sequence": 0},
            {"action_type_code": "notify_inviter",  "phase_code": "on_reject", "sequence": 0}
        ]'::jsonb,
        _message := 'Please join us'
    ) INTO __inv_id, __inv_uuid, __on_create;

    RAISE NOTICE '  INFO: Invitation created (id=%)', __inv_id;

    -- Reject the invitation
    SELECT __invitation_action_id, __action_type_code, __executor_code, __payload
    FROM auth.reject_invitation('svc_app', __inviter_id, 'inv-corr-rej-2', (select uuid from auth.invitation where invitation_id = __inv_id))
    INTO __action_id, __status, __status, ___payload;

    -- Verify on_reject returned the notify_inviter action
    IF __action_id IS NOT NULL THEN
        RAISE NOTICE '  PASS: on_reject returned notify_inviter action (id=%)', __action_id;
    ELSE
        RAISE EXCEPTION '  FAIL: Expected on_reject action to be returned';
    END IF;

    -- Verify the payload has inviter info resolved from schema
    IF (___payload->>'inviter_user_id')::bigint = __inviter_id THEN
        RAISE NOTICE '  PASS: Payload inviter_user_id resolved correctly';
    ELSE
        RAISE EXCEPTION '  FAIL: Expected inviter_user_id=%, got %', __inviter_id, ___payload->>'inviter_user_id';
    END IF;

    IF ___payload->>'target_email' = 'someone@external.com' THEN
        RAISE NOTICE '  PASS: Payload target_email resolved correctly';
    ELSE
        RAISE EXCEPTION '  FAIL: Expected target_email=someone@external.com, got %', ___payload->>'target_email';
    END IF;

    -- Verify on_accept action was skipped
    SELECT count(*) FROM auth.invitation_action
    WHERE invitation_id = __inv_id AND phase_code = 'on_accept' AND status_code = 'skipped'
    INTO __count;
    IF __count = 1 THEN
        RAISE NOTICE '  PASS: on_accept action was skipped';
    ELSE
        RAISE EXCEPTION '  FAIL: Expected 1 skipped on_accept action, got %', __count;
    END IF;

    -- Verify invitation is rejected
    SELECT status_code FROM auth.invitation WHERE invitation_id = __inv_id INTO __status;
    IF __status = 'rejected' THEN
        RAISE NOTICE '  PASS: Invitation status is rejected';
    ELSE
        RAISE EXCEPTION '  FAIL: Expected rejected, got %', __status;
    END IF;

    -- Backend handles the notification, reports success
    PERFORM unsecure.complete_invitation_action('svc_app', __inviter_id, 'inv-corr-rej-3', __action_id);

    SELECT status_code FROM auth.invitation_action WHERE invitation_action_id = __action_id INTO __status;
    IF __status = 'completed' THEN
        RAISE NOTICE '  PASS: notify_inviter action completed';
    ELSE
        RAISE EXCEPTION '  FAIL: Expected completed, got %', __status;
    END IF;

    RAISE NOTICE 'TEST 5: Done';
    RAISE NOTICE '';
END $$;
