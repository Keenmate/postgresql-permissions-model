set search_path = public, const, ext, stage, helpers, internal, unsecure, auth, triggers;

-- ============================================================================
-- TEST 13: Full end-to-end SMS flow — the "invite unregistered user" story
--
-- 1. Backend creates invitation from template for unregistered user
-- 2. on_create: send_sms_invite returned to backend
-- 3. Backend sends SMS, reports success
-- 4. User registers (simulated by creating a new user_info)
-- 5. Backend accepts invitation with new user_id
-- 6. on_accept: add_tenant_user + add_group_member execute (conditions evaluated)
-- 7. Invitation completed
-- ============================================================================
DO $$
DECLARE
    __inviter_id bigint;
    __group_id integer;
    __tmpl_id integer;
    __inv_id bigint;
    __inv_uuid uuid;
    __on_create jsonb;
    __sms_action_id bigint;
    __sms_payload jsonb;
    __new_user_id bigint;
    __accept_result record;
    __pending_count integer;
    __status text;
    __count integer;
BEGIN
    RAISE NOTICE 'TEST 13: Full end-to-end SMS invitation flow for unregistered user';

    SELECT val FROM _inv_test_data WHERE key = 'inviter_id' INTO __inviter_id;
    SELECT val FROM _inv_test_data WHERE key = 'group_id' INTO __group_id;

    -- Reuse template from test 7 if available, or check it exists
    SELECT val FROM _inv_test_data WHERE key = 'tmpl_id' INTO __tmpl_id;
    IF __tmpl_id IS NULL THEN
        RAISE EXCEPTION '  FAIL: Template not found (test 7 must run first)';
    END IF;

    -- Step 1: Backend creates invitation from template for new phone number
    RAISE NOTICE '  Step 1: Creating invitation from template...';
    SELECT __invitation_id, __uuid, __on_create_actions
    FROM auth.create_invitation_from_template(
        'svc_app', __inviter_id, 'inv-corr-e2e-1', 1,
        'sms_group_invite',
        '+420111999888',
        _payload_overrides := ('{"user_group_id": ' || __group_id || '}')::jsonb
    ) INTO __inv_id, __inv_uuid, __on_create;

    IF __inv_id IS NOT NULL THEN
        RAISE NOTICE '    PASS: Invitation created (id=%, uuid=%)', __inv_id, __inv_uuid;
    ELSE
        RAISE EXCEPTION '    FAIL: Invitation not created';
    END IF;

    -- Step 2: Backend receives SMS action
    RAISE NOTICE '  Step 2: Verifying on_create returned SMS action...';
    IF jsonb_array_length(__on_create) = 1 THEN
        __sms_action_id := (__on_create->0->>'invitation_action_id')::bigint;
        __sms_payload := __on_create->0->'payload';
        RAISE NOTICE '    PASS: SMS action (id=%) with phone=%', __sms_action_id, __sms_payload->>'mobile_phone';
    ELSE
        RAISE EXCEPTION '    FAIL: Expected 1 on_create action, got %', jsonb_array_length(__on_create);
    END IF;

    -- Step 3: Backend sends SMS and reports success
    RAISE NOTICE '  Step 3: Backend reports SMS sent...';
    PERFORM unsecure.complete_invitation_action('svc_app', __inviter_id, 'inv-corr-e2e-2', __sms_action_id,
        '{"provider": "twilio", "sid": "SM1234567890"}'::jsonb);

    SELECT status_code FROM auth.invitation_action WHERE invitation_action_id = __sms_action_id INTO __status;
    IF __status = 'completed' THEN
        RAISE NOTICE '    PASS: SMS action completed';
    ELSE
        RAISE EXCEPTION '    FAIL: Expected completed, got %', __status;
    END IF;

    -- Step 4: User registers (simulate creating a new user)
    RAISE NOTICE '  Step 4: User registers...';
    INSERT INTO auth.user_info (created_by, updated_by, display_name, code, username, original_username, email, can_login)
    VALUES ('svc_app', 'svc_app', 'New SMS User', 'new_sms_user', '+420111999888', '+420111999888', null, true)
    RETURNING user_id INTO __new_user_id;
    RAISE NOTICE '    PASS: New user created (id=%)', __new_user_id;

    -- Step 5: Backend accepts invitation with new user_id
    RAISE NOTICE '  Step 5: Accepting invitation...';

    -- Count pending backend actions returned
    SELECT count(*) FROM auth.accept_invitation('svc_app', __inviter_id, 'inv-corr-e2e-3', (select uuid from auth.invitation where invitation_id = __inv_id), __new_user_id) INTO __pending_count;
    RAISE NOTICE '    INFO: accept_invitation returned % pending backend actions', __pending_count;

    -- Step 6: Verify database actions executed
    RAISE NOTICE '  Step 6: Verifying database actions...';

    -- User should be in tenant 1
    SELECT count(*) FROM auth.user_group_member ugm
    INNER JOIN auth.user_group ug ON ug.user_group_id = ugm.user_group_id
    WHERE ug.tenant_id = 1 AND ug.code = 'tenant_members' AND ugm.user_id = __new_user_id INTO __count;
    IF __count = 1 THEN
        RAISE NOTICE '    PASS: User added to tenant 1';
    ELSE
        RAISE EXCEPTION '    FAIL: User not in tenant, count=%', __count;
    END IF;

    -- User should be in the group
    SELECT count(*) FROM auth.user_group_member WHERE user_group_id = __group_id AND user_id = __new_user_id INTO __count;
    IF __count = 1 THEN
        RAISE NOTICE '    PASS: User added to group %', __group_id;
    ELSE
        RAISE EXCEPTION '    FAIL: User not in group, count=%', __count;
    END IF;

    -- Step 7: Verify invitation completed
    RAISE NOTICE '  Step 7: Verifying final state...';
    SELECT status_code FROM auth.invitation WHERE invitation_id = __inv_id INTO __status;
    IF __status = 'completed' THEN
        RAISE NOTICE '    PASS: Invitation completed';
    ELSE
        RAISE EXCEPTION '    FAIL: Expected completed, got %', __status;
    END IF;

    -- Verify all on_accept actions are completed (not just pending)
    SELECT count(*) FROM auth.invitation_action
    WHERE invitation_id = __inv_id AND phase_code = 'on_accept' AND status_code = 'completed'
    INTO __count;
    RAISE NOTICE '    INFO: % on_accept actions completed', __count;

    -- Verify no actions are still pending
    SELECT count(*) FROM auth.invitation_action
    WHERE invitation_id = __inv_id AND status_code IN ('pending', 'processing')
    INTO __count;
    IF __count = 0 THEN
        RAISE NOTICE '    PASS: No actions pending or processing';
    ELSE
        RAISE EXCEPTION '    FAIL: Still have % pending/processing actions', __count;
    END IF;

    RAISE NOTICE 'TEST 13: Done';
    RAISE NOTICE '';
END $$;
