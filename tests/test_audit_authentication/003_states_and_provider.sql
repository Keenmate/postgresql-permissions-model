set search_path = public, const, ext, stage, helpers, internal, unsecure, auth, triggers;

-- ============================================================================
-- TEST 6: admin lock, disabled user and unknown email are outcomes, persisted
-- ============================================================================
do $$
declare
    __auth_svc_id bigint := (select val::bigint from _a02 where key = 'auth_svc_id');
    __alice_id    bigint := (select val::bigint from _a02 where key = 'alice_id');
    __r           record;
    __rows        int;
begin
    raise notice 'TEST 6: admin lock, disabled, unknown email';

    update auth.user_info set is_locked = true where user_id = __alice_id;
    select * from auth.create_user_login_attempt('audit02', __auth_svc_id, 'audit02-t6', 'email'
        , 'alice.audit02@test.com', __alice_id, true) into __r;
    if __r.__event_id <> 33004 or __r.__locked_until is not null then
        raise exception '  FAIL: admin lock: %', row_to_json(__r);
    end if;
    update auth.user_info set is_locked = false, is_active = false where user_id = __alice_id;

    select * from auth.create_user_login_attempt('audit02', __auth_svc_id, 'audit02-t6', 'email'
        , 'alice.audit02@test.com', __alice_id, true) into __r;
    if __r.__event_id <> 33003 or __r.__outcome_code <> 'err_user_not_active' then
        raise exception '  FAIL: disabled: %', row_to_json(__r);
    end if;
    update auth.user_info set is_active = true where user_id = __alice_id;

    select count(*) from auth.get_user_by_email_for_authentication(__auth_svc_id, 'audit02-t6', 'nobody.audit02@test.com')
    into __rows;
    if __rows <> 0 then
        raise exception '  FAIL: unknown email returned % rows', __rows;
    end if;

    select * from auth.create_user_login_attempt('audit02', __auth_svc_id, 'audit02-t6', 'email'
        , 'nobody.audit02@test.com', null, null) into __r;
    if __r.__event_id <> 33001 or __r.__user_event_id is null then
        raise exception '  FAIL: unknown email: %', row_to_json(__r);
    end if;
    if not exists(select from auth.user_event where user_event_id = __r.__user_event_id
                  and target_user_id is null and event_data ->> 'reason' = 'user_not_found') then
        raise exception '  FAIL: unknown-email event not persisted';
    end if;

    raise notice '  PASS: admin lock 33004, disabled 33003, unknown email 33001 with event';
end $$;

-- ============================================================================
-- TEST 7: provider login returns outcomes; locked users (admin or temporary)
--         can no longer log in through a provider
-- ============================================================================
do $$
declare
    __auth_svc_id bigint := (select val::bigint from _a02 where key = 'auth_svc_id');
    __bob_id      bigint := (select val::bigint from _a02 where key = 'bob_id');
    __r           record;
begin
    raise notice 'TEST 7: provider login outcomes';

    update auth.user_info set is_locked = true where user_id = __bob_id;
    select * from auth.ensure_user_from_provider('audit02', __auth_svc_id, 'audit02-t7', 'audit02_idp'
        , 'uid-bob', 'oid-bob', 'bob.audit02@corp.com', 'Bob', 'bob.audit02@corp.com') into __r;
    if __r.__event_id <> 33004 or __r.__user_id is not null then
        raise exception '  FAIL: admin-locked provider login: %', row_to_json(__r);
    end if;
    update auth.user_info set is_locked = false where user_id = __bob_id;

    insert into auth.user_login_state (created_by, updated_by, user_id, locked_until)
    values ('audit02', 'audit02', __bob_id, now() + interval '10 minutes');
    select * from auth.ensure_user_from_provider('audit02', __auth_svc_id, 'audit02-t7', 'audit02_idp'
        , 'uid-bob', 'oid-bob', 'bob.audit02@corp.com', 'Bob', 'bob.audit02@corp.com') into __r;
    if __r.__event_id <> 33004 or __r.__user_id is not null then
        raise exception '  FAIL: temporarily locked provider login: %', row_to_json(__r);
    end if;
    delete from auth.user_login_state where user_id = __bob_id;

    select * from auth.ensure_user_from_provider('audit02', __auth_svc_id, 'audit02-t7', 'audit02_idp'
        , 'uid-bob', 'oid-bob', 'bob.audit02@corp.com', 'Bob', 'bob.audit02@corp.com') into __r;
    if __r.__event_id <> 10010 or __r.__user_id is distinct from __bob_id or __r.__user_event_id is null then
        raise exception '  FAIL: provider login: %', row_to_json(__r);
    end if;

    -- first login of another identity with a taken username: outcome, not exception
    select * from auth.ensure_user_from_provider('audit02', __auth_svc_id, 'audit02-t7', 'audit02_idp'
        , 'uid-mallory', 'oid-mallory', 'bob.audit02@corp.com', 'Mallory', 'bob.audit02@corp.com') into __r;
    if __r.__event_id <> 33024 or __r.__user_id is not null then
        raise exception '  FAIL: username taken: %', row_to_json(__r);
    end if;

    raise notice '  PASS: admin lock 33004, temporary lock 33004, login 10010, username taken 33024';
end $$;
