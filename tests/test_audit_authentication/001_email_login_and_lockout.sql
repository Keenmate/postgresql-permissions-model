set search_path = public, const, ext, stage, helpers, internal, unsecure, auth, triggers;

-- ============================================================================
-- TEST 1: step 1 (get_user_by_email_for_authentication) is read only
-- ============================================================================
do $$
declare
    __auth_svc_id bigint := (select val::bigint from _a02 where key = 'auth_svc_id');
    __alice_id    bigint := (select val::bigint from _a02 where key = 'alice_id');
    __events      bigint;
    __hash        text;
    __provider    text;
begin
    raise notice 'TEST 1: step 1 writes nothing';

    select count(*) from auth.user_event where target_user_id = __alice_id into __events;
    update auth.user_info set last_used_provider_code = 'audit02_idp' where user_id = __alice_id;

    select u.__password_hash
    from auth.get_user_by_email_for_authentication(__auth_svc_id, 'audit02-t1', ' Alice.Audit02@test.com ') u
    into __hash;

    if __hash is distinct from 'HASH_ALICE' then
        raise exception '  FAIL: expected the hash, got %', __hash;
    end if;
    if (select count(*) from auth.user_event where target_user_id = __alice_id) <> __events then
        raise exception '  FAIL: step 1 wrote a user_event';
    end if;
    select last_used_provider_code from auth.user_info where user_id = __alice_id into __provider;
    if __provider is distinct from 'audit02_idp' then
        raise exception '  FAIL: step 1 changed last_used_provider_code to %', __provider;
    end if;

    raise notice '  PASS: hash returned, no event, last-used provider untouched';
end $$;

-- ============================================================================
-- TEST 2: 4 wrong passwords -> 33001 with a growing counter; the 5th -> 33004,
--         15 min lock. Every failure and the auto-lock are recorded.
--         (Before v2.6 record_login_failure raised and rolled all of it back.)
-- ============================================================================
do $$
declare
    __auth_svc_id bigint := (select val::bigint from _a02 where key = 'auth_svc_id');
    __alice_id    bigint := (select val::bigint from _a02 where key = 'alice_id');
    __r           record;
    __i           int;
    __hash        text;
    __locked      timestamptz;
begin
    raise notice 'TEST 2: wrong passwords lead to a temporary lock';

    for __i in 1..4 loop
        select * from auth.create_user_login_attempt('audit02', __auth_svc_id, 'audit02-t2', 'email'
            , 'alice.audit02@test.com', __alice_id, false) into __r;
        if __r.__event_id <> 33001 or __r.__outcome_code <> 'err_user_not_found'
            or __r.__failed_login_count <> __i or __r.__max_failed_attempts <> 5 or __r.__user_event_id is null then
            raise exception '  FAIL: attempt %: %', __i, row_to_json(__r);
        end if;
    end loop;

    select * from auth.create_user_login_attempt('audit02', __auth_svc_id, 'audit02-t2', 'email'
        , 'alice.audit02@test.com', __alice_id, false) into __r;
    if __r.__event_id <> 33004 or __r.__outcome_code <> 'err_user_locked'
        or __r.__locked_until is distinct from now() + interval '15 minutes' then
        raise exception '  FAIL: 5th attempt: %', row_to_json(__r);
    end if;

    if (select count(*) from auth.user_event
        where target_user_id = __alice_id and event_type_code = 'user_login_failed'
          and event_data ->> 'reason' = 'wrong_password') <> 5 then
        raise exception '  FAIL: expected 5 persisted user_login_failed rows';
    end if;
    if not exists(select from auth.user_event where target_user_id = __alice_id and event_type_code = 'user_auto_locked') then
        raise exception '  FAIL: no user_auto_locked row';
    end if;

    select u.__password_hash, u.__locked_until
    from auth.get_user_by_email_for_authentication(__auth_svc_id, 'audit02-t2', 'alice.audit02@test.com') u
    into __hash, __locked;
    if __hash is not null or __locked is null then
        raise exception '  FAIL: step 1 while locked: hash=%, locked_until=%', __hash, __locked;
    end if;

    raise notice '  PASS: 4x 33001 (count 1..4), 5th 33004 until now()+15m, events persisted, no hash while locked';
end $$;

-- ============================================================================
-- TEST 3: while locked even the right password gets 33004 and is not counted;
--         after the lock expires it logs in and clears the counters
-- ============================================================================
do $$
declare
    __auth_svc_id bigint := (select val::bigint from _a02 where key = 'auth_svc_id');
    __alice_id    bigint := (select val::bigint from _a02 where key = 'alice_id');
    __r           record;
    __s           auth.user_login_state;
begin
    raise notice 'TEST 3: attempts during a lock, then expiry';

    select * from auth.create_user_login_attempt('audit02', __auth_svc_id, 'audit02-t3', 'email'
        , 'alice.audit02@test.com', __alice_id, true) into __r;
    if __r.__event_id <> 33004 then
        raise exception '  FAIL: correct password while locked: %', row_to_json(__r);
    end if;
    if not exists(select from auth.user_event where target_user_id = __alice_id
                  and event_data ->> 'reason' = 'user_temporarily_locked') then
        raise exception '  FAIL: attempt during the lock was not logged';
    end if;

    select * from auth.user_login_state where user_id = __alice_id into __s;
    if __s.failed_login_count <> 0 or __s.lockout_count <> 1 then
        raise exception '  FAIL: attempt during the lock changed counters: %', row_to_json(__s);
    end if;

    update auth.user_login_state set locked_until = now() - interval '1 second' where user_id = __alice_id;

    select * from auth.create_user_login_attempt('audit02', __auth_svc_id, 'audit02-t3', 'email'
        , 'alice.audit02@test.com', __alice_id, true) into __r;
    if __r.__event_id <> 10010 or __r.__outcome_code <> 'user_logged_in' then
        raise exception '  FAIL: login after expiry: %', row_to_json(__r);
    end if;

    select * from auth.user_login_state where user_id = __alice_id into __s;
    if __s.failed_login_count <> 0 or __s.lockout_count <> 0 or __s.locked_until is not null then
        raise exception '  FAIL: success did not clear the state: %', row_to_json(__s);
    end if;
    if (select last_used_provider_code from auth.user_info where user_id = __alice_id) <> 'email' then
        raise exception '  FAIL: last_used_provider_code not set to email';
    end if;

    raise notice '  PASS: 33004 during lock (not counted), 10010 after expiry, counters cleared';
end $$;
