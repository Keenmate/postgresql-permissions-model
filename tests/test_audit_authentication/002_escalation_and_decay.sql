set search_path = public, const, ext, stage, helpers, internal, unsecure, auth, triggers;

-- helper for this file: 5 wrong passwords for alice, returns the last outcome
create or replace function pg_temp.audit02_fail5() returns record
    language plpgsql
as $$
declare
    __auth_svc_id bigint := (select val::bigint from _a02 where key = 'auth_svc_id');
    __alice_id    bigint := (select val::bigint from _a02 where key = 'alice_id');
    __r           record;
begin
    for __i in 1..5 loop
        select * from auth.create_user_login_attempt('audit02', __auth_svc_id, 'audit02-esc', 'email'
            , 'alice.audit02@test.com', __alice_id, false) into __r;
    end loop;
    return __r;
end $$;

-- ============================================================================
-- TEST 4: consecutive lockouts escalate 15 -> 60 minutes; the cap repeats the
--         last step; a changed lockout_durations_minutes is honoured
-- ============================================================================
do $$
declare
    __alice_id bigint := (select val::bigint from _a02 where key = 'alice_id');
    __r        record;
begin
    raise notice 'TEST 4: escalation';

    select * from pg_temp.audit02_fail5() as (__event_id int, __outcome_code text, __user_event_id bigint
        , __failed_login_count int, __max_failed_attempts int, __locked_until timestamptz) into __r;
    if __r.__locked_until is distinct from now() + interval '15 minutes' then
        raise exception '  FAIL: 1st lockout: %', __r.__locked_until;
    end if;

    update auth.user_login_state set locked_until = now() - interval '1 second' where user_id = __alice_id;

    select * from pg_temp.audit02_fail5() as (__event_id int, __outcome_code text, __user_event_id bigint
        , __failed_login_count int, __max_failed_attempts int, __locked_until timestamptz) into __r;
    if __r.__locked_until is distinct from now() + interval '60 minutes' then
        raise exception '  FAIL: 2nd lockout: %', __r.__locked_until;
    end if;

    -- far past the end of the list: the last step (cap) repeats
    update auth.user_login_state set locked_until = now() - interval '1 second', lockout_count = 9 where user_id = __alice_id;
    select * from pg_temp.audit02_fail5() as (__event_id int, __outcome_code text, __user_event_id bigint
        , __failed_login_count int, __max_failed_attempts int, __locked_until timestamptz) into __r;
    if __r.__locked_until is distinct from now() + interval '1440 minutes' then
        raise exception '  FAIL: capped lockout: %', __r.__locked_until;
    end if;

    -- configured steps are honoured
    perform auth.update_sys_param(1, 'login_lockout', 'lockout_durations_minutes', '5, 10');
    update auth.user_login_state set locked_until = now() - interval '1 second', lockout_count = 0 where user_id = __alice_id;
    select * from pg_temp.audit02_fail5() as (__event_id int, __outcome_code text, __user_event_id bigint
        , __failed_login_count int, __max_failed_attempts int, __locked_until timestamptz) into __r;
    if __r.__locked_until is distinct from now() + interval '5 minutes' then
        raise exception '  FAIL: configured first step: %', __r.__locked_until;
    end if;
    perform auth.update_sys_param(1, 'login_lockout', 'lockout_durations_minutes', '15,60,240,960,1440');

    raise notice '  PASS: 15m, 60m, cap 1440m, configured 5m';
end $$;

-- ============================================================================
-- TEST 5: after lockout_reset_hours without a failure the escalation decays,
--         and failures outside the window are forgotten
-- ============================================================================
do $$
declare
    __auth_svc_id bigint := (select val::bigint from _a02 where key = 'auth_svc_id');
    __alice_id    bigint := (select val::bigint from _a02 where key = 'alice_id');
    __r           record;
begin
    raise notice 'TEST 5: decay';

    update auth.user_login_state
    set locked_until = null, lockout_count = 3, failed_login_count = 4
      , last_failed_login_at = now() - interval '25 hours'
    where user_id = __alice_id;

    -- the 4 old failures are outside the window: this is failure 1, not 5
    select * from auth.create_user_login_attempt('audit02', __auth_svc_id, 'audit02-t5', 'email'
        , 'alice.audit02@test.com', __alice_id, false) into __r;
    if __r.__event_id <> 33001 or __r.__failed_login_count <> 1 then
        raise exception '  FAIL: old failures counted: %', row_to_json(__r);
    end if;
    if (select lockout_count from auth.user_login_state where user_id = __alice_id) <> 0 then
        raise exception '  FAIL: lockout_count did not decay';
    end if;

    select * from pg_temp.audit02_fail5() as (__event_id int, __outcome_code text, __user_event_id bigint
        , __failed_login_count int, __max_failed_attempts int, __locked_until timestamptz) into __r;
    if __r.__locked_until is distinct from now() + interval '15 minutes' then
        raise exception '  FAIL: lockout after decay should be the first step, got %', __r.__locked_until;
    end if;

    -- leave alice unlocked for the next files
    update auth.user_login_state set locked_until = null, lockout_count = 0, failed_login_count = 0 where user_id = __alice_id;

    raise notice '  PASS: window reset, lockout_count decayed, next lockout at first step';
end $$;
