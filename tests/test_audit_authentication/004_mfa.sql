set search_path = public, const, ext, stage, helpers, internal, unsecure, auth, triggers;

-- Enrollment runs as user 1 (setup only); challenges and attempts run as the
-- authenticator service, as in a real login.
-- ============================================================================
-- TEST 8: a wrong MFA code persists the failed token state, the token cannot be
--         retried, MFA failures count toward the lockout; recovery code works
--         (Before v2.6 verify_mfa_challenge raised and rolled the failed state back.)
-- ============================================================================
do $$
declare
    __auth_svc_id bigint := (select val::bigint from _a02 where key = 'auth_svc_id');
    __alice_id  bigint := (select val::bigint from _a02 where key = 'alice_id');
    __codes     text[];
    __token_uid text;
    __r         record;
    __i         int;
begin
    raise notice 'TEST 8: MFA attempts';

    select e.__recovery_codes from auth.enroll_mfa('audit02', 1, 'audit02-t8', __alice_id, 'totp', 'secret') e
    into __codes;
    perform auth.confirm_mfa_enrollment('audit02', 1, 'audit02-t8', __alice_id, 'totp', true);

    select c.__token_uid from auth.create_mfa_challenge('audit02', __auth_svc_id, 'audit02-t8', __alice_id, 'totp') c
    into __token_uid;

    select * from auth.create_mfa_challenge_attempt('audit02', __auth_svc_id, 'audit02-t8', __alice_id, __token_uid, false) into __r;
    if __r.__event_id <> 38004 or __r.__failed_login_count <> 1 then
        raise exception '  FAIL: wrong code: %', row_to_json(__r);
    end if;
    if (select token_state_code from auth.token where uid = __token_uid) <> 'failed' then
        raise exception '  FAIL: token state not persisted as failed';
    end if;

    select * from auth.create_mfa_challenge_attempt('audit02', __auth_svc_id, 'audit02-t8', __alice_id, __token_uid, true) into __r;
    if __r.__event_id <> 30002 then
        raise exception '  FAIL: retry of a failed token: %', row_to_json(__r);
    end if;

    -- 4 more wrong codes on fresh challenges -> locked
    for __i in 1..4 loop
        select c.__token_uid from auth.create_mfa_challenge('audit02', __auth_svc_id, 'audit02-t8', __alice_id, 'totp') c
        into __token_uid;
        select * from auth.create_mfa_challenge_attempt('audit02', __auth_svc_id, 'audit02-t8', __alice_id, __token_uid, false) into __r;
    end loop;
    if __r.__event_id <> 33004 or __r.__locked_until is null then
        raise exception '  FAIL: 5th MFA failure should lock: %', row_to_json(__r);
    end if;

    update auth.user_login_state set locked_until = null where user_id = __alice_id;

    select c.__token_uid from auth.create_mfa_challenge('audit02', __auth_svc_id, 'audit02-t8', __alice_id, 'totp') c
    into __token_uid;
    select * from auth.create_mfa_challenge_attempt('audit02', __auth_svc_id, 'audit02-t8', __alice_id, __token_uid
        , false, __codes[1]) into __r;
    if __r.__event_id <> 10094 or __r.__recovery_codes_remaining <> array_length(__codes, 1) - 1 then
        raise exception '  FAIL: recovery code: %', row_to_json(__r);
    end if;

    raise notice '  PASS: 38004 + failed token persisted, retry 30002, 5th failure 33004, recovery 10094';
end $$;
