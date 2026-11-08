set search_path = public, const, ext, stage, helpers, internal, unsecure, auth, triggers;

-- ============================================================================
-- TEST 1: register_user with the username of an existing SSO-only user must
--         fail with 33007 and must not attach an email identity to that user.
--         (Before v2.4 the existing user was returned and the attacker's
--         password hash became a login to the victim's account.)
-- ============================================================================
do $$
declare
    __registrator_id bigint := (select val::bigint from _a01 where key = 'registrator_id');
    __jane_id        bigint := (select val::bigint from _a01 where key = 'jane_id');
    __input          text;
    __raised         text;
    __identities     int;
begin
    raise notice 'TEST 1: register_user cannot take over an existing username';

    foreach __input in array array['jane.audit01@corp.com', '  JANE.Audit01@corp.COM '] loop
        __raised := null;
        begin
            perform auth.register_user('audit01', __registrator_id, 'audit01-t1', __input, 'ATTACKER_HASH', 'Mallory');
        exception when others then
            __raised := sqlstate;
        end;
        if __raised is distinct from '33007' then
            raise exception '  FAIL: register_user(%): expected 33007, got %', __input, coalesce(__raised, 'no error');
        end if;
    end loop;

    select count(*) from auth.user_identity where user_id = __jane_id into __identities;
    if __identities <> 1 then
        raise exception '  FAIL: victim should still have exactly 1 identity, has %', __identities;
    end if;

    if exists(select from auth.user_identity where provider_code = 'email' and uid = 'jane.audit01@corp.com') then
        raise exception '  FAIL: an email identity for the victim address exists';
    end if;

    raise notice '  PASS: 33007 for exact and case/space variants, victim untouched';
end $$;

-- ============================================================================
-- TEST 2: regression - registering a genuinely new address still works and
--         creates a new user with an unverified email identity
-- ============================================================================
do $$
declare
    __registrator_id bigint := (select val::bigint from _a01 where key = 'registrator_id');
    __jane_id        bigint := (select val::bigint from _a01 where key = 'jane_id');
    __new_id         bigint;
    __username       text;
    __is_verified    boolean;
begin
    raise notice 'TEST 2: register_user still registers new addresses';

    select r.__user_id, r.__username
    from auth.register_user('audit01', __registrator_id, 'audit01-t2', 'New.Audit01@Corp.com', 'NEW_HASH', 'New User') r
    into __new_id, __username;

    if __new_id is null or __new_id = __jane_id then
        raise exception '  FAIL: expected a new user, got %', __new_id;
    end if;
    if __username <> 'new.audit01@corp.com' then
        raise exception '  FAIL: username not normalized: %', __username;
    end if;

    select is_verified from auth.user_identity
    where user_id = __new_id and provider_code = 'email' and uid = 'new.audit01@corp.com'
    into __is_verified;
    if __is_verified is distinct from false then
        raise exception '  FAIL: new email identity missing or already verified (is_verified=%)', __is_verified;
    end if;

    raise notice '  PASS: new user % with unverified email identity', __new_id;
end $$;
