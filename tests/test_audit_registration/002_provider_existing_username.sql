set search_path = public, const, ext, stage, helpers, internal, unsecure, auth, triggers;

-- ============================================================================
-- TEST 3: a first login from another provider whose username claim equals an
--         existing user's username must fail with 33024 and must not link.
-- ============================================================================
do $$
declare
    __registrator_id bigint := (select val::bigint from _a01 where key = 'registrator_id');
    __jane_id        bigint := (select val::bigint from _a01 where key = 'jane_id');
    __raised         text;
    __identities     int;
begin
    raise notice 'TEST 3: ensure_user_from_provider does not link by username';

    begin
        perform auth.ensure_user_from_provider('audit01', __registrator_id, 'audit01-t3', 'audit01_idp_b'
            , 'uid-b-mallory', 'oid-b-mallory', 'jane.audit01@corp.com', 'Mallory', 'jane.audit01@corp.com');
    exception when others then
        __raised := sqlstate;
    end;
    if __raised is distinct from '33024' then
        raise exception '  FAIL: expected 33024, got %', coalesce(__raised, 'no error');
    end if;

    select count(*) from auth.user_identity where user_id = __jane_id into __identities;
    if __identities <> 1 then
        raise exception '  FAIL: victim should still have exactly 1 identity, has %', __identities;
    end if;
    if exists(select from auth.user_identity where provider_code = 'audit01_idp_b' and uid = 'uid-b-mallory') then
        raise exception '  FAIL: attacker identity was created';
    end if;

    raise notice '  PASS: 33024, no identity created';
end $$;

-- ============================================================================
-- TEST 4: regression - returning login and new-user login still work
-- ============================================================================
do $$
declare
    __registrator_id bigint := (select val::bigint from _a01 where key = 'registrator_id');
    __jane_id        bigint := (select val::bigint from _a01 where key = 'jane_id');
    __login_id       bigint;
    __new_id         bigint;
begin
    raise notice 'TEST 4: existing identity logs in, new username creates a user';

    select __user_id
    from auth.ensure_user_from_provider('audit01', __registrator_id, 'audit01-t4', 'audit01_idp_a'
        , 'uid-a-jane', 'oid-a-jane', 'Jane.Audit01@Corp.com', 'Jane Doe', 'jane.audit01@corp.com')
    into __login_id;
    if __login_id is distinct from __jane_id then
        raise exception '  FAIL: returning login resolved to %, expected %', __login_id, __jane_id;
    end if;

    select __user_id
    from auth.ensure_user_from_provider('audit01', __registrator_id, 'audit01-t4', 'audit01_idp_b'
        , 'uid-b-fresh', 'oid-b-fresh', 'fresh.audit01@corp.com', 'Fresh User', 'fresh.audit01@corp.com')
    into __new_id;
    if __new_id is null or __new_id = __jane_id then
        raise exception '  FAIL: expected a new user, got %', __new_id;
    end if;

    raise notice '  PASS: returning login = %, new user = %', __login_id, __new_id;
end $$;
