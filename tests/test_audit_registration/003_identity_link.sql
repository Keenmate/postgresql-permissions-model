set search_path = public, const, ext, stage, helpers, internal, unsecure, auth, triggers;

-- ============================================================================
-- TEST 5: the user links an email identity to their own account. No permission
--         is needed for a self-link; the email identity starts unverified.
-- ============================================================================
do $$
declare
    __jane_id     bigint := (select val::bigint from _a01 where key = 'jane_id');
    __linked_user bigint;
    __is_verified boolean;
    __login_id    bigint;
begin
    raise notice 'TEST 5: self-link of an email identity';

    select l.__user_id, l.__is_verified
    from auth.create_user_identity_link('audit01', __jane_id, 'audit01-t5', __jane_id
        , 'email', ' Jane.Audit01@Corp.com ', null, 'JANE_HASH') l
    into __linked_user, __is_verified;

    if __linked_user is distinct from __jane_id then
        raise exception '  FAIL: link returned user %, expected %', __linked_user, __jane_id;
    end if;
    if __is_verified is distinct from false then
        raise exception '  FAIL: linked email identity must start unverified';
    end if;

    -- the email login lookup is done by the authenticator service user
    select __user_id
    from auth.get_user_by_email_for_authentication(
        (select user_id from auth.user_info where username = 'svc_authenticator'), 'audit01-t5', 'jane.audit01@corp.com')
    into __login_id;
    if __login_id is distinct from __jane_id then
        raise exception '  FAIL: email login resolved to %, expected %', __login_id, __jane_id;
    end if;

    if not exists(select from auth.user_event e
                  where e.target_user_id = __jane_id and e.event_type_code = 'identity_linked') then
        raise exception '  FAIL: no identity_linked user event';
    end if;

    raise notice '  PASS: email identity linked, unverified, login resolves to jane, event logged';
end $$;

-- ============================================================================
-- TEST 6: linking to someone else's account needs users.create_user_identity_link
-- ============================================================================
do $$
declare
    __jane_id  bigint := (select val::bigint from _a01 where key = 'jane_id');
    __plain_id bigint := (select val::bigint from _a01 where key = 'plain_id');
    __admin_id bigint := (select val::bigint from _a01 where key = 'admin_id');
    __raised   text;
    __linked   bigint;
begin
    raise notice 'TEST 6: linking for another user requires permission';

    begin
        perform auth.create_user_identity_link('audit01', __plain_id, 'audit01-t6', __jane_id
            , 'audit01_idp_b', 'uid-b-jane', 'oid-b-jane');
    exception when others then
        __raised := sqlstate;
    end;
    if __raised is distinct from '32001' then
        raise exception '  FAIL: plain user: expected 32001, got %', coalesce(__raised, 'no error');
    end if;

    select l.__user_id
    from auth.create_user_identity_link('audit01', __admin_id, 'audit01-t6', __jane_id
        , 'audit01_idp_b', 'uid-b-jane', 'oid-b-jane') l
    into __linked;
    if __linked is distinct from __jane_id then
        raise exception '  FAIL: admin link returned %, expected %', __linked, __jane_id;
    end if;

    raise notice '  PASS: plain 32001, admin linked idp_b identity';
end $$;

-- ============================================================================
-- TEST 7: an identity owned by another user cannot be linked (33007), by uid or oid
-- ============================================================================
do $$
declare
    __jane_id bigint := (select val::bigint from _a01 where key = 'jane_id');
    __raised  text;
begin
    raise notice 'TEST 7: identity already in use';

    begin
        perform auth.create_user_identity_link('audit01', __jane_id, 'audit01-t7', __jane_id
            , 'audit01_idp_b', 'uid-b-other', null);
    exception when others then
        __raised := sqlstate;
    end;
    if __raised is distinct from '33007' then
        raise exception '  FAIL: same uid: expected 33007, got %', coalesce(__raised, 'no error');
    end if;

    __raised := null;
    begin
        perform auth.create_user_identity_link('audit01', __jane_id, 'audit01-t7', __jane_id
            , 'audit01_idp_b', 'uid-b-something-else', 'oid-b-other');
    exception when others then
        __raised := sqlstate;
    end;
    if __raised is distinct from '33007' then
        raise exception '  FAIL: same oid: expected 33007, got %', coalesce(__raised, 'no error');
    end if;

    raise notice '  PASS: 33007 for uid and oid collisions';
end $$;

-- ============================================================================
-- TEST 8: unknown, disabled, locked and service-user targets are rejected
-- ============================================================================
do $$
declare
    __admin_id bigint := (select val::bigint from _a01 where key = 'admin_id');
    __plain_id bigint := (select val::bigint from _a01 where key = 'plain_id');
    __raised   text;
begin
    raise notice 'TEST 8: invalid link targets';

    begin
        perform auth.create_user_identity_link('audit01', __admin_id, 'audit01-t8', -42
            , 'audit01_idp_b', 'uid-b-ghost', null);
    exception when others then
        __raised := sqlstate;
    end;
    if __raised is distinct from '33001' then
        raise exception '  FAIL: unknown target: expected 33001, got %', coalesce(__raised, 'no error');
    end if;

    update auth.user_info set is_active = false where user_id = __plain_id;
    __raised := null;
    begin
        perform auth.create_user_identity_link('audit01', __admin_id, 'audit01-t8', __plain_id
            , 'audit01_idp_b', 'uid-b-plain', null);
    exception when others then
        __raised := sqlstate;
    end;
    if __raised is distinct from '33003' then
        raise exception '  FAIL: disabled target: expected 33003, got %', coalesce(__raised, 'no error');
    end if;

    update auth.user_info set is_active = true, is_locked = true where user_id = __plain_id;
    __raised := null;
    begin
        perform auth.create_user_identity_link('audit01', __admin_id, 'audit01-t8', __plain_id
            , 'audit01_idp_b', 'uid-b-plain', null);
    exception when others then
        __raised := sqlstate;
    end;
    if __raised is distinct from '33004' then
        raise exception '  FAIL: locked target: expected 33004, got %', coalesce(__raised, 'no error');
    end if;

    __raised := null;
    begin
        perform auth.create_user_identity_link('audit01', __admin_id, 'audit01-t8'
            , (select val::bigint from _a01 where key = 'registrator_id')
            , 'audit01_idp_b', 'uid-b-svc', null);
    exception when others then
        __raised := sqlstate;
    end;
    if __raised is distinct from '33005' then
        raise exception '  FAIL: service user target: expected 33005, got %', coalesce(__raised, 'no error');
    end if;

    raise notice '  PASS: unknown 33001, disabled 33003, locked 33004, service user 33005';
end $$;
