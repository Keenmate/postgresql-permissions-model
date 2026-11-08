set search_path = public, const, ext, stage, helpers, internal, unsecure, auth, triggers;

-- ============================================================================
-- SETUP
--   alice    : email user (password hash 'HASH_ALICE'), registered by svc_registrator
--   bob      : SSO user on audit02_idp
--   admin    : full_admin (tenant 1), NOT user 1 - caller for MFA and API keys
--   auth_svc : seeded svc_authenticator - caller for the login functions
-- Every call in a transaction-mode suite sees the same now(), so the tests move
-- locked_until / last_failed_login_at back instead of waiting.
-- ============================================================================
do $$
declare
    __registrator_id bigint := (select user_id from auth.user_info where username = 'svc_registrator');
    __auth_svc_id    bigint := (select user_id from auth.user_info where username = 'svc_authenticator');
    __alice_id       bigint;
    __bob_id         bigint;
    __admin_id       bigint;
begin
    raise notice '';
    raise notice '=================================================================';
    raise notice 'Audit 02: authentication outcomes and lockout - Starting';
    raise notice '=================================================================';

    select r.__user_id
    from auth.register_user('audit02', __registrator_id, 'audit02-setup', 'alice.audit02@test.com', 'HASH_ALICE', 'Alice') r
    into __alice_id;

    insert into auth.provider (created_by, updated_by, code, is_active)
    values ('audit02', 'audit02', 'audit02_idp', true);

    select p.__user_id
    from auth.ensure_user_from_provider('audit02', __auth_svc_id, 'audit02-setup', 'audit02_idp'
        , 'uid-bob', 'oid-bob', 'bob.audit02@corp.com', 'Bob', 'bob.audit02@corp.com') p
    into __bob_id;

    insert into auth.user_info (created_by, updated_by, user_type_code, username, original_username, display_name, can_login)
    values ('audit02', 'audit02', 'normal', 'audit02_admin', 'audit02_admin', 'Audit02 Admin', true)
    returning user_id into __admin_id;
    perform unsecure.assign_permission_as_system(null::integer, __admin_id, 'full_admin');

    if __alice_id is null or __bob_id is null then
        raise exception 'SETUP FAIL: alice=% bob=%', __alice_id, __bob_id;
    end if;

    create temp table if not exists _a02 (key text primary key, val text);
    delete from _a02;
    insert into _a02 values
        ('auth_svc_id', __auth_svc_id::text), ('alice_id', __alice_id::text),
        ('bob_id', __bob_id::text), ('admin_id', __admin_id::text);

    raise notice 'SETUP: auth_svc=%, alice=%, bob=%, admin=%', __auth_svc_id, __alice_id, __bob_id, __admin_id;
end $$;
