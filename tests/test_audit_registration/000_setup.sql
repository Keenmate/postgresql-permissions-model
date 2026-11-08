set search_path = public, const, ext, stage, helpers, internal, unsecure, auth, triggers;

-- ============================================================================
-- SETUP
--   two external providers (idp_a, idp_b)
--   jane    : SSO-only user created by an idp_a login, username = her UPN
--   other   : SSO user on idp_b, owns identity 'uid-b-other'
--   plain   : user with no permissions
--   admin   : full_admin perm set (NOT user 1 - user 1 bypasses every check)
--   registrator: the seeded svc_registrator service user (users.register_user)
-- ============================================================================
do $$
declare
    __registrator_id bigint := (select user_id from auth.user_info where username = 'svc_registrator');
    __jane_id        bigint;
    __other_id       bigint;
    __plain_id       bigint;
    __admin_id       bigint;
begin
    raise notice '';
    raise notice '=================================================================';
    raise notice 'Audit 01: registration & identity linking - Starting';
    raise notice '=================================================================';

    if __registrator_id is null then
        raise exception 'SETUP FAIL: seeded svc_registrator user not found';
    end if;

    insert into auth.provider (created_by, updated_by, code, is_active)
    values ('audit01', 'audit01', 'audit01_idp_a', true)
         , ('audit01', 'audit01', 'audit01_idp_b', true);

    select __user_id
    from auth.ensure_user_from_provider('audit01', __registrator_id, 'audit01-setup', 'audit01_idp_a'
        , 'uid-a-jane', 'oid-a-jane', 'Jane.Audit01@Corp.com', 'Jane Doe', 'jane.audit01@corp.com')
    into __jane_id;

    select __user_id
    from auth.ensure_user_from_provider('audit01', __registrator_id, 'audit01-setup', 'audit01_idp_b'
        , 'uid-b-other', 'oid-b-other', 'other.audit01@corp.com', 'Other User', 'other.audit01@corp.com')
    into __other_id;

    insert into auth.user_info (created_by, updated_by, user_type_code, username, original_username, display_name, email, can_login)
    values ('audit01', 'audit01', 'normal', 'audit01_plain', 'audit01_plain', 'Audit01 Plain', 'plain.audit01@test.com', true)
    returning user_id into __plain_id;

    insert into auth.user_info (created_by, updated_by, user_type_code, username, original_username, display_name, email, can_login)
    values ('audit01', 'audit01', 'normal', 'audit01_admin', 'audit01_admin', 'Audit01 Admin', 'admin.audit01@test.com', true)
    returning user_id into __admin_id;

    perform unsecure.assign_permission_as_system(null::integer, __admin_id, 'full_admin');

    create temp table if not exists _a01 (key text primary key, val text);
    delete from _a01;
    insert into _a01 values
        ('registrator_id', __registrator_id::text), ('jane_id', __jane_id::text),
        ('other_id', __other_id::text), ('plain_id', __plain_id::text), ('admin_id', __admin_id::text);

    raise notice 'SETUP: registrator=%, jane=%, other=%, plain=%, admin=%', __registrator_id, __jane_id, __other_id, __plain_id, __admin_id;
end $$;
