set search_path = public, const, ext, stage, helpers, internal, unsecure, auth, triggers;

-- ============================================================================
-- SETUP
--   tenant A, tenant B : created the normal way
--   admin_b  : perm set 'a02_admin' in B with every groups / api_keys /
--              invitations / mfa / tenants permission
--   owner_b  : tenant-wide owner of B, no perm set
--   tenant A : its tenant_admins group, an API key, an invitation, a template,
--              an MFA policy; B : a group of its own for the positive checks
-- ============================================================================
do $$
declare
    __a_id        int;
    __b_id        int;
    __admin_b_id  bigint;
    __owner_b_id  bigint;
    __member_id   bigint;
    __ga_id       int;
    __gb_id       int;
    __ps_id       int;
    __key_a_id    int;
    __key_b_id    int;
    __inv_a_id    bigint;
    __tmpl_a_id   int;
    __tmpl_g_id   int;
    __mfa_a_id    bigint;
begin
    raise notice '';
    raise notice '=================================================================';
    raise notice 'Audit 02: cross-tenant ids - Starting';
    raise notice '=================================================================';

    select t.__tenant_id from auth.create_tenant('audit02', 1, 'audit02-setup', 'Audit02 Tenant A', 'audit02_a') t into __a_id;
    select t.__tenant_id from auth.create_tenant('audit02', 1, 'audit02-setup', 'Audit02 Tenant B', 'audit02_b') t into __b_id;

    insert into auth.user_info (created_by, updated_by, user_type_code, username, original_username, display_name, can_login)
    values ('audit02', 'audit02', 'normal', 'audit02_admin_b', 'audit02_admin_b', 'Audit02 Admin B', true)
    returning user_id into __admin_b_id;
    insert into auth.user_info (created_by, updated_by, user_type_code, username, original_username, display_name, can_login)
    values ('audit02', 'audit02', 'normal', 'audit02_owner_b', 'audit02_owner_b', 'Audit02 Owner B', true)
    returning user_id into __owner_b_id;
    insert into auth.user_info (created_by, updated_by, user_type_code, username, original_username, display_name, can_login)
    values ('audit02', 'audit02', 'normal', 'audit02_member', 'audit02_member', 'Audit02 Member', true)
    returning user_id into __member_id;

    insert into auth.perm_set (created_by, updated_by, tenant_id, code, is_system, is_assignable)
    values ('audit02', 'audit02', __b_id, 'a02_admin', false, true)
    returning perm_set_id into __ps_id;
    insert into auth.perm_set_perm (created_by, perm_set_id, permission_id)
    select 'audit02', __ps_id, p.permission_id
    from auth.permission p
    where subpath(p.full_code, 0, 1)::text in ('groups', 'api_keys', 'invitations', 'mfa', 'tenants');
    perform unsecure.assign_permission_as_system(null::integer, __admin_b_id, 'a02_admin', null, __b_id);

    insert into auth.owner (created_by, tenant_id, user_group_id, user_id)
    values ('audit02', __b_id, null, __owner_b_id);

    select user_group_id from auth.user_group where tenant_id = __a_id and code = 'tenant_admins' into __ga_id;
    select user_group_id from auth.user_group where tenant_id = __b_id and code = 'tenant_members' into __gb_id;
    -- a manual member in A's group, so delete-member has something to remove
    insert into auth.user_group_member (created_by, user_group_id, user_id, member_type_code)
    values ('audit02', __ga_id, __member_id, 'manual');

    select k.__api_key_id from auth.create_api_key('audit02', 1, 'audit02-setup', 'A02 key A', null, null, null, _tenant_id := __a_id) k into __key_a_id;
    select k.__api_key_id from auth.create_api_key('audit02', 1, 'audit02-setup', 'A02 key B', null, null, null, _tenant_id := __b_id) k into __key_b_id;

    select i.__invitation_id from auth.create_invitation('audit02', 1, 'audit02-setup', __a_id, 'audit02_target@example.com') i into __inv_a_id;
    select t.__template_id from auth.create_invitation_template('audit02', 1, 'audit02-setup', __a_id, 'a02_tmpl_a', 'A02 template A') t into __tmpl_a_id;
    select t.__template_id from auth.create_invitation_template('audit02', 1, 'audit02-setup', null, 'a02_tmpl_global', 'A02 global template') t into __tmpl_g_id;

    select p.__mfa_policy_id from auth.create_mfa_policy('audit02', 1, 'audit02-setup', __a_id, null, null, true) p into __mfa_a_id;

    create temp table if not exists _a02 (key text primary key, val text);
    delete from _a02;
    insert into _a02 values
        ('a_id', __a_id::text), ('b_id', __b_id::text),
        ('admin_b_id', __admin_b_id::text), ('owner_b_id', __owner_b_id::text), ('member_id', __member_id::text),
        ('ga_id', __ga_id::text), ('gb_id', __gb_id::text),
        ('key_a_id', __key_a_id::text), ('key_b_id', __key_b_id::text),
        ('inv_a_id', __inv_a_id::text), ('tmpl_a_id', __tmpl_a_id::text), ('tmpl_g_id', __tmpl_g_id::text),
        ('mfa_a_id', __mfa_a_id::text);

    raise notice 'SETUP: A=%, B=%, admin_b=%, owner_b=%, ga=%, gb=%, key_a=%, inv_a=%, tmpl_a=%, tmpl_g=%, mfa_a=%',
        __a_id, __b_id, __admin_b_id, __owner_b_id, __ga_id, __gb_id, __key_a_id, __inv_a_id, __tmpl_a_id, __tmpl_g_id, __mfa_a_id;
end $$;

-- Runs _sql (with {a}, {b}, {ga}, ... placeholders filled from _a02) and expects SQLSTATE _code.
create or replace function pg_temp.a02_expect(_label text, _sql text, _code text) returns void
    language plpgsql
as
$$
declare
    __sql   text := _sql;
    __r     record;
    __state text;
    __msg   text;
begin
    for __r in select key, val from _a02 loop
        __sql := replace(__sql, '{' || __r.key || '}', __r.val);
    end loop;
    begin
        execute __sql;
        raise notice 'FAIL: % - no error raised (expected %)', _label, _code;
        return;
    exception when others then
        get stacked diagnostics __state = returned_sqlstate, __msg = message_text;
    end;
    if __state = _code then
        raise notice 'PASS: % - %', _label, _code;
    else
        raise notice 'FAIL: % - got % (expected %): %', _label, __state, _code, __msg;
    end if;
end;
$$;

create or replace function pg_temp.a02(_key text) returns text language sql as $$ select val from _a02 where key = _key $$;
