set search_path = public, const, ext, stage, helpers, internal, unsecure, auth, triggers;

-- ============================================================================
-- SETUP
--   providers ru_aad (group mapping) and ru_pwd (no group mapping)
--   tenant FGH: ru_fgh_admin holds tenant_admin there and owns the tenant
--     group "FGH Admins"  (tenant_admin perm set)  - rule mappings in 003
--     group "FGH Members" (tenant_member perm set) - rule mappings in 003
--     group "FGH Synced"  (is_synced)
--   tenant CDE: ru_cde_admin holds tenant_admin there and owns the tenant
--   tenant 1:   ru_full (full_admin), ru_sys (system_admin)
--   svc_authenticator (3) logs users in
-- ============================================================================
create temp table if not exists _ru (key text primary key, val text);

do $$
declare
    __fgh   int;
    __cde   int;
    __id    bigint;
    __g     int;
    __name  text;
begin
    raise notice '';
    raise notice '=================================================================';
    raise notice 'Audit D-13: rules and rule mappings - Starting';
    raise notice '=================================================================';

    insert into auth.provider (created_by, updated_by, code, is_active, allows_group_mapping, allows_group_sync)
    values ('ru', 'ru', 'ru_aad', true, true, true),
           ('ru', 'ru', 'ru_pwd', true, false, false);

    select t.__tenant_id from auth.create_tenant('ru', 1, 'ru', 'RU FGH', 'ru_fgh') t into __fgh;
    select t.__tenant_id from auth.create_tenant('ru', 1, 'ru', 'RU CDE', 'ru_cde') t into __cde;
    insert into _ru values ('fgh', __fgh), ('cde', __cde);

    foreach __name in array array['fgh_admin', 'cde_admin', 'full', 'sys']
    loop
        insert into auth.user_info (created_by, updated_by, user_type_code, username, original_username, display_name, email, can_login)
        values ('ru', 'ru', 'normal', 'ru_' || __name, 'ru_' || __name, 'RU ' || __name, 'ru_' || __name || '@test.com', true)
        returning user_id into __id;
        insert into _ru values (__name, __id);
    end loop;

    perform unsecure.assign_permission_as_system(null::integer, (select val from _ru where key = 'fgh_admin')::bigint, 'tenant_admin', null, __fgh);
    perform unsecure.assign_permission_as_system(null::integer, (select val from _ru where key = 'cde_admin')::bigint, 'tenant_admin', null, __cde);
    -- they own their tenants: mapping into Tenant Admins (owner-only tenant_admin, v2.26) needs an owner
    insert into auth.owner (created_by, tenant_id, user_group_id, user_id)
    values ('ru', __fgh, null, (select val from _ru where key = 'fgh_admin')::bigint),
           ('ru', __cde, null, (select val from _ru where key = 'cde_admin')::bigint);
    perform unsecure.assign_permission_as_system(null::integer, (select val from _ru where key = 'full')::bigint, 'full_admin', null, 1);
    perform unsecure.assign_permission_as_system(null::integer, (select val from _ru where key = 'sys')::bigint, 'system_admin', null, 1);

    select g.__user_group_id from unsecure.create_user_group('ru', 1, 'ru', 'FGH Admins', _tenant_id := __fgh) g into __g;
    perform unsecure.assign_permission('ru', 1, 'ru', __g, null, 'tenant_admin', _tenant_id := __fgh);
    insert into _ru values ('g_admins', __g);

    select g.__user_group_id from unsecure.create_user_group('ru', 1, 'ru', 'FGH Members', _tenant_id := __fgh) g into __g;
    perform unsecure.assign_permission('ru', 1, 'ru', __g, null, 'tenant_member', _tenant_id := __fgh);
    insert into _ru values ('g_members', __g);

    select g.__user_group_id from unsecure.create_user_group('ru', 1, 'ru', 'FGH Synced', _is_external := true, _tenant_id := __fgh) g into __g;
    update auth.user_group set is_synced = true where user_group_id = __g;
    insert into _ru values ('g_synced', __g);

    raise notice 'PASS: setup (FGH=%, CDE=%)', __fgh, __cde;
end $$;

create or replace function pg_temp.ru(_key text) returns text language sql as $$ select val from _ru where key = _key $$;

-- runs _sql (with {key} placeholders from _ru) and expects sqlstate _code
create or replace function pg_temp.ru_expect(_label text, _sql text, _code text) returns void
    language plpgsql
as
$$
declare
    __sql   text := _sql;
    __r     record;
    __state text;
    __msg   text;
begin
    for __r in select key, val from _ru loop
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

create or replace function pg_temp.ru_is(_label text, _actual text, _expected text) returns void
    language plpgsql
as
$$
begin
    if _actual is not distinct from _expected then
        raise notice 'PASS: % (%)', _label, coalesce(_actual, 'null');
    else
        raise notice 'FAIL: % - got %, expected %', _label, coalesce(_actual, 'null'), coalesce(_expected, 'null');
    end if;
end;
$$;

-- logs a user in through a provider with the given groups and claims, returns the user id
create or replace function pg_temp.ru_login(_name text, _provider text, _groups text[], _claims jsonb default null,
                                            _email text default null) returns bigint
    language plpgsql
as
$$
declare
    __r record;
begin
    select * from auth.ensure_user_from_provider('ru', 3, 'ru', _provider, 'uid-' || _name, 'oid-' || _name
        , 'ru_' || _name, initcap(_name), coalesce(_email, _name || '@fgh.com'), _claims) into __r;
    if __r.__user_id is null then
        raise exception 'FAIL: login of % failed: %', _name, __r.__outcome_code;
    end if;
    perform auth.ensure_groups_and_permissions('ru', 3, 'ru', __r.__user_id, _provider, _groups, null);
    return __r.__user_id;
end;
$$;

-- group codes the user is a member of, in tenant FGH
create or replace function pg_temp.ru_groups(_user_id bigint) returns text
    language sql
as
$$
select coalesce(string_agg(ug.code, ',' order by ug.code), '')
from auth.user_group_member m
         inner join auth.user_group ug on ug.user_group_id = m.user_group_id
where m.user_id = _user_id
  and ug.tenant_id = (select val::int from _ru where key = 'fgh');
$$;
