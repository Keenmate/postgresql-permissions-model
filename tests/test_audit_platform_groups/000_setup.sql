set search_path = public, const, ext, stage, helpers, internal, unsecure, auth, triggers;

-- ============================================================================
-- SETUP
--   tenants ABC, CDE, FGH
--   tenant 1 perm sets: "PG Admin" (groups.create_group, groups.get_groups,
--     users.read_users, tenants.update_tenant), "PG Support" (users.read_users)
--   users
--     pg_full      - full_admin in tenant 1 (holds the platform permissions)
--     pg_sys       - system_admin in tenant 1 (no platform permissions)
--     pg_abc_admin - tenant_admin + tenant_owner perm sets in ABC
--     pg_anna, pg_gina - support staff, no direct rights anywhere
--   provider pg_aad (group mapping), svc_authenticator (3) logs users in
-- ============================================================================
create temp table if not exists _pg (key text primary key, val text);

do $$
declare
    __id   bigint;
    __t    int;
    __name text;
begin
    raise notice '';
    raise notice '=================================================================';
    raise notice 'Audit D-13: platform groups - Starting';
    raise notice '=================================================================';

    insert into auth.provider (created_by, updated_by, code, is_active, allows_group_mapping, allows_group_sync)
    values ('pg', 'pg', 'pg_aad', true, true, false);

    foreach __name in array array['abc', 'cde', 'fgh']
    loop
        select t.__tenant_id from auth.create_tenant('pg', 1, 'pg', 'PG ' || upper(__name), 'pg_' || __name) t into __t;
        insert into _pg values (__name, __t);
    end loop;

    foreach __name in array array['full', 'sys', 'abc_admin', 'anna', 'gina']
    loop
        insert into auth.user_info (created_by, updated_by, user_type_code, username, original_username, display_name, email, can_login)
        values ('pg', 'pg', 'normal', 'pg_' || __name, 'pg_' || __name, 'PG ' || __name, 'pg_' || __name || '@test.com', true)
        returning user_id into __id;
        insert into _pg values (__name, __id);
    end loop;

    perform unsecure.assign_permission_as_system(null::integer, (select val from _pg where key = 'full')::bigint, 'full_admin', null, 1);
    perform unsecure.assign_permission_as_system(null::integer, (select val from _pg where key = 'sys')::bigint, 'system_admin', null, 1);
    perform unsecure.assign_permission_as_system(null::integer, (select val from _pg where key = 'abc_admin')::bigint, 'tenant_admin', null, (select val from _pg where key = 'abc')::int);
    perform unsecure.assign_permission_as_system(null::integer, (select val from _pg where key = 'abc_admin')::bigint, 'tenant_owner', null, (select val from _pg where key = 'abc')::int);

    perform unsecure.create_perm_set('pg', 1, 'pg', 'PG Admin', _permissions := array[
        'groups.create_group', 'groups.get_groups', 'users.read_users', 'tenants.update_tenant'], _tenant_id := 1);
    perform unsecure.create_perm_set('pg', 1, 'pg', 'PG Support', _permissions := array['users.read_users'], _tenant_id := 1);

    raise notice 'PASS: setup';
end $$;

create or replace function pg_temp.pg(_key text) returns text language sql as $$ select val from _pg where key = _key $$;

-- runs _sql (with {key} placeholders from _pg) and expects sqlstate _code
create or replace function pg_temp.pg_expect(_label text, _sql text, _code text) returns void
    language plpgsql
as
$$
declare
    __sql   text := _sql;
    __r     record;
    __state text;
    __msg   text;
begin
    for __r in select key, val from _pg order by length(key) desc loop
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

create or replace function pg_temp.pg_is(_label text, _actual text, _expected text) returns void
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

-- the tenants (codes) in which the user holds the permission, tenant 1 included
create or replace function pg_temp.pg_holds(_user_id bigint, _perm text) returns text
    language sql
as
$$
select coalesce(string_agg(t.code, ',' order by t.code), '')
from auth.tenant t
where (t.tenant_id = 1 or t.code like 'pg\_%')
  and auth.has_permission(_user_id, 'pg', _perm, t.tenant_id, _throw_err := false);
$$;
