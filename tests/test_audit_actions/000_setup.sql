set search_path = public, const, ext, stage, helpers, internal, unsecure, auth, triggers;

-- ============================================================================
-- SETUP
--   tenants ac_abc, ac_cde
--   ABC: perm set "AC Reader" (users.read_users), group "AC Staff" (AC Reader)
--   users
--     ac_full      - full_admin in tenant 1
--     ac_abc_owner - owner row in ABC
--     ac_abc_admin - tenant_admin in ABC (no users.read_users, no groups.*)
--     ac_cde_admin - tenant_admin in CDE
--     ac_nobody    - nothing
--   provider ac_aad (group mapping); svc_authenticator (3) logs users in
-- ============================================================================
create temp table if not exists _ac (key text primary key, val text);

do $$
declare
    __id   bigint;
    __t    int;
    __g    int;
    __name text;
begin
    raise notice '';
    raise notice '=================================================================';
    raise notice 'Audit D-13: actions - Starting';
    raise notice '=================================================================';

    insert into auth.provider (created_by, updated_by, code, is_active, allows_group_mapping, allows_group_sync)
    values ('ac', 'ac', 'ac_aad', true, true, false);

    foreach __name in array array['abc', 'cde']
    loop
        select t.__tenant_id from auth.create_tenant('ac', 1, 'ac', 'AC ' || upper(__name), 'ac_' || __name) t into __t;
        insert into _ac values (__name, __t);
    end loop;

    foreach __name in array array['full', 'abc_owner', 'abc_admin', 'cde_admin', 'nobody']
    loop
        insert into auth.user_info (created_by, updated_by, user_type_code, username, original_username, display_name, email, can_login)
        values ('ac', 'ac', 'normal', 'ac_' || __name, 'ac_' || __name, 'AC ' || __name, 'ac_' || __name || '@test.com', true)
        returning user_id into __id;
        insert into _ac values (__name, __id);
    end loop;

    perform unsecure.assign_permission_as_system(null::integer, (select val from _ac where key = 'full')::bigint, 'full_admin', null, 1);
    perform unsecure.assign_permission_as_system(null::integer, (select val from _ac where key = 'abc_admin')::bigint, 'tenant_admin', null, (select val from _ac where key = 'abc')::int);
    perform unsecure.assign_permission_as_system(null::integer, (select val from _ac where key = 'cde_admin')::bigint, 'tenant_admin', null, (select val from _ac where key = 'cde')::int);
    insert into auth.owner (created_by, tenant_id, user_group_id, user_id)
    values ('ac', (select val from _ac where key = 'abc')::int, null, (select val from _ac where key = 'abc_owner')::bigint);

    __t := (select val from _ac where key = 'abc')::int;
    perform unsecure.create_perm_set('ac', 1, 'ac', 'AC Reader', _permissions := array['users.read_users'], _tenant_id := __t);
    select g.__user_group_id from unsecure.create_user_group('ac', 1, 'ac', 'AC Staff', _tenant_id := __t) g into __g;
    insert into _ac values ('g_staff', __g);
    perform unsecure.assign_permission('ac', 1, 'ac', __g, null, 'ac_reader', _tenant_id := __t);

    select g.__user_group_id from unsecure.create_user_group('ac', 1, 'ac', 'CDE Staff', _tenant_id := (select val from _ac where key = 'cde')::int) g into __g;
    insert into _ac values ('g_cde_staff', __g);

    insert into _ac values ('g_abc_members', (select ug.user_group_id from auth.user_group ug where ug.tenant_id = __t and ug.code = 'tenant_members'));

    raise notice 'PASS: setup';
end $$;

create or replace function pg_temp.ac(_key text) returns text language sql as $$ select val from _ac where key = _key $$;

-- runs _sql (with {key} placeholders from _ac) and expects sqlstate _code
create or replace function pg_temp.ac_expect(_label text, _sql text, _code text) returns void
    language plpgsql
as
$$
declare
    __sql   text := _sql;
    __r     record;
    __state text;
    __msg   text;
begin
    for __r in select key, val from _ac order by length(key) desc loop
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

create or replace function pg_temp.ac_is(_label text, _actual text, _expected text) returns void
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

-- a user's runs: action code:status:[step type:status, ...], oldest first
create or replace function pg_temp.ac_runs(_user_id bigint) returns text
    language sql
as
$$
select coalesce(string_agg(a.code || ':' || r.status_code || ':[' ||
                           (select string_agg(s.step_type_code || ':' || s.status_code, ',' order by s.sequence, s.action_run_step_id)
                            from auth.action_run_step s
                            where s.action_run_id = r.action_run_id) || ']', ' | ' order by r.action_run_id), '')
from auth.action_run r
         inner join auth.action a on a.action_id = r.action_id
where r.user_id = _user_id
  and a.code like 'ac\_%';
$$;

-- the user's groups in a tenant
create or replace function pg_temp.ac_groups(_user_id bigint, _tenant_id int) returns text
    language sql
as
$$
select coalesce(string_agg(g.code, ',' order by g.code), '')
from auth.user_group_member m
         inner join auth.user_group g on g.user_group_id = m.user_group_id
where m.user_id = _user_id
  and g.tenant_id = _tenant_id;
$$;
