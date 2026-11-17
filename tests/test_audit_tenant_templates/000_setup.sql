set search_path = public, const, ext, stage, helpers, internal, unsecure, auth, triggers;

-- ============================================================================
-- SETUP
--   tenant tt_abc with its admin
--   tenant 1 perm set "TT Finance" (users.read_users)
--   rules in tenant 1: tt_fin (global), tt_local (tenant rule)
--   users
--     tt_full    - full_admin in tenant 1
--     tt_sys     - system_admin in tenant 1
--     tt_lim     - only the template permissions in tenant 1
--     tt_creator - only tenants.create_tenant in tenant 1
--     tt_abc_admin - tenant_admin + tenant_owner in tt_abc
--   provider tt_aad (group mapping), tt_nomap (no group mapping)
-- ============================================================================
create temp table if not exists _tt (key text primary key, val text);

do $$
declare
    __id   bigint;
    __t    int;
    __name text;
begin
    raise notice '';
    raise notice '=================================================================';
    raise notice 'Audit D-13: tenant templates - Starting';
    raise notice '=================================================================';

    insert into auth.provider (created_by, updated_by, code, is_active, allows_group_mapping, allows_group_sync)
    values ('tt', 'tt', 'tt_aad', true, true, false),
           ('tt', 'tt', 'tt_nomap', true, false, false);

    select t.__tenant_id from auth.create_tenant('tt', 1, 'tt', 'TT ABC', 'tt_abc') t into __t;
    insert into _tt values ('abc', __t);

    foreach __name in array array['full', 'sys', 'lim', 'creator', 'abc_admin']
    loop
        insert into auth.user_info (created_by, updated_by, user_type_code, username, original_username, display_name, email, can_login)
        values ('tt', 'tt', 'normal', 'tt_' || __name, 'tt_' || __name, 'TT ' || __name, 'tt_' || __name || '@test.com', true)
        returning user_id into __id;
        insert into _tt values (__name, __id);
    end loop;

    perform unsecure.create_perm_set('tt', 1, 'tt', 'TT Finance', _permissions := array['users.read_users'], _tenant_id := 1);
    perform unsecure.create_perm_set('tt', 1, 'tt', 'TT Templates', _permissions := array[
        'tenants.manage_tenant_templates', 'tenants.read_tenant_templates'], _tenant_id := 1);
    perform unsecure.create_perm_set('tt', 1, 'tt', 'TT Creator', _permissions := array['tenants.create_tenant'], _tenant_id := 1);

    perform unsecure.assign_permission_as_system(null::integer, (select val from _tt where key = 'full')::bigint, 'full_admin', null, 1);
    perform unsecure.assign_permission_as_system(null::integer, (select val from _tt where key = 'sys')::bigint, 'system_admin', null, 1);
    perform unsecure.assign_permission_as_system(null::integer, (select val from _tt where key = 'lim')::bigint, 'tt_templates', null, 1);
    perform unsecure.assign_permission_as_system(null::integer, (select val from _tt where key = 'creator')::bigint, 'tt_creator', null, 1);
    perform unsecure.assign_permission_as_system(null::integer, (select val from _tt where key = 'abc_admin')::bigint, 'tenant_admin', null, (select val from _tt where key = 'abc')::int);
    perform unsecure.assign_permission_as_system(null::integer, (select val from _tt where key = 'abc_admin')::bigint, 'tenant_owner', null, (select val from _tt where key = 'abc')::int);

    insert into auth.rule (created_by, updated_by, tenant_id, code, title, rule, is_global)
    values ('tt', 'tt', 1, 'tt_fin', 'TT Finance people'
           , '{"mode": "conditional", "conditions": [{"field": "provider_groups", "op": "includes", "values": ["tt-finance"]}]}', true)
    returning rule_id into __id;
    insert into _tt values ('rule_fin', __id);

    insert into auth.rule (created_by, updated_by, tenant_id, code, title, rule, is_global)
    values ('tt', 'tt', 1, 'tt_local', 'TT local', '{"mode": "always"}', false)
    returning rule_id into __id;
    insert into _tt values ('rule_local', __id);

    raise notice 'PASS: setup';
end $$;

create or replace function pg_temp.tt(_key text) returns text language sql as $$ select val from _tt where key = _key $$;

-- runs _sql (with {key} placeholders from _tt) and expects sqlstate _code
create or replace function pg_temp.tt_expect(_label text, _sql text, _code text) returns void
    language plpgsql
as
$$
declare
    __sql   text := _sql;
    __r     record;
    __state text;
    __msg   text;
begin
    for __r in select key, val from _tt order by length(key) desc loop
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

create or replace function pg_temp.tt_is(_label text, _actual text, _expected text) returns void
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

-- a tenant's shape: groups (code:title:perm sets), perm sets, mappings
create or replace function pg_temp.tt_groups(_tenant_id int) returns text
    language sql
as
$$
select coalesce(string_agg(g.code || ':' || g.title || ':' || g.is_external || ':' || g.is_system || ':[' || coalesce(
        (select string_agg(ps.code, ',' order by ps.code)
         from auth.permission_assignment pa
                  inner join auth.perm_set ps on ps.perm_set_id = pa.perm_set_id
         where pa.user_group_id = g.user_group_id), '') || ']', ' | ' order by g.code), '')
from auth.user_group g
where g.tenant_id = _tenant_id;
$$;

create or replace function pg_temp.tt_perm_sets(_tenant_id int) returns text
    language sql
as
$$
select coalesce(string_agg(ps.code, ',' order by ps.code), '')
from auth.perm_set ps
where ps.tenant_id = _tenant_id;
$$;

create or replace function pg_temp.tt_mappings(_tenant_id int) returns text
    language sql
as
$$
select coalesce(string_agg(g.code || ':' || coalesce(m.provider_code, '-') || ':' || coalesce(m.mapped_object_id, '-')
                               || ':' || coalesce(m.mapped_object_name, '-') || ':' || coalesce(m.mapped_role, '-')
                               || ':' || coalesce(r.code, '-'), ' | ' order by g.code, m.user_group_mapping_id), '')
from auth.user_group_mapping m
         inner join auth.user_group g on g.user_group_id = m.user_group_id
         left join auth.rule r on r.rule_id = m.rule_id
where g.tenant_id = _tenant_id;
$$;
