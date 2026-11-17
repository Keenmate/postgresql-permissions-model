set search_path = public, const, ext, stage, helpers, internal, unsecure, auth, triggers;

-- ============================================================================
-- SETUP
--   tenant ah_abc (Tenant Admins / Tenant Members from the default template)
--   ABC perm set "AH Reader" (users.read_users), group "AH Readers" (AH Reader)
--   users
--     ah_owner - owner row in ABC
--     ah_admin - tenant_admin in ABC
--     ah_padmin - tenant_admin + AH Perms (permissions.assign/unassign/update) in ABC
--     ah_user, ah_user2 - nothing
--     ah_full  - full_admin in tenant 1
-- ============================================================================
create temp table if not exists _ah (key text primary key, val text);

do $$
declare
    __id   bigint;
    __t    int;
    __g    int;
    __name text;
begin
    raise notice '';
    raise notice '=================================================================';
    raise notice 'Audit: tenant owners above tenant admins - Starting';
    raise notice '=================================================================';

    select t.__tenant_id from auth.create_tenant('ah', 1, 'ah', 'AH ABC', 'ah_abc') t into __t;
    insert into _ah values ('abc', __t);

    foreach __name in array array['owner', 'admin', 'padmin', 'user', 'user2', 'full']
    loop
        insert into auth.user_info (created_by, updated_by, user_type_code, username, original_username, display_name, email, can_login)
        values ('ah', 'ah', 'normal', 'ah_' || __name, 'ah_' || __name, 'AH ' || __name, 'ah_' || __name || '@test.com', true)
        returning user_id into __id;
        insert into _ah values (__name, __id);
    end loop;

    insert into auth.owner (created_by, tenant_id, user_group_id, user_id)
    values ('ah', __t, null, (select val from _ah where key = 'owner')::bigint);
    perform unsecure.assign_permission_as_system(null::integer, (select val from _ah where key = 'admin')::bigint, 'tenant_admin', null, __t);
    perform unsecure.assign_permission_as_system(null::integer, (select val from _ah where key = 'full')::bigint, 'full_admin', null, 1);

    perform unsecure.create_perm_set('ah', 1, 'ah', 'AH Perms', _permissions := array['permissions.assign_permission'
        , 'permissions.unassign_permission', 'permissions.update_permission_set'], _tenant_id := __t);
    perform unsecure.assign_permission_as_system(null::integer, (select val from _ah where key = 'padmin')::bigint, 'tenant_admin', null, __t);
    perform unsecure.assign_permission_as_system(null::integer, (select val from _ah where key = 'padmin')::bigint, 'ah_perms', null, __t);
    perform unsecure.create_perm_set('ah', 1, 'ah', 'AH Reader', _permissions := array['users.read_users'], _tenant_id := __t);
    select g.__user_group_id from unsecure.create_user_group('ah', 1, 'ah', 'AH Readers', _tenant_id := __t) g into __g;
    insert into _ah values ('g_readers', __g);
    perform unsecure.assign_permission('ah', 1, 'ah', __g, null, 'ah_reader', _tenant_id := __t);

    insert into _ah values ('g_admins', (select ug.user_group_id from auth.user_group ug where ug.tenant_id = __t and ug.code = 'tenant_admins'));
    insert into _ah values ('g_members', (select ug.user_group_id from auth.user_group ug where ug.tenant_id = __t and ug.code = 'tenant_members'));
    insert into _ah values ('ps_admin', (select ps.perm_set_id from auth.perm_set ps where ps.tenant_id = __t and ps.code = 'tenant_admin'));

    raise notice 'PASS: setup';
end $$;

create or replace function pg_temp.ah(_key text) returns text language sql as $$ select val from _ah where key = _key $$;

-- runs _sql (with {key} placeholders from _ah) and expects sqlstate _code
create or replace function pg_temp.ah_expect(_label text, _sql text, _code text) returns void
    language plpgsql
as
$$
declare
    __sql   text := _sql;
    __r     record;
    __state text;
    __msg   text;
begin
    for __r in select key, val from _ah order by length(key) desc loop
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

create or replace function pg_temp.ah_is(_label text, _actual text, _expected text) returns void
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
