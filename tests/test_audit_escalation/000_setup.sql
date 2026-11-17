set search_path = public, const, ext, stage, helpers, internal, unsecure, auth, triggers;

-- ============================================================================
-- SETUP
--   tenant ESC
--     perm set "Helpdesk": every management permission, users.read_users and the
--       whole journal node, none of tenant_admin's tenant permissions
--     perm set "Small":    users.read_users
--     perm set "Elevated": tenants.update_tenant
--     group "ESC Admins": tenant_admin perm set
--     group "ESC Small":  users.read_users
--   users
--     esc_helper  - Helpdesk in ESC
--     esc_owner   - tenant owner of ESC (owner row)
--     esc_gowner  - group owner of ESC Admins, nothing else
--     esc_target  - the user things are given to
--   provider esc_aad (group mapping)
-- ============================================================================
create temp table if not exists _esc (key text primary key, val text);

do $$
declare
    __esc  int;
    __id   bigint;
    __g    int;
    __ps   int;
    __name text;
begin
    raise notice '';
    raise notice '=================================================================';
    raise notice 'Audit D-19: no privilege escalation - Starting';
    raise notice '=================================================================';

    insert into auth.provider (created_by, updated_by, code, is_active, allows_group_mapping, allows_group_sync)
    values ('esc', 'esc', 'esc_aad', true, true, false);

    select t.__tenant_id from auth.create_tenant('esc', 1, 'esc', 'ESC Tenant', 'esc_tenant') t into __esc;
    insert into _esc values ('esc', __esc);

    foreach __name in array array['helper', 'owner', 'gowner', 'target', 'target2']
    loop
        insert into auth.user_info (created_by, updated_by, user_type_code, username, original_username, display_name, email, can_login)
        values ('esc', 'esc', 'normal', 'esc_' || __name, 'esc_' || __name, 'ESC ' || __name, 'esc_' || __name || '@test.com', true)
        returning user_id into __id;
        insert into _esc values (__name, __id);
    end loop;

    select p.perm_set_id from unsecure.create_perm_set('esc', 1, 'esc', 'Helpdesk', _permissions := array[
        'permissions.assign_permission', 'permissions.unassign_permission',
        'permissions.create_permission_set', 'permissions.update_permission_set', 'permissions.delete_permission_set',
        'groups.create_member', 'groups.delete_member', 'groups.create_mapping', 'groups.delete_mapping',
        'rules.update_rule', 'api_keys.create_api_key', 'api_keys.update_permissions',
        'invitations.create_invitation', 'tenants.assign_owner', 'tenants.assign_group_owner',
        'users.read_users', 'journal'], _tenant_id := __esc) p into __ps;
    perform unsecure.create_perm_set('esc', 1, 'esc', 'Small', _permissions := array['users.read_users'], _tenant_id := __esc);
    select p.perm_set_id from unsecure.create_perm_set('esc', 1, 'esc', 'Elevated', _permissions := array['tenants.update_tenant'], _tenant_id := __esc) p into __ps;
    insert into _esc values ('ps_elevated', __ps);
    select p.perm_set_id from auth.perm_set p where p.tenant_id = __esc and p.code = 'small' into __ps;
    insert into _esc values ('ps_small', __ps);

    perform unsecure.assign_permission_as_system(null::integer, (select val from _esc where key = 'helper')::bigint, 'helpdesk', null, __esc);

    insert into auth.owner (created_by, tenant_id, user_id) values ('esc', __esc, (select val from _esc where key = 'owner')::bigint);

    select g.__user_group_id from unsecure.create_user_group('esc', 1, 'esc', 'ESC Admins', _tenant_id := __esc) g into __g;
    perform unsecure.assign_permission('esc', 1, 'esc', __g, null, 'tenant_admin', _tenant_id := __esc);
    insert into _esc values ('g_admins', __g);
    insert into auth.owner (created_by, tenant_id, user_group_id, user_id) values ('esc', __esc, __g, (select val from _esc where key = 'gowner')::bigint);

    select g.__user_group_id from unsecure.create_user_group('esc', 1, 'esc', 'ESC Small', _tenant_id := __esc) g into __g;
    perform unsecure.assign_permission('esc', 1, 'esc', __g, null, null, 'users.read_users', _tenant_id := __esc);
    insert into _esc values ('g_small', __g);

    raise notice 'PASS: setup (ESC=%)', __esc;
end $$;

create or replace function pg_temp.esc(_key text) returns text language sql as $$ select val from _esc where key = _key $$;

-- runs _sql (with {key} placeholders from _esc) and expects sqlstate _code
create or replace function pg_temp.esc_expect(_label text, _sql text, _code text) returns void
    language plpgsql
as
$$
declare
    __sql   text := _sql;
    __r     record;
    __state text;
    __msg   text;
begin
    for __r in select key, val from _esc order by length(key) desc loop
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

-- runs _sql (with {key} placeholders) and expects it to succeed
create or replace function pg_temp.esc_ok(_label text, _sql text) returns void
    language plpgsql
as
$$
declare
    __sql   text := _sql;
    __r     record;
    __state text;
    __msg   text;
begin
    for __r in select key, val from _esc order by length(key) desc loop
        __sql := replace(__sql, '{' || __r.key || '}', __r.val);
    end loop;
    begin
        execute __sql;
        raise notice 'PASS: %', _label;
    exception when others then
        get stacked diagnostics __state = returned_sqlstate, __msg = message_text;
        raise notice 'FAIL: % - got %: %', _label, __state, __msg;
    end;
end;
$$;

create or replace function pg_temp.esc_is(_label text, _actual text, _expected text) returns void
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
