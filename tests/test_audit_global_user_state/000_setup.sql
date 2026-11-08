set search_path = public, const, ext, stage, helpers, internal, unsecure, auth, triggers;

-- ============================================================================
-- SETUP
--   tenant B   : created the normal way
--   admin_b    : perm set 'd04_admin' in B with every users.* and mfa.* permission
--   sysadmin   : the same permissions in tenant 1 (perm set 'd04_admin' in tenant 1)
--   target     : a normal user with an email identity and a TOTP enrollment
--   blacklist  : one blacklist entry
-- ============================================================================
do $$
declare
    __b_id         int;
    __admin_b_id   bigint;
    __sysadmin_id  bigint;
    __target_id    bigint;
    __ps_b_id      int;
    __ps_1_id      int;
    __blacklist_id bigint;
begin
    raise notice '';
    raise notice '=================================================================';
    raise notice 'Audit D-04: global user state - Starting';
    raise notice '=================================================================';

    select t.__tenant_id from auth.create_tenant('auditd04', 1, 'auditd04-setup', 'AuditD04 Tenant B', 'auditd04_b') t into __b_id;

    insert into auth.user_info (created_by, updated_by, user_type_code, username, original_username, display_name, can_login)
    values ('auditd04', 'auditd04', 'normal', 'auditd04_admin_b', 'auditd04_admin_b', 'AuditD04 Admin B', true)
    returning user_id into __admin_b_id;
    insert into auth.user_info (created_by, updated_by, user_type_code, username, original_username, display_name, can_login)
    values ('auditd04', 'auditd04', 'normal', 'auditd04_sysadmin', 'auditd04_sysadmin', 'AuditD04 Sysadmin', true)
    returning user_id into __sysadmin_id;
    insert into auth.user_info (created_by, updated_by, user_type_code, username, original_username, display_name, can_login)
    values ('auditd04', 'auditd04', 'normal', 'auditd04_target', 'auditd04_target', 'AuditD04 Target', true)
    returning user_id into __target_id;

    insert into auth.user_identity (created_by, updated_by, provider_code, uid, provider_oid, user_id, password_hash, is_active)
    values ('auditd04', 'auditd04', 'email', 'auditd04_target@example.com', 'auditd04_target@example.com', __target_id, 'hash', true);

    insert into auth.perm_set (created_by, updated_by, tenant_id, code, is_system, is_assignable)
    values ('auditd04', 'auditd04', __b_id, 'd04_admin', false, true)
    returning perm_set_id into __ps_b_id;
    insert into auth.perm_set (created_by, updated_by, tenant_id, code, is_system, is_assignable)
    values ('auditd04', 'auditd04', 1, 'd04_admin', false, true)
    returning perm_set_id into __ps_1_id;
    insert into auth.perm_set_perm (created_by, perm_set_id, permission_id)
    select 'auditd04', ps.id, p.permission_id
    from auth.permission p
       , unnest(array[__ps_b_id, __ps_1_id]) as ps(id)
    where subpath(p.full_code, 0, 1)::text in ('users', 'mfa');
    perform unsecure.assign_permission_as_system(null::integer, __admin_b_id, 'd04_admin', null, __b_id);
    perform unsecure.assign_permission_as_system(null::integer, __sysadmin_id, 'd04_admin', null, 1);

    insert into auth.user_blacklist (created_by, username, reason)
    values ('auditd04', 'auditd04_banned', 'manual')
    returning blacklist_id into __blacklist_id;

    create temp table if not exists _d04 (key text primary key, val text);
    delete from _d04;
    insert into _d04 values
        ('b_id', __b_id::text), ('admin_b_id', __admin_b_id::text), ('sysadmin_id', __sysadmin_id::text),
        ('target_id', __target_id::text), ('blacklist_id', __blacklist_id::text);

    raise notice 'SETUP: B=%, admin_b=%, sysadmin=%, target=%, blacklist=%',
        __b_id, __admin_b_id, __sysadmin_id, __target_id, __blacklist_id;
end $$;

-- Runs _sql (with {key} placeholders filled from _d04); _code null = must succeed.
create or replace function pg_temp.d04_expect(_label text, _sql text, _code text) returns void
    language plpgsql
as
$$
declare
    __sql   text := _sql;
    __r     record;
    __state text;
    __msg   text;
begin
    for __r in select key, val from _d04 loop
        __sql := replace(__sql, '{' || __r.key || '}', __r.val);
    end loop;
    begin
        execute __sql;
        if _code is null then
            raise notice 'PASS: % - succeeded', _label;
        else
            raise notice 'FAIL: % - no error raised (expected %)', _label, _code;
        end if;
        return;
    exception when others then
        get stacked diagnostics __state = returned_sqlstate, __msg = message_text;
    end;
    if __state = _code then
        raise notice 'PASS: % - %', _label, _code;
    else
        raise notice 'FAIL: % - got % (expected %): %', _label, __state, coalesce(_code, 'success'), __msg;
    end if;
end;
$$;

create or replace function pg_temp.d04(_key text) returns text language sql as $$ select val from _d04 where key = _key $$;
