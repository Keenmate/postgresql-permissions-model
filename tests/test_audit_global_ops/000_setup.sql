set search_path = public, const, ext, stage, helpers, internal, unsecure, auth, triggers;

-- ============================================================================
-- SETUP
--   tenant B
--   admin_b   : perm set 'd07_all' in B holding EVERY permission of the tree
--   sysadmin  : the same perm set in tenant 1
--   nobody    : a user without any permission
--   a translation of tenant 1 to aim at
-- ============================================================================
do $$
declare
    __b_id        int;
    __admin_b_id  bigint;
    __sysadmin_id bigint;
    __nobody_id   bigint;
    __ps_b        int;
    __ps_1        int;
    __tr_id       int;
begin
    raise notice '';
    raise notice '=================================================================';
    raise notice 'Audit D-07: global operations - Starting';
    raise notice '=================================================================';

    select t.__tenant_id from auth.create_tenant('auditd07', 1, 'auditd07-setup', 'AuditD07 Tenant B', 'auditd07_b') t into __b_id;

    insert into auth.user_info (created_by, updated_by, user_type_code, username, original_username, display_name, can_login)
    values ('auditd07', 'auditd07', 'normal', 'auditd07_admin_b', 'auditd07_admin_b', 'AuditD07 Admin B', true)
    returning user_id into __admin_b_id;
    insert into auth.user_info (created_by, updated_by, user_type_code, username, original_username, display_name, can_login)
    values ('auditd07', 'auditd07', 'normal', 'auditd07_sysadmin', 'auditd07_sysadmin', 'AuditD07 Sysadmin', true)
    returning user_id into __sysadmin_id;
    insert into auth.user_info (created_by, updated_by, user_type_code, username, original_username, display_name, can_login)
    values ('auditd07', 'auditd07', 'normal', 'auditd07_nobody', 'auditd07_nobody', 'AuditD07 Nobody', true)
    returning user_id into __nobody_id;

    insert into auth.perm_set (created_by, updated_by, tenant_id, code, is_system, is_assignable)
    values ('auditd07', 'auditd07', __b_id, 'd07_all', false, true) returning perm_set_id into __ps_b;
    insert into auth.perm_set (created_by, updated_by, tenant_id, code, is_system, is_assignable)
    values ('auditd07', 'auditd07', 1, 'd07_all', false, true) returning perm_set_id into __ps_1;
    insert into auth.perm_set_perm (created_by, perm_set_id, permission_id)
    select 'auditd07', ps.id, p.permission_id
    from auth.permission p, unnest(array[__ps_b, __ps_1]) as ps(id);
    perform unsecure.assign_permission_as_system(null::integer, __admin_b_id, 'd07_all', null, __b_id);
    perform unsecure.assign_permission_as_system(null::integer, __sysadmin_id, 'd07_all', null, 1);

    select translation_id from public.translation where tenant_id = 1 order by translation_id limit 1 into __tr_id;

    create temp table if not exists _d07 (key text primary key, val text);
    delete from _d07;
    insert into _d07 values
        ('b_id', __b_id::text), ('admin_b_id', __admin_b_id::text), ('sysadmin_id', __sysadmin_id::text),
        ('nobody_id', __nobody_id::text), ('tr_id', __tr_id::text);

    raise notice 'SETUP: B=%, admin_b=%, sysadmin=%, nobody=%, translation=%', __b_id, __admin_b_id, __sysadmin_id, __nobody_id, __tr_id;
end $$;

-- Runs _sql with {key} placeholders from _d07; _code null = must succeed.
create or replace function pg_temp.d07_expect(_label text, _sql text, _code text) returns void
    language plpgsql
as
$$
declare
    __sql   text := _sql;
    __r     record;
    __state text;
    __msg   text;
begin
    for __r in select key, val from _d07 loop
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
