set search_path = public, const, ext, stage, helpers, internal, unsecure, auth, triggers;

-- ============================================================================
-- SETUP
--   tenant A, tenant B : created the normal way
--   owner_a     : tenant-wide owner of A, no perm set
--   group_owner : owner of A's tenant_members group only, no perm set
--   member      : plain user
--   resource type 'd05_doc' for the resource-access checks
-- ============================================================================
do $$
declare
    __a_id           int;
    __b_id           int;
    __owner_a_id     bigint;
    __group_owner_id bigint;
    __member_id      bigint;
    __ga_members_id  int;
begin
    raise notice '';
    raise notice '=================================================================';
    raise notice 'Audit D-05: ownership is a perm set - Starting';
    raise notice '=================================================================';

    select t.__tenant_id from auth.create_tenant('auditd05', 1, 'auditd05-setup', 'AuditD05 Tenant A', 'auditd05_a') t into __a_id;
    select t.__tenant_id from auth.create_tenant('auditd05', 1, 'auditd05-setup', 'AuditD05 Tenant B', 'auditd05_b') t into __b_id;

    insert into auth.user_info (created_by, updated_by, user_type_code, username, original_username, display_name, can_login)
    values ('auditd05', 'auditd05', 'normal', 'auditd05_owner_a', 'auditd05_owner_a', 'AuditD05 Owner A', true)
    returning user_id into __owner_a_id;
    insert into auth.user_info (created_by, updated_by, user_type_code, username, original_username, display_name, can_login)
    values ('auditd05', 'auditd05', 'normal', 'auditd05_group_owner', 'auditd05_group_owner', 'AuditD05 Group Owner', true)
    returning user_id into __group_owner_id;
    insert into auth.user_info (created_by, updated_by, user_type_code, username, original_username, display_name, can_login)
    values ('auditd05', 'auditd05', 'normal', 'auditd05_member', 'auditd05_member', 'AuditD05 Member', true)
    returning user_id into __member_id;

    select user_group_id from auth.user_group where tenant_id = __a_id and code = 'tenant_members' into __ga_members_id;

    insert into auth.owner (created_by, tenant_id, user_group_id, user_id)
    values ('auditd05', __a_id, null, __owner_a_id)
         , ('auditd05', __a_id, __ga_members_id, __group_owner_id);

    insert into const.resource_type (code, path, source) values ('d05_doc', 'd05_doc', 'auditd05')
    on conflict do nothing;

    create temp table if not exists _d05 (key text primary key, val text);
    delete from _d05;
    insert into _d05 values
        ('a_id', __a_id::text), ('b_id', __b_id::text), ('owner_a_id', __owner_a_id::text),
        ('group_owner_id', __group_owner_id::text), ('member_id', __member_id::text),
        ('ga_members_id', __ga_members_id::text);

    raise notice 'SETUP: A=%, B=%, owner_a=%, group_owner=%, member=%, A.tenant_members=%',
        __a_id, __b_id, __owner_a_id, __group_owner_id, __member_id, __ga_members_id;
end $$;

create or replace function pg_temp.d05(_key text) returns text language sql as $$ select val from _d05 where key = _key $$;

create or replace function pg_temp.d05_check(_label text, _actual boolean, _expected boolean) returns void
    language plpgsql
as
$$
begin
    if _actual is not distinct from _expected then
        raise notice 'PASS: %', _label;
    else
        raise notice 'FAIL: % (got %, expected %)', _label, _actual, _expected;
    end if;
end;
$$;
