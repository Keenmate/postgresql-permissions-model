set search_path = public, const, ext, stage, helpers, internal, unsecure, auth, triggers;

-- ============================================================================
-- SETUP
--   tenant B, tenant C : created the normal way (create_tenant copies tenant_admin)
--   admin_b  : tenant_admin perm set in B only
--   owner_b  : tenant-wide owner of B, no perm set
--   sysadmin : full_admin (tenant 1), NOT user 1
-- ============================================================================
do $$
declare
    __b_id        int;
    __b_uuid      uuid;
    __c_id        int;
    __c_uuid      uuid;
    __admin_b_id  bigint;
    __owner_b_id  bigint;
    __sysadmin_id bigint;
begin
    raise notice '';
    raise notice '=================================================================';
    raise notice 'Audit 05: tenant lifecycle scoping - Starting';
    raise notice '=================================================================';

    select t.__tenant_id, t.__uuid from auth.create_tenant('audit05', 1, 'audit05-setup', 'Audit05 Tenant B', 'audit05_b') t
    into __b_id, __b_uuid;
    select t.__tenant_id, t.__uuid from auth.create_tenant('audit05', 1, 'audit05-setup', 'Audit05 Tenant C', 'audit05_c') t
    into __c_id, __c_uuid;

    insert into auth.user_info (created_by, updated_by, user_type_code, username, original_username, display_name, can_login)
    values ('audit05', 'audit05', 'normal', 'audit05_admin_b', 'audit05_admin_b', 'Audit05 Admin B', true)
    returning user_id into __admin_b_id;
    perform unsecure.assign_permission_as_system(null::integer, __admin_b_id, 'tenant_admin', null, __b_id);

    insert into auth.user_info (created_by, updated_by, user_type_code, username, original_username, display_name, can_login)
    values ('audit05', 'audit05', 'normal', 'audit05_owner_b', 'audit05_owner_b', 'Audit05 Owner B', true)
    returning user_id into __owner_b_id;
    insert into auth.owner (created_by, tenant_id, user_group_id, user_id)
    values ('audit05', __b_id, null, __owner_b_id);

    insert into auth.user_info (created_by, updated_by, user_type_code, username, original_username, display_name, can_login)
    values ('audit05', 'audit05', 'normal', 'audit05_sysadmin', 'audit05_sysadmin', 'Audit05 Sysadmin', true)
    returning user_id into __sysadmin_id;
    perform unsecure.assign_permission_as_system(null::integer, __sysadmin_id, 'full_admin');

    create temp table if not exists _a05 (key text primary key, val text);
    delete from _a05;
    insert into _a05 values
        ('b_id', __b_id::text), ('b_uuid', __b_uuid::text), ('c_id', __c_id::text), ('c_uuid', __c_uuid::text),
        ('admin_b_id', __admin_b_id::text), ('owner_b_id', __owner_b_id::text), ('sysadmin_id', __sysadmin_id::text);

    raise notice 'SETUP: B=%, C=%, admin_b=%, owner_b=%, sysadmin=%', __b_id, __c_id, __admin_b_id, __owner_b_id, __sysadmin_id;
end $$;
