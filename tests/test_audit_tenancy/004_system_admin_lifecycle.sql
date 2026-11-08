set search_path = public, const, ext, stage, helpers, internal, unsecure, auth, triggers;

-- ============================================================================
-- TEST 4: a tenant-1 admin (not user 1) still runs the full lifecycle:
--         restore B, delete + purge C, create a tenant, set is_removable/code
-- ============================================================================
do $$
declare
    __b_id        int    := (select val::int from _a05 where key = 'b_id');
    __b_uuid      uuid   := (select val::uuid from _a05 where key = 'b_uuid');
    __c_id        int    := (select val::int from _a05 where key = 'c_id');
    __c_uuid      uuid   := (select val::uuid from _a05 where key = 'c_uuid');
    __sysadmin_id bigint := (select val::bigint from _a05 where key = 'sysadmin_id');
    __new_id      int;
begin
    raise notice 'TEST 4: tenant-1 admin lifecycle';

    perform auth.restore_tenant('audit05', __sysadmin_id, 'audit05-t4', __b_uuid, 1);
    if not exists(select from auth.tenant where tenant_id = __b_id and deleted_at is null) then
        raise exception '  FAIL: B not restored';
    end if;

    perform auth.delete_tenant('audit05', __sysadmin_id, 'audit05-t4', __c_uuid, 1);
    perform auth.purge_tenant('audit05', __sysadmin_id, 'audit05-t4', __c_uuid, 1);
    if exists(select from auth.tenant where tenant_id = __c_id) then
        raise exception '  FAIL: C not purged';
    end if;

    select t.__tenant_id from auth.create_tenant('audit05', __sysadmin_id, 'audit05-t4', 'Audit05 Tenant D', 'audit05_d') t
    into __new_id;
    if __new_id is null then
        raise exception '  FAIL: create_tenant returned no tenant';
    end if;

    raise notice '  PASS: restore B, delete+purge C, create D (%)', __new_id;
end $$;
