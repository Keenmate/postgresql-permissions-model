set search_path = public, const, ext, stage, helpers, internal, unsecure, auth, triggers;

-- ============================================================================
-- TEST 1: admin of B and owner of B cannot delete / restore / purge tenant C,
--         and cannot create tenants (all 32001). C stays live.
--         (Before v2.5 the permission was checked in the caller's _tenant_id and
--         the action applied to whatever _tenant_uuid named.)
-- ============================================================================
do $$
declare
    __b_id       int    := (select val::int from _a05 where key = 'b_id');
    __c_uuid     uuid   := (select val::uuid from _a05 where key = 'c_uuid');
    __admin_b_id bigint := (select val::bigint from _a05 where key = 'admin_b_id');
    __owner_b_id bigint := (select val::bigint from _a05 where key = 'owner_b_id');
    __caller     bigint;
    __op         text;
    __raised     text;
begin
    raise notice 'TEST 1: tenant B admin/owner cannot act on tenant C or create tenants';

    foreach __caller in array array[__admin_b_id, __owner_b_id] loop
        foreach __op in array array['delete', 'restore', 'purge', 'create'] loop
            __raised := null;
            begin
                case __op
                    when 'delete'  then perform auth.delete_tenant('audit05', __caller, 'audit05-t1', __c_uuid, __b_id);
                    when 'restore' then perform auth.restore_tenant('audit05', __caller, 'audit05-t1', __c_uuid, __b_id);
                    when 'purge'   then perform auth.purge_tenant('audit05', __caller, 'audit05-t1', __c_uuid, __b_id);
                    when 'create'  then perform auth.create_tenant('audit05', __caller, 'audit05-t1', 'Audit05 Rogue', 'audit05_rogue_' || __caller, _tenant_id := __b_id);
                end case;
            exception when others then
                __raised := sqlstate;
            end;
            if __raised is distinct from '32001' then
                raise exception '  FAIL: caller % %: expected 32001, got %', __caller, __op, coalesce(__raised, 'no error');
            end if;
        end loop;
    end loop;

    if not exists(select from auth.tenant where uuid = __c_uuid and deleted_at is null) then
        raise exception '  FAIL: tenant C is no longer live';
    end if;

    raise notice '  PASS: admin and owner of B get 32001 for delete/restore/purge of C and create; C live';
end $$;
