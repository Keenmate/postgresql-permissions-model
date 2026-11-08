set search_path = public, const, ext, stage, helpers, internal, unsecure, auth, triggers;

-- ============================================================================
-- TEST 3: admin of B may soft-delete B itself; restoring or purging it needs
--         tenant 1.
-- ============================================================================
do $$
declare
    __b_id       int    := (select val::int from _a05 where key = 'b_id');
    __b_uuid     uuid   := (select val::uuid from _a05 where key = 'b_uuid');
    __admin_b_id bigint := (select val::bigint from _a05 where key = 'admin_b_id');
    __deleted_id int;
    __raised     text;
begin
    raise notice 'TEST 3: own-tenant soft delete';

    select d.__tenant_id from auth.delete_tenant('audit05', __admin_b_id, 'audit05-t3', __b_uuid, __b_id) d
    into __deleted_id;
    if __deleted_id is distinct from __b_id then
        raise exception '  FAIL: delete_tenant returned %, expected %', __deleted_id, __b_id;
    end if;
    if not exists(select from auth.tenant where tenant_id = __b_id and deleted_at is not null) then
        raise exception '  FAIL: B is not soft-deleted';
    end if;

    begin
        perform auth.restore_tenant('audit05', __admin_b_id, 'audit05-t3', __b_uuid, __b_id);
    exception when others then
        __raised := sqlstate;
    end;
    if __raised is distinct from '32001' then
        raise exception '  FAIL: restore own: expected 32001, got %', coalesce(__raised, 'no error');
    end if;

    __raised := null;
    begin
        perform auth.purge_tenant('audit05', __admin_b_id, 'audit05-t3', __b_uuid, __b_id);
    exception when others then
        __raised := sqlstate;
    end;
    if __raised is distinct from '32001' then
        raise exception '  FAIL: purge own: expected 32001, got %', coalesce(__raised, 'no error');
    end if;

    if not exists(select from auth.tenant where tenant_id = __b_id) then
        raise exception '  FAIL: B was purged';
    end if;

    raise notice '  PASS: B soft-deleted by its admin; restore and purge 32001';
end $$;
