set search_path = public, const, ext, stage, helpers, internal, unsecure, auth, triggers;

-- ============================================================================
-- TEST 2: admin of B may rename B, but changing is_removable or code needs
--         tenant 1 (otherwise B could make itself undeletable, or reuse a code
--         past the identity ledger).
-- ============================================================================
do $$
declare
    __b_id       int    := (select val::int from _a05 where key = 'b_id');
    __admin_b_id bigint := (select val::bigint from _a05 where key = 'admin_b_id');
    __title      text;
    __raised     text;
begin
    raise notice 'TEST 2: update_tenant on own tenant';

    select t.__title from auth.update_tenant('audit05', __admin_b_id, 'audit05-t2', __b_id, 'Audit05 Tenant B renamed') t
    into __title;
    if __title is distinct from 'Audit05 Tenant B renamed' then
        raise exception '  FAIL: rename returned title %', __title;
    end if;

    begin
        perform auth.update_tenant('audit05', __admin_b_id, 'audit05-t2', __b_id, 'Audit05 Tenant B renamed', _is_removable := false);
    exception when others then
        __raised := sqlstate;
    end;
    if __raised is distinct from '32001' then
        raise exception '  FAIL: is_removable change: expected 32001, got %', coalesce(__raised, 'no error');
    end if;

    __raised := null;
    begin
        perform auth.update_tenant('audit05', __admin_b_id, 'audit05-t2', __b_id, 'Audit05 Tenant B renamed', _code := 'audit05_b_new');
    exception when others then
        __raised := sqlstate;
    end;
    if __raised is distinct from '32001' then
        raise exception '  FAIL: code change: expected 32001, got %', coalesce(__raised, 'no error');
    end if;

    if not exists(select from auth.tenant where tenant_id = __b_id and is_removable and code = 'audit05_b') then
        raise exception '  FAIL: is_removable or code of B changed';
    end if;

    raise notice '  PASS: rename ok, is_removable and code changes 32001';
end $$;
