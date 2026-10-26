set search_path = public, const, ext, stage, helpers, internal, unsecure, auth, triggers;

-- ============================================================================
-- TEST 1: owning one group does not make a user a tenant-wide owner
-- ============================================================================
do $$
declare
    __plain_id   bigint := (select val::bigint from _tss where key = 'plain_id');
    __group_a_id int    := (select val::int from _tss where key = 'group_a_id');
begin
    raise notice 'TEST 1: group owner vs tenant-wide owner';

    if not auth.is_owner(__plain_id, 'tss-1', __group_a_id, 1) then
        raise exception '  FAIL: is_owner(group) returned false for the group owner';
    end if;

    if auth.is_owner(__plain_id, 'tss-1', null, 1) then
        raise exception '  FAIL: is_owner(null group) returned true for a group-only owner';
    end if;

    raise notice '  PASS: group owner is owner of the group only';
end $$;

-- ============================================================================
-- TEST 2: a group-only owner does not pass unrelated permission checks
-- ============================================================================
do $$
declare
    __plain_id bigint := (select val::bigint from _tss where key = 'plain_id');
begin
    raise notice 'TEST 2: group owner gets no tenant-wide permissions';

    if auth.has_permission(__plain_id, 'tss-2', 'tenants.create_tenant', 1, _throw_err := false) then
        raise exception '  FAIL: group-only owner passed has_permission(tenants.create_tenant)';
    end if;

    raise notice '  PASS: has_permission is false for a group-only owner';
end $$;
