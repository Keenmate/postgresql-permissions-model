set search_path = public, const, ext, stage, helpers, internal, unsecure, auth, triggers;

-- ============================================================================
-- TEST 3: assign_permission refuses a group from another tenant (33011)
-- ============================================================================
do $$
declare
    __admin_id   bigint := (select val::bigint from _tss where key = 'admin_id');
    __group_b_id int    := (select val::int from _tss where key = 'group_b_id');
    __raised     text;
begin
    raise notice 'TEST 3: assign_permission with a foreign-tenant group';

    begin
        perform auth.assign_permission('tss_test', __admin_id, 'tss-3', __group_b_id, null, 'tenant_member', null, 1);
    exception when others then
        __raised := sqlstate;
    end;

    if __raised is distinct from '33011' then
        raise exception '  FAIL: expected 33011, got %', coalesce(__raised, 'no error');
    end if;

    raise notice '  PASS: foreign-tenant group rejected with 33011';
end $$;

-- ============================================================================
-- TEST 4: unassign_permission refuses an assignment of another tenant (32009)
-- ============================================================================
do $$
declare
    __admin_id        bigint := (select val::bigint from _tss where key = 'admin_id');
    __assignment_b_id bigint := (select val::bigint from _tss where key = 'assignment_b_id');
    __raised          text;
begin
    raise notice 'TEST 4: unassign_permission with a foreign-tenant assignment';

    begin
        perform auth.unassign_permission('tss_test', __admin_id, 'tss-4', __assignment_b_id, 1);
    exception when others then
        __raised := sqlstate;
    end;

    if __raised is distinct from '32009' then
        raise exception '  FAIL: expected 32009, got %', coalesce(__raised, 'no error');
    end if;

    if not exists(select from auth.permission_assignment where assignment_id = __assignment_b_id) then
        raise exception '  FAIL: foreign-tenant assignment was deleted';
    end if;

    raise notice '  PASS: foreign-tenant assignment rejected with 32009 and kept';
end $$;

-- ============================================================================
-- TEST 5: unassign_permission of an unknown id raises 32009
-- ============================================================================
do $$
declare
    __admin_id bigint := (select val::bigint from _tss where key = 'admin_id');
    __raised   text;
begin
    raise notice 'TEST 5: unassign_permission with an unknown id';

    begin
        perform auth.unassign_permission('tss_test', __admin_id, 'tss-5', -1, 1);
    exception when others then
        __raised := sqlstate;
    end;

    if __raised is distinct from '32009' then
        raise exception '  FAIL: expected 32009, got %', coalesce(__raised, 'no error');
    end if;

    raise notice '  PASS: unknown assignment rejected with 32009';
end $$;

-- ============================================================================
-- TEST 6: same-tenant assign + unassign still work
-- ============================================================================
do $$
declare
    __admin_id      bigint := (select val::bigint from _tss where key = 'admin_id');
    __group_a_id    int    := (select val::int from _tss where key = 'group_a_id');
    __assignment_id bigint;
    __deleted_id    bigint;
begin
    raise notice 'TEST 6: same-tenant assign/unassign';

    select r.__assignment_id
    from auth.assign_permission('tss_test', __admin_id, 'tss-6', __group_a_id, null, 'tenant_member', null, 1) r
    into __assignment_id;

    if __assignment_id is null then
        raise exception '  FAIL: assign_permission returned no assignment';
    end if;

    select r.__assignment_id
    from auth.unassign_permission('tss_test', __admin_id, 'tss-6', __assignment_id, 1) r
    into __deleted_id;

    if __deleted_id is distinct from __assignment_id
        or exists(select from auth.permission_assignment where assignment_id = __assignment_id) then
        raise exception '  FAIL: unassign_permission did not delete the assignment';
    end if;

    raise notice '  PASS: same-tenant assign/unassign work';
end $$;
