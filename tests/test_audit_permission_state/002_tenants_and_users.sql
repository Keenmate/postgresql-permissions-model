set search_path = public, const, ext, stage, helpers, internal, unsecure, auth, triggers;

-- ============================================================================
-- TEST 4: nobody holds permissions in a soft-deleted tenant, owners included;
--         restore brings them back
--         (before v2.7 the next check rebuilt full permissions; owners always passed)
-- ============================================================================
do $$
declare
    __b_id int := (select val::int from _a04 where key = 'b_id');
begin
    raise notice 'TEST 4: soft-deleted tenant';

    perform unsecure.soft_delete_tenant('audit04', 1, 'audit04-t4', __b_id);

    if pg_temp.a04_can('u_group') or pg_temp.a04_can('u_direct') or pg_temp.a04_can('u_mapped') or pg_temp.a04_can('owner_b') then
        raise exception '  FAIL: soft-deleted tenant: group %, direct %, mapped %, owner %',
            pg_temp.a04_can('u_group'), pg_temp.a04_can('u_direct'), pg_temp.a04_can('u_mapped'), pg_temp.a04_can('owner_b');
    end if;

    perform unsecure.restore_tenant('audit04', 1, 'audit04-t4', __b_id);

    if not (pg_temp.a04_can('u_group') and pg_temp.a04_can('u_direct') and pg_temp.a04_can('u_mapped') and pg_temp.a04_can('owner_b')) then
        raise exception '  FAIL: restored tenant does not grant again';
    end if;

    raise notice '  PASS: all denied while soft-deleted (owner too), all restored';
end $$;

-- ============================================================================
-- TEST 5: a disabled or locked user is denied even with a warm cache, and the
--         silent check returns false instead of raising
-- ============================================================================
do $$
declare
    __u_direct bigint := (select val::bigint from _a04 where key = 'u_direct');
    __raised   text;
begin
    raise notice 'TEST 5: disabled / locked user, warm cache';

    if not pg_temp.a04_can('u_direct') then          -- warms the cache
        raise exception '  FAIL: precondition';
    end if;

    -- direct UPDATE: no auth.disable_user, so nothing but the state check protects
    update auth.user_info set is_active = false where user_id = __u_direct;
    if pg_temp.a04_can('u_direct') then
        raise exception '  FAIL: disabled user still has the permission';
    end if;
    begin
        perform auth.has_permission(__u_direct, 'audit04', (select val from _a04 where key = 'perm'),
                                    (select val::int from _a04 where key = 'b_id'));
    exception when others then
        __raised := sqlstate;
    end;
    if __raised is distinct from '33003' then
        raise exception '  FAIL: throwing check for disabled user: expected 33003, got %', coalesce(__raised, 'no error');
    end if;
    update auth.user_info set is_active = true, is_locked = true where user_id = __u_direct;

    if pg_temp.a04_can('u_direct') then
        raise exception '  FAIL: locked user still has the permission';
    end if;
    update auth.user_info set is_locked = false where user_id = __u_direct;

    if auth.has_permission(-42, 'audit04', 'audit04_perm', 1, false) then
        raise exception '  FAIL: unknown user granted';
    end if;

    raise notice '  PASS: disabled and locked denied with a warm cache, silent check returns false, unknown user false';
end $$;

-- ============================================================================
-- TEST 6: a disabled or locked tenant owner no longer passes the owner shortcut
-- ============================================================================
do $$
declare
    __owner_b bigint := (select val::bigint from _a04 where key = 'owner_b');
begin
    raise notice 'TEST 6: disabled / locked owner';

    update auth.user_info set is_active = false where user_id = __owner_b;
    if pg_temp.a04_can('owner_b') then
        raise exception '  FAIL: disabled owner passes';
    end if;
    update auth.user_info set is_active = true, is_locked = true where user_id = __owner_b;
    if pg_temp.a04_can('owner_b') then
        raise exception '  FAIL: locked owner passes';
    end if;
    update auth.user_info set is_locked = false where user_id = __owner_b;
    if not pg_temp.a04_can('owner_b') then
        raise exception '  FAIL: owner should pass again';
    end if;

    raise notice '  PASS: disabled and locked owners denied, active owner passes';
end $$;
