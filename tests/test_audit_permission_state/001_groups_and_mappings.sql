set search_path = public, const, ext, stage, helpers, internal, unsecure, auth, triggers;

-- ============================================================================
-- TEST 1: baseline - every path grants
-- ============================================================================
do $$
begin
    raise notice 'TEST 1: baseline';
    if not (pg_temp.a04_can('u_group') and pg_temp.a04_can('u_direct') and pg_temp.a04_can('u_mapped') and pg_temp.a04_can('owner_b')) then
        raise exception '  FAIL: baseline: group %, direct %, mapped %, owner %',
            pg_temp.a04_can('u_group'), pg_temp.a04_can('u_direct'), pg_temp.a04_can('u_mapped'), pg_temp.a04_can('owner_b');
    end if;
    raise notice '  PASS: group, direct, mapped and owner all grant';
end $$;

-- ============================================================================
-- TEST 2: a disabled group grants nothing; membership kept; re-enable restores
--         (before v2.7 the rebuild after the disable re-granted everything)
-- ============================================================================
do $$
declare
    __g_id   int := (select val::int from _a04 where key = 'g_id');
    __raised text;
begin
    raise notice 'TEST 2: disabled group';

    update auth.user_group set is_active = false where user_group_id = __g_id;

    if pg_temp.a04_can('u_group') then
        raise exception '  FAIL: member of a disabled group still has the permission';
    end if;

    begin
        perform auth.has_permission((select val::bigint from _a04 where key = 'u_group'), 'audit04',
                                    (select val from _a04 where key = 'perm'), (select val::int from _a04 where key = 'b_id'));
    exception when others then
        __raised := sqlstate;
    end;
    if __raised is distinct from '32001' then
        raise exception '  FAIL: throwing check: expected 32001, got %', coalesce(__raised, 'no error');
    end if;

    if not exists(select from auth.user_group_member where user_group_id = __g_id) then
        raise exception '  FAIL: membership was deleted';
    end if;

    update auth.user_group set is_active = true where user_group_id = __g_id;
    if not pg_temp.a04_can('u_group') then
        raise exception '  FAIL: re-enabled group does not grant again';
    end if;

    raise notice '  PASS: disabled group denies (32001), membership kept, re-enable restores';
end $$;

-- ============================================================================
-- TEST 3: mapped membership counts only while the provider is active and the
--         user's identity at that provider is not disabled
-- ============================================================================
do $$
declare
    __u_mapped bigint := (select val::bigint from _a04 where key = 'u_mapped');
begin
    raise notice 'TEST 3: inactive provider / identity';

    update auth.provider set is_active = false where code = 'audit04_idp';
    if pg_temp.a04_can('u_mapped') then
        raise exception '  FAIL: mapped membership of an inactive provider still grants';
    end if;
    update auth.provider set is_active = true where code = 'audit04_idp';
    if not pg_temp.a04_can('u_mapped') then
        raise exception '  FAIL: re-enabled provider does not grant again';
    end if;

    update auth.user_identity set is_active = false where user_id = __u_mapped and provider_code = 'audit04_idp';
    if pg_temp.a04_can('u_mapped') then
        raise exception '  FAIL: mapped membership of a disabled identity still grants';
    end if;
    update auth.user_identity set is_active = true where user_id = __u_mapped and provider_code = 'audit04_idp';
    if not pg_temp.a04_can('u_mapped') then
        raise exception '  FAIL: re-enabled identity does not grant again';
    end if;

    raise notice '  PASS: provider and identity disable deny, re-enable restores';
end $$;
