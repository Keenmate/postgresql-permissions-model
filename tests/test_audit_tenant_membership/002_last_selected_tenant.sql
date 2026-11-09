set search_path = public, const, ext, stage, helpers, internal, unsecure, auth, triggers;

-- ============================================================================
-- update_user_last_selected_tenant checks the TARGET user's membership.
-- ============================================================================
do $$
declare
    __t_uuid   text   := (select uuid::text from auth.tenant where tenant_id = (select val from _d03 where key = 't'));
    __direct   bigint := (select val from _d03 where key = 'direct');
    __member   bigint := (select val from _d03 where key = 'member');
    __outsider bigint := (select val from _d03 where key = 'outsider');
    __sysadmin bigint := (select val from _d03 where key = 'sysadmin');
    __state    text;
begin
    raise notice '';
    raise notice '--- 002: last selected tenant ---';

    begin
        perform auth.update_user_last_selected_tenant('d03', __direct, 'd03', __direct, __t_uuid);
        raise notice 'PASS: a member without groups selects T for themselves';
    exception when others then
        raise notice 'FAIL: d03_direct cannot select T: % %', sqlstate, sqlerrm;
    end;

    begin
        perform auth.update_user_last_selected_tenant('d03', __sysadmin, 'd03', __member, __t_uuid, 1);
        raise notice 'PASS: sysadmin (not in T) sets T for a member of T';
    exception when others then
        raise notice 'FAIL: sysadmin cannot set T for d03_member: % %', sqlstate, sqlerrm;
    end;

    begin
        perform auth.update_user_last_selected_tenant('d03', __sysadmin, 'd03', __outsider, __t_uuid, 1);
        raise notice 'FAIL: T set as last tenant of a user who is not in T';
    exception when others then
        get stacked diagnostics __state = returned_sqlstate;
        if __state = '34001' then
            raise notice 'PASS: T rejected for a user who is not in T (34001)';
        else
            raise notice 'FAIL: expected 34001, got % %', __state, sqlerrm;
        end if;
    end;
end $$;
