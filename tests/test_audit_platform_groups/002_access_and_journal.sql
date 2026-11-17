set search_path = public, const, ext, stage, helpers, internal, unsecure, auth, triggers;

-- ============================================================================
-- Platform members see the tenants in their own tenant list
-- ============================================================================
do $$
declare
    __anna bigint := pg_temp.pg('anna')::bigint;
begin
    raise notice 'TEST 5: available tenants and the last selected tenant';

    perform pg_temp.pg_is('anna''s tenants, marked as platform access'
        , (select string_agg(t.__tenant_code || ':' || t.__is_platform_access, ',' order by t.__tenant_code)
           from auth.get_user_available_tenants(__anna, 'pg', __anna) t)
        , 'pg_abc:true,pg_cde:true');

    perform auth.update_user_last_selected_tenant('pg', __anna, 'pg', __anna
        , (select uuid::text from auth.tenant where tenant_id = pg_temp.pg('abc')::int));
    perform pg_temp.pg_is('anna selected ABC'
        , (select last_selected_tenant_id::text from auth.user_info where user_id = __anna), pg_temp.pg('abc'));
end $$;

select pg_temp.pg_expect('anna selects FGH (not in scope)'
    , 'select * from auth.update_user_last_selected_tenant(''pg'', {anna}, ''pg'', {anna}, (select uuid::text from auth.tenant where tenant_id = {fgh}))', '34001');

-- ============================================================================
-- Journal: the tenant sees "Platform support", tenant 1 sees the person
-- ============================================================================
do $$
declare
    __anna bigint := pg_temp.pg('anna')::bigint;
    __abc  int := pg_temp.pg('abc')::int;
    __j    record;
begin
    raise notice 'TEST 6: the journal hides the person from the tenant';

    perform auth.create_user_group('pg_anna', __anna, 'pg', 'Anna Group', _tenant_id := __abc);

    select j.journal_id, j.created_by, j.user_id, j.platform_user_id, j.platform_created_by
    from public.journal j
    where j.tenant_id = __abc and j.event_id = 13001 and j.correlation_id = 'pg'
    order by j.journal_id desc limit 1
    into __j;
    insert into _pg values ('j_anna', __j.journal_id);

    perform pg_temp.pg_is('stored as Platform support', __j.created_by || ' ' || coalesce(__j.user_id::text, 'null'), 'Platform support null');
    perform pg_temp.pg_is('the person is kept apart', __j.platform_user_id::text || ' ' || __j.platform_created_by, __anna || ' pg_anna');

    perform pg_temp.pg_is('ABC admin sees Platform support'
        , (select s.__created_by || ' ' || coalesce(s.__user_id::text, 'null')
           from public.search_journal(pg_temp.pg('abc_admin')::bigint, 'pg', _event_id := 13001, _page_size := 100, _tenant_id := __abc) s
           where s.__journal_id = __j.journal_id)
        , 'Platform support null');
    perform pg_temp.pg_is('ABC admin''s entry shows Platform support'
        , (select e.__created_by from public.get_journal_entry(pg_temp.pg('abc_admin')::bigint, 'pg', __abc, __j.journal_id) e)
        , 'Platform support');
    perform pg_temp.pg_is('full_admin sees anna from tenant 1'
        , (select s.__created_by || ' ' || s.__user_id::text
           from public.search_journal(pg_temp.pg('full')::bigint, 'pg', _event_id := 13001, _page_size := 100, _tenant_id := 1) s
           where s.__journal_id = __j.journal_id)
        , 'pg_anna ' || __anna);
    perform pg_temp.pg_is('system_admin sees Platform support from tenant 1'
        , (select s.__created_by
           from public.search_journal(pg_temp.pg('sys')::bigint, 'pg', _event_id := 13001, _page_size := 100, _tenant_id := 1) s
           where s.__journal_id = __j.journal_id)
        , 'Platform support');

    -- a tenant admin acting in their own tenant is journaled by name
    perform auth.create_user_group('pg_abc_admin', pg_temp.pg('abc_admin')::bigint, 'pg', 'Admin Group', _tenant_id := __abc);
    perform pg_temp.pg_is('a member is journaled by name'
        , (select j.created_by from public.journal j
           where j.tenant_id = __abc and j.event_id = 13001 and j.correlation_id = 'pg'
           order by j.journal_id desc limit 1)
        , 'pg_abc_admin');
end $$;

-- ============================================================================
-- Changes reach the members right away
-- ============================================================================
do $$
declare
    __full bigint := pg_temp.pg('full')::bigint;
    __anna bigint := pg_temp.pg('anna')::bigint;
    __gina bigint := pg_temp.pg('gina')::bigint;
begin
    raise notice 'TEST 7: tenant opt-out';
    perform auth.update_tenant_platform_access('pg', __full, 'pg', pg_temp.pg('cde')::int, false);
    perform pg_temp.pg_is('anna lost CDE', pg_temp.pg_holds(__anna, 'tenants.update_tenant'), 'pg_abc');
    perform pg_temp.pg_is('gina lost CDE (even from "all")', pg_temp.pg_holds(__gina, 'tenants.update_tenant'), 'pg_abc,pg_fgh');
    perform pg_temp.pg_is('CDE left anna''s tenant list'
        , (select string_agg(t.__tenant_code, ',' order by t.__tenant_code) from auth.get_user_available_tenants(__anna, 'pg', __anna) t)
        , 'pg_abc');
    perform auth.update_tenant_platform_access('pg', __full, 'pg', pg_temp.pg('cde')::int, true);
    perform pg_temp.pg_is('opting back in restores it', pg_temp.pg_holds(__anna, 'tenants.update_tenant'), 'pg_abc,pg_cde');

    raise notice 'TEST 8: scope changes';
    perform auth.update_platform_group_scope('pg', __full, 'pg', pg_temp.pg('g_eu')::int, false
        , array[pg_temp.pg('abc')::int, pg_temp.pg('fgh')::int]);
    perform pg_temp.pg_is('anna: ABC and FGH now', pg_temp.pg_holds(__anna, 'tenants.update_tenant'), 'pg_abc,pg_fgh');
    perform pg_temp.pg_is('get_platform_groups shows the new scope'
        , (select array_to_string(p.__scope_tenant_ids, ',') from auth.get_platform_groups(__full, 'pg') p
           where p.__user_group_id = pg_temp.pg('g_eu')::int)
        , pg_temp.pg('abc') || ',' || pg_temp.pg('fgh'));

    raise notice 'TEST 9: tenant 1 only when listed';
    perform auth.update_platform_group_scope('pg', __full, 'pg', pg_temp.pg('g_eu')::int, false, array[1]);
    perform pg_temp.pg_is('anna: tenant 1 only', pg_temp.pg_holds(__anna, 'tenants.update_tenant'), 'primary');
    perform pg_temp.pg_is('anna is still no member of tenant 1'
        , (select count(*)::text from auth.tenant_memberships where user_id = __anna), '0');

    raise notice 'TEST 10: the group''s perm set and members';
    perform auth.update_platform_group_scope('pg', __full, 'pg', pg_temp.pg('g_eu')::int, false, array[pg_temp.pg('abc')::int]);
    perform pg_temp.pg_is('anna: ABC', pg_temp.pg_holds(__anna, 'tenants.update_tenant'), 'pg_abc');
    perform unsecure.delete_perm_set_permissions('pg', 1, 'pg'
        , (select perm_set_id from auth.perm_set where tenant_id = 1 and code = 'pg_admin'), array['tenants.update_tenant'], 1);
    perform pg_temp.pg_is('the perm set edit reaches anna in ABC', pg_temp.pg_holds(__anna, 'tenants.update_tenant'), '');
    perform pg_temp.pg_is('anna still reads users in ABC', pg_temp.pg_holds(__anna, 'users.read_users'), 'pg_abc');
    perform auth.disable_user_group('pg', __full, 'pg', pg_temp.pg('g_eu')::int, 1);
    perform pg_temp.pg_is('a disabled platform group grants nothing', pg_temp.pg_holds(__anna, 'users.read_users'), '');
    perform auth.enable_user_group('pg', __full, 'pg', pg_temp.pg('g_eu')::int, 1);
    perform pg_temp.pg_is('enabled again', pg_temp.pg_holds(__anna, 'users.read_users'), 'pg_abc');
    perform auth.delete_user_group_member('pg', __full, 'pg', pg_temp.pg('g_eu')::int, __anna, 1);
    perform pg_temp.pg_is('anna removed: nothing', pg_temp.pg_holds(__anna, 'users.read_users'), '');
    perform pg_temp.pg_is('anna''s tenant list is empty'
        , (select count(*)::text from auth.get_user_available_tenants(__anna, 'pg', __anna)), '0');
end $$;

do $$
begin
    raise notice '';
    raise notice '=================================================================';
    raise notice 'Audit D-13: platform groups - Finished';
    raise notice '=================================================================';
end $$;
