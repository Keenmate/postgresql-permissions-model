set search_path = public, const, ext, stage, helpers, internal, unsecure, auth, triggers;

-- ============================================================================
-- Scenario 2: an admin decides; the change itself fires on_join / on_leave
-- ============================================================================
do $$
declare
    __owner  bigint := pg_temp.me('owner')::bigint;
    __bob    bigint := pg_temp.me('bob')::bigint;
    __abc    int := pg_temp.me('abc')::int;
    __assign bigint;
begin
    raise notice 'TEST 5: group members, direct assignments, owners';

    perform auth.create_user_group_member('me', __owner, 'me', pg_temp.me('g_staff')::int, __bob, __abc);
    perform pg_temp.me_is('added to ME Staff: on_join', pg_temp.me_runs(__bob), 'me_join');
    perform auth.delete_user_group_member('me', __owner, 'me', pg_temp.me('g_staff')::int, __bob, __abc);
    perform pg_temp.me_is('removed from it: on_leave', pg_temp.me_runs(__bob), 'me_join,me_leave');

    perform auth.create_user_group_member('me', __owner, 'me', pg_temp.me('g_picker')::int, __bob, __abc);
    perform pg_temp.me_is('a picker group grants nothing: no join', pg_temp.me_runs(__bob), 'me_join,me_leave');
    perform pg_temp.me_is('and no snapshot row', pg_temp.me_state(__bob), 'none');

    select a.__assignment_id from auth.assign_permission('me', __owner, 'me', null, __bob, 'me_reader', null, __abc) a into __assign;
    perform pg_temp.me_is('a direct perm set: on_join', pg_temp.me_runs(__bob), 'me_join,me_leave,me_join');
    perform auth.unassign_permission('me', __owner, 'me', __assign, __abc);
    perform pg_temp.me_is('unassigned: on_leave', pg_temp.me_runs(__bob), 'me_join,me_leave,me_join,me_leave');

    perform auth.create_owner('me', __owner, 'me', __bob, null, __abc);
    perform pg_temp.me_is('made an owner: on_join', pg_temp.me_runs(__bob), 'me_join,me_leave,me_join,me_leave,me_join');
    perform auth.delete_owner('me', __owner, 'me', __bob, null, __abc);
    perform pg_temp.me_is('no longer an owner: on_leave', pg_temp.me_runs(__bob), 'me_join,me_leave,me_join,me_leave,me_join,me_leave');
end $$;

do $$
declare
    __owner bigint := pg_temp.me('owner')::bigint;
    __kate  bigint := pg_temp.me('kate')::bigint;
    __abc   int := pg_temp.me('abc')::int;
    __before text;
begin
    raise notice 'TEST 6: group-level changes reach every member';

    perform pg_temp.me_login('kate', array['grp-staff']);
    __before := pg_temp.me_runs(__kate);

    perform auth.disable_user_group('me', __owner, 'me', pg_temp.me('g_staff')::int, __abc);
    perform pg_temp.me_is('ME Staff disabled: kate leaves', pg_temp.me_runs(__kate), __before || ',me_leave');
    perform auth.enable_user_group('me', __owner, 'me', pg_temp.me('g_staff')::int, __abc);
    perform pg_temp.me_is('enabled again: kate joins', pg_temp.me_runs(__kate), __before || ',me_leave,me_join');

    perform pg_temp.me_is('kate holds nothing in CDE: CDE''s on_join never ran'
        , (select count(*)::text from auth.action_run r inner join auth.action a on a.action_id = r.action_id
           where r.user_id = __kate and a.code = 'me_cde_join')
        , '0');
end $$;

-- ============================================================================
-- The sweep: catches what no hook saw
-- ============================================================================
select pg_temp.me_expect('ABC''s owner runs the sweep'
    , 'select * from auth.process_tenant_memberships(''me'', {owner}, ''me'')', '32001');

do $$
declare
    __carl bigint := pg_temp.me('carl')::bigint;
    __abc  int := pg_temp.me('abc')::int;
begin
    raise notice 'TEST 7: the sweep';

    -- a grant written past every function
    insert into auth.permission_assignment (created_by, tenant_id, user_id, perm_set_id)
    values ('me', __abc, __carl, (select ps.perm_set_id from auth.perm_set ps where ps.tenant_id = __abc and ps.code = 'me_reader'));
    perform pg_temp.me_is('no hook saw it', pg_temp.me_runs(__carl), '');

    perform pg_temp.me_is('the sweep finds the join'
        , (select string_agg(c.__change_code, ',') from auth.process_tenant_memberships('me', 3, 'me') c where c.__target_user_id = __carl)
        , 'joined');
    perform pg_temp.me_is('on_join ran', pg_temp.me_runs(__carl), 'me_join');
    perform pg_temp.me_is('a second sweep changes nothing'
        , (select count(*)::text from auth.process_tenant_memberships('me', 3, 'me') c where c.__target_user_id = __carl)
        , '0');
end $$;

-- ============================================================================
-- Not leaving: disabled users; deleted users leave once
-- ============================================================================
do $$
declare
    __full bigint := pg_temp.me('full')::bigint;
    __kate bigint := pg_temp.me('kate')::bigint;
    __before text;
begin
    raise notice 'TEST 8: disabled and deleted users';

    __before := pg_temp.me_runs(__kate);
    perform auth.disable_user('me', __full, 'me', __kate);
    perform auth.process_tenant_memberships('me', 3, 'me', __kate);
    perform pg_temp.me_is('disabled is not leaving', pg_temp.me_state(__kate), 'member');
    perform pg_temp.me_is('no on_leave', pg_temp.me_runs(__kate), __before);

    perform auth.delete_user_info('me', __full, 'me', __kate);
    perform pg_temp.me_is('deleted: on_leave once', pg_temp.me_runs(__kate), __before || ',me_leave');
    perform pg_temp.me_is('the snapshot rows are gone'
        , (select count(*)::text from auth.tenant_membership_state s where s.user_id = __kate), '0');
end $$;
