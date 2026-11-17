set search_path = public, const, ext, stage, helpers, internal, unsecure, auth, triggers;

-- ============================================================================
-- on_registration: anna@abc.com registers with a password
-- ============================================================================
do $$
declare
    __anna bigint;
    __abc  int := pg_temp.ac('abc')::int;
begin
    raise notice 'TEST 4: on_registration';

    select u.__user_id from auth.register_user('ac', pg_temp.ac('full')::bigint, 'ac', 'anna@abc.com', 'hash', 'Anna') u into __anna;
    insert into _ac values ('anna', __anna);

    perform pg_temp.ac_is('anna''s runs'
        , pg_temp.ac_runs(__anna)
        , 'ac_platform:processing:[provision_external:processing] | ac_join:processing:[add_tenant_user:completed,assign_perm_set:completed,send_welcome_email:processing]');
    perform pg_temp.ac_is('anna joined ABC''s Tenant Members', pg_temp.ac_groups(__anna, __abc), 'tenant_members');
    perform pg_temp.ac_is('anna holds AC Reader in ABC'
        , auth.has_permission(__anna, 'ac', 'users.read_users', __abc, _throw_err := false)::text, 'true');
    perform pg_temp.ac_is('nothing in CDE', pg_temp.ac_groups(__anna, pg_temp.ac('cde')::int), '');

    perform pg_temp.ac_is('the app gets the backend steps with their payload'
        , (select string_agg(s.__action_code || ':' || s.__step_type_code || ':' || coalesce(s.__tenant_id::text, 'null')
                                 || ':' || coalesce(s.__payload ->> 'message', '-') || ':' || coalesce(s.__payload ->> 'email', s.__payload ->> 'target_email', '-')
                             , ' | ' order by s.__action_run_step_id)
           from auth.get_pending_action_steps(3, 'ac', __anna) s)
        , 'ac_platform:provision_external:null:-:anna@abc.com | ac_join:send_welcome_email:' || __abc || ':Welcome to ac_abc, anna@abc.com:anna@abc.com');
end $$;

select pg_temp.ac_expect('ABC''s owner fetches the pending steps'
    , 'select * from auth.get_pending_action_steps({abc_owner}, ''ac'')', '32001');

do $$
declare
    __anna bigint := pg_temp.ac('anna')::bigint;
    __step bigint;
begin
    raise notice 'TEST 5: the app reports back';

    select s.__action_run_step_id from auth.get_pending_action_steps(3, 'ac', __anna) s where s.__action_code = 'ac_join' into __step;
    insert into _ac values ('step_welcome', __step);
    perform auth.complete_action_step('ac', 3, 'ac', __step, '{"message_id": "m-1"}');

    select s.__action_run_step_id from auth.get_pending_action_steps(3, 'ac', __anna) s where s.__action_code = 'ac_platform' into __step;
    perform auth.fail_action_step('ac', 3, 'ac', __step, 'HR system is down');

    perform pg_temp.ac_is('the runs are finished'
        , pg_temp.ac_runs(__anna)
        , 'ac_platform:failed:[provision_external:failed] | ac_join:completed:[add_tenant_user:completed,assign_perm_set:completed,send_welcome_email:completed]');
    perform pg_temp.ac_is('nothing is pending', (select count(*)::text from auth.get_pending_action_steps(3, 'ac', __anna)), '0');
    perform pg_temp.ac_is('the failure is journaled'
        , (select j.data_payload ->> 'error_message' from public.journal j where j.event_id = 24004 and j.correlation_id = 'ac'
           order by j.journal_id desc limit 1)
        , 'HR system is down');
end $$;

select pg_temp.ac_expect('a finished step is reported again'
    , 'select auth.complete_action_step(''ac'', 3, ''ac'', {step_welcome})', '41004');

-- ============================================================================
-- on_entry: kate signs in through Azure, in the ABC staff group
-- ============================================================================
do $$
declare
    __kate bigint;
    __abc  int := pg_temp.ac('abc')::int;
    __r    record;
begin
    raise notice 'TEST 6: on_entry';

    select * from auth.ensure_user_from_provider('ac', 3, 'ac', 'ac_aad', 'uid-kate', 'oid-kate'
        , 'ac_kate', 'Kate', 'kate@abc.com', '{"department": "Sales"}') into __r;
    __kate := __r.__user_id;
    insert into _ac values ('kate', __kate);
    perform pg_temp.ac_is('registration ran the registration actions'
        , pg_temp.ac_runs(__kate)
        , 'ac_platform:processing:[provision_external:processing] | ac_join:processing:[add_tenant_user:completed,assign_perm_set:completed,send_welcome_email:processing]');

    perform auth.ensure_groups_and_permissions('ac', 3, 'ac', __kate, 'ac_aad', array['abc-staff'], null);
    perform pg_temp.ac_is('the login ran the entry actions (fresh provider groups)'
        , pg_temp.ac_runs(__kate)
        , 'ac_platform:processing:[provision_external:processing] | ac_join:processing:[add_tenant_user:completed,assign_perm_set:completed,send_welcome_email:processing]'
          || ' | ac_staff:completed:[add_group_member:completed] | ac_audit:processing:[provision_external:processing]');
    perform pg_temp.ac_is('kate is in AC Staff', pg_temp.ac_groups(__kate, __abc), 'ac_staff,tenant_members');
    perform pg_temp.ac_is('the claims fill the payload'
        , (select s.__payload ->> 'department' from auth.get_pending_action_steps(3, 'ac', __kate) s where s.__action_code = 'ac_audit')
        , 'Sales');

    perform auth.ensure_groups_and_permissions('ac', 3, 'ac', __kate, 'ac_aad', array['abc-staff'], null);
    perform pg_temp.ac_is('the next login: AC Staff runs once, AC Audit every time'
        , (select string_agg(a.code, ',' order by r.action_run_id) from auth.action_run r inner join auth.action a on a.action_id = r.action_id
           where r.user_id = __kate and a.event_code = 'on_entry')
        , 'ac_staff,ac_audit,ac_audit');
end $$;

-- ============================================================================
-- on_entry through the password, failures don't break the login
-- ============================================================================
do $$
declare
    __anna bigint := pg_temp.ac('anna')::bigint;
    __r    record;
begin
    raise notice 'TEST 7: password login, a failing step';

    select * from auth.create_user_login_attempt('ac', 3, 'ac', 'email', 'anna@abc.com', __anna, true) into __r;
    perform pg_temp.ac_is('the login succeeds', __r.__outcome_code, 'user_logged_in');
    perform pg_temp.ac_is('AC Audit failed: no department in the data'
        , (select r.status_code || ':' || s.status_code || ':' || coalesce(s.error_message, '')
           from auth.action_run r
                    inner join auth.action a on a.action_id = r.action_id
                    inner join auth.action_run_step s on s.action_run_id = r.action_run_id
           where r.user_id = __anna and a.code = 'ac_audit')
        , 'failed:failed:Action placeholder {data.department} has no value');
    perform pg_temp.ac_is('AC Staff: no provider groups, no run'
        , (select count(*)::text from auth.action_run r inner join auth.action a on a.action_id = r.action_id
           where r.user_id = __anna and a.code = 'ac_staff'), '0');
end $$;

do $$
declare
    __owner bigint := pg_temp.ac('abc_owner')::bigint;
    __abc   int := pg_temp.ac('abc')::int;
    __bob   bigint;
begin
    raise notice 'TEST 8: a required step fails, the rest is skipped';

    -- AC Reader disappears after the action was saved
    delete from auth.permission_assignment where perm_set_id = (select perm_set_id from auth.perm_set where tenant_id = __abc and code = 'ac_reader');
    delete from auth.perm_set where tenant_id = __abc and code = 'ac_reader';

    select u.__user_id from auth.register_user('ac', pg_temp.ac('full')::bigint, 'ac', 'bob@abc.com', 'hash', 'Bob') u into __bob;
    insert into _ac values ('bob', __bob);
    perform pg_temp.ac_is('bob is registered; AC Join failed at the perm set'
        , pg_temp.ac_runs(__bob)
        , 'ac_platform:processing:[provision_external:processing] | ac_join:failed:[add_tenant_user:completed,assign_perm_set:failed,send_welcome_email:skipped]');
    perform pg_temp.ac_is('the completed step stays', pg_temp.ac_groups(__bob, __abc), 'tenant_members');

    raise notice 'TEST 9: rules';
    perform auth.register_user('ac', pg_temp.ac('full')::bigint, 'ac', 'cid@cde.com', 'hash', 'Cid');
    perform pg_temp.ac_is('cid@cde.com: CDE''s action, not ABC''s'
        , (select string_agg(a.code || ':' || coalesce(r.tenant_id::text, 'null'), ',' order by a.code)
           from auth.action_run r inner join auth.action a on a.action_id = r.action_id
               inner join auth.user_info u on u.user_id = r.user_id
           where u.email = 'cid@cde.com')
        , 'ac_cde_join:' || pg_temp.ac('cde') || ',ac_platform:null');

    raise notice 'TEST 10: run logs';
    perform pg_temp.ac_is('ABC''s owner reads ABC''s runs only'
        , (select string_agg(distinct r.__action_code, ',' order by r.__action_code) from auth.get_action_runs(__owner, 'ac', _tenant_id := __abc) r)
        , 'ac_audit,ac_join,ac_staff');
    perform pg_temp.ac_is('kate''s runs in ABC'
        , (select count(*)::text from auth.get_action_runs(__owner, 'ac', pg_temp.ac('kate')::bigint, _tenant_id := __abc) r), '4');
end $$;

select pg_temp.ac_expect('ABC''s owner completes a step'
    , 'select auth.complete_action_step(''ac'', {abc_owner}, ''ac'', {step_welcome})', '32001');

-- ============================================================================
-- on_leave: anna is deleted
-- ============================================================================
do $$
declare
    __anna bigint := pg_temp.ac('anna')::bigint;
begin
    raise notice 'TEST 11: on_leave';

    perform auth.delete_user_info('ac', pg_temp.ac('full')::bigint, 'ac', __anna);
    perform pg_temp.ac_is('AC Leave ran for ABC, the run outlives the user'
        , (select r.status_code || ':' || r.username || ':' || coalesce(r.tenant_id::text, 'null')
           from auth.action_run r inner join auth.action a on a.action_id = r.action_id
           where r.user_id = __anna and a.code = 'ac_leave')
        , 'processing:anna@abc.com:' || pg_temp.ac('abc'));
    perform pg_temp.ac_is('the app gets the step'
        , (select s.__payload ->> 'reason' || ':' || (s.__payload ->> 'target_email') from auth.get_pending_action_steps(3, 'ac', __anna) s
           where s.__action_code = 'ac_leave')
        , 'left:anna@abc.com');
end $$;

do $$
begin
    raise notice '';
    raise notice '=================================================================';
    raise notice 'Audit D-13: actions - Finished';
    raise notice '=================================================================';
end $$;
