set search_path = public, const, ext, stage, helpers, internal, unsecure, auth, triggers;

-- ============================================================================
-- Scenario 1: membership follows the provider groups at login
-- ============================================================================
do $$
declare
    __kate bigint;
    __abc  int := pg_temp.me('abc')::int;
begin
    raise notice 'TEST 1: joining at login';

    __kate := pg_temp.me_login('kate', array['grp-staff']);
    insert into _me values ('kate', __kate);

    perform pg_temp.me_is('kate joined ABC: on_join ran, not CDE''s', pg_temp.me_runs(__kate), 'me_join');
    perform pg_temp.me_is('kate is in the snapshot', pg_temp.me_state(__kate), 'member');
    perform pg_temp.me_is('the platform on_join ran for ABC with the tenant in its data'
        , (select string_agg(r.extra_data ->> 'tenant_code', ',')
           from auth.action_run r
                    inner join auth.action a on a.action_id = r.action_id
           where r.user_id = __kate and a.code = 'me_platform_join')
        , 'me_abc');
    perform pg_temp.me_is('the join is journaled'
        , (select count(*)::text from public.journal j
           where j.event_id = 11016 and j.tenant_id = __abc and (j.data_payload ->> 'target_user_id')::bigint = __kate)
        , '1');

    perform pg_temp.me_login('kate', array['grp-staff']);
    perform pg_temp.me_is('a second login is no new join', pg_temp.me_runs(__kate), 'me_join');
end $$;

do $$
declare
    __kate bigint := pg_temp.me('kate')::bigint;
    __abc  int := pg_temp.me('abc')::int;
begin
    raise notice 'TEST 2: leaving at login (strike limit 1, no grace)';

    perform pg_temp.me_login('kate', array[]::text[]);
    perform pg_temp.me_is('kate left ABC: on_leave ran', pg_temp.me_runs(__kate), 'me_join,me_leave');
    perform pg_temp.me_is('kate is out of the snapshot', pg_temp.me_state(__kate), 'none');
    perform pg_temp.me_is('the leave is journaled'
        , (select count(*)::text from public.journal j
           where j.event_id = 11017 and j.tenant_id = __abc and (j.data_payload ->> 'target_user_id')::bigint = __kate)
        , '1');

    perform pg_temp.me_login('kate', array['grp-staff']);
    perform pg_temp.me_is('back in the group: joins again', pg_temp.me_runs(__kate), 'me_join,me_leave,me_join');
end $$;

do $$
declare
    __kate bigint := pg_temp.me('kate')::bigint;
begin
    raise notice 'TEST 3: strikes (limit 3)';

    perform pg_temp.me_param('leave_strike_limit', 3);

    perform pg_temp.me_login('kate', array[]::text[]);
    perform pg_temp.me_is('first login without the group: a strike', pg_temp.me_state(__kate), '1 missing');
    perform pg_temp.me_login('kate', array[]::text[]);
    perform pg_temp.me_is('second: two strikes', pg_temp.me_state(__kate), '2 missing');
    perform pg_temp.me_is('no on_leave yet', pg_temp.me_runs(__kate), 'me_join,me_leave,me_join');

    perform pg_temp.me_login('kate', array['grp-staff']);
    perform pg_temp.me_is('the group is back: strikes reset', pg_temp.me_state(__kate), 'member');
    perform pg_temp.me_is('coming back is no new join', pg_temp.me_runs(__kate), 'me_join,me_leave,me_join');

    perform pg_temp.me_login('kate', array[]::text[]);
    perform pg_temp.me_login('kate', array[]::text[]);
    perform pg_temp.me_login('kate', array[]::text[]);
    perform pg_temp.me_is('the third strike in a row: on_leave', pg_temp.me_runs(__kate), 'me_join,me_leave,me_join,me_leave');
    perform pg_temp.me_is('out of the snapshot', pg_temp.me_state(__kate), 'none');

    perform pg_temp.me_param('leave_strike_limit', 1);
end $$;

do $$
declare
    __kate bigint := pg_temp.me('kate')::bigint;
begin
    raise notice 'TEST 4: grace period (60 minutes) and the sweep';

    perform pg_temp.me_param('leave_grace_minutes', 60);

    perform pg_temp.me_login('kate', array['grp-staff']);
    perform pg_temp.me_login('kate', array[]::text[]);
    perform pg_temp.me_is('missing, inside the grace period', pg_temp.me_state(__kate), '1 missing');
    perform pg_temp.me_is('no on_leave yet', pg_temp.me_runs(__kate), 'me_join,me_leave,me_join,me_leave,me_join');

    perform pg_temp.me_is('the sweep reports the missing membership'
        , (select string_agg(c.__change_code, ',') from auth.process_tenant_memberships('me', 3, 'me', __kate) c)
        , 'missing');
    perform pg_temp.me_is('still inside the grace period', pg_temp.me_runs(__kate), 'me_join,me_leave,me_join,me_leave,me_join');

    update auth.tenant_membership_state
    set missing_since = now() - interval '2 hours'
    where user_id = __kate;

    perform pg_temp.me_is('the sweep after the grace period'
        , (select string_agg(c.__change_code, ',') from auth.process_tenant_memberships('me', 3, 'me', __kate) c)
        , 'left');
    perform pg_temp.me_is('on_leave ran', pg_temp.me_runs(__kate), 'me_join,me_leave,me_join,me_leave,me_join,me_leave');
    perform pg_temp.me_is('out of the snapshot', pg_temp.me_state(__kate), 'none');

    perform pg_temp.me_param('leave_grace_minutes', 0);
end $$;

select pg_temp.me_expect('a strike limit of 0'
    , 'select pg_temp.me_param(''leave_strike_limit'', 0)', '31016');
select pg_temp.me_expect('a negative grace period'
    , 'select pg_temp.me_param(''leave_grace_minutes'', -5)', '31016');
select pg_temp.me_expect('the tenant system parameters can''t be deleted'
    , 'delete from const.sys_param where group_code = ''tenant_membership''', '31015');
