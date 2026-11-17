set search_path = public, const, ext, stage, helpers, internal, unsecure, auth, triggers;

-- ============================================================================
-- Who may manage actions
-- ============================================================================
do $$
begin
    raise notice 'TEST 1: who manages actions';
end $$;

select pg_temp.ac_expect('a user without permissions creates an action'
    , 'select * from auth.create_action(''ac'', {nobody}, ''ac'', ''X'', ''on_entry'', ''{"mode": "always"}'', _tenant_id := {abc})', '32001');
select pg_temp.ac_expect('CDE''s admin creates an action in ABC'
    , 'select * from auth.create_action(''ac'', {cde_admin}, ''ac'', ''X'', ''on_entry'', ''{"mode": "always"}'', _tenant_id := {abc})', '32001');
select pg_temp.ac_expect('ABC''s owner creates a platform action'
    , 'select * from auth.create_action(''ac'', {abc_owner}, ''ac'', ''X'', ''on_entry'', ''{"mode": "always"}'', _is_platform := true, _tenant_id := {abc})', '32001');

-- ============================================================================
-- Validation when saving
-- ============================================================================
do $$
begin
    raise notice 'TEST 2: validation';
end $$;

select pg_temp.ac_expect('no rule'
    , 'select * from auth.create_action(''ac'', {abc_owner}, ''ac'', ''X'', ''on_entry'', null, _tenant_id := {abc})', '40001');
select pg_temp.ac_expect('an invalid rule'
    , 'select * from auth.create_action(''ac'', {abc_owner}, ''ac'', ''X'', ''on_entry'', ''{"mode": "sometimes"}'', _tenant_id := {abc})', '40001');
select pg_temp.ac_expect('an unknown event'
    , 'select * from auth.create_action(''ac'', {abc_owner}, ''ac'', ''X'', ''on_lunch'', ''{"mode": "always"}'', _tenant_id := {abc})', '41003');

do $$
declare
    __owner bigint := pg_temp.ac('abc_owner')::bigint;
    __abc   int := pg_temp.ac('abc')::int;
    __a     int;
begin
    -- A1: new @abc.com users join ABC, get AC Reader and a welcome email
    select a.__action_id from auth.create_action('ac', __owner, 'ac', 'AC Join', 'on_registration'
        , '{"mode": "conditional", "conditions": [{"field": "email_domain", "op": "is", "values": ["abc.com"]}]}'
        , _code := 'ac_join', _tenant_id := __abc) a into __a;
    insert into _ac values ('a_join', __a);
    perform auth.create_action_step('ac', __owner, 'ac', __a, 'add_tenant_user', _sequence := 1, _tenant_id := __abc);
    perform auth.create_action_step('ac', __owner, 'ac', __a, 'assign_perm_set', '{"perm_set_code": "ac_reader"}', _sequence := 2, _tenant_id := __abc);
    perform auth.create_action_step('ac', __owner, 'ac', __a, 'send_welcome_email', '{"message": "Welcome to {tenant.code}, {user.email}"}', _sequence := 3, _tenant_id := __abc);
end $$;

select pg_temp.ac_expect('the code is taken'
    , 'select * from auth.create_action(''ac'', {abc_owner}, ''ac'', ''X'', ''on_entry'', ''{"mode": "always"}'', _code := ''ac_join'', _tenant_id := {abc})', '41002');
select pg_temp.ac_expect('an unknown step type'
    , 'select * from auth.create_action_step(''ac'', {abc_owner}, ''ac'', {a_join}, ''bake_cake'', _tenant_id := {abc})', '41003');
select pg_temp.ac_expect('add_group_member without a group'
    , 'select * from auth.create_action_step(''ac'', {abc_owner}, ''ac'', {a_join}, ''add_group_member'', _tenant_id := {abc})', '41003');
select pg_temp.ac_expect('add_group_member with CDE''s group'
    , 'select * from auth.create_action_step(''ac'', {abc_owner}, ''ac'', {a_join}, ''add_group_member'', ''{"user_group_id": {g_cde_staff}}'', _tenant_id := {abc})', '33011');
select pg_temp.ac_expect('a perm set the tenant doesn''t have'
    , 'select * from auth.create_action_step(''ac'', {abc_owner}, ''ac'', {a_join}, ''assign_perm_set'', ''{"perm_set_code": "full_admin"}'', _tenant_id := {abc})', '32004');
select pg_temp.ac_expect('an unknown condition'
    , 'select * from auth.create_action_step(''ac'', {abc_owner}, ''ac'', {a_join}, ''add_tenant_user'', _condition_code := ''if_raining'', _tenant_id := {abc})', '41003');
select pg_temp.ac_expect('an unknown placeholder'
    , 'select * from auth.create_action_step(''ac'', {abc_owner}, ''ac'', {a_join}, ''send_welcome_email'', ''{"message": "{tenant.title}"}'', _tenant_id := {abc})', '41003');
select pg_temp.ac_expect('CDE''s admin adds a step to ABC''s action'
    , 'select * from auth.create_action_step(''ac'', {cde_admin}, ''ac'', {a_join}, ''add_tenant_user'', _tenant_id := {cde})', '41001');
select pg_temp.ac_expect('CDE''s admin deletes ABC''s action'
    , 'select auth.delete_action(''ac'', {cde_admin}, ''ac'', {a_join}, {cde})', '41001');

-- D-19: the author must hold what the steps hand out
select pg_temp.ac_expect('ABC''s admin hands out AC Reader'
    , 'select * from auth.create_action_step(''ac'', {abc_admin}, ''ac'', {a_join}, ''assign_perm_set'', ''{"perm_set_code": "ac_reader"}'', _tenant_id := {abc})', '32010');
select pg_temp.ac_expect('ABC''s admin adds users to AC Staff'
    , 'select * from auth.create_action_step(''ac'', {abc_admin}, ''ac'', {a_join}, ''add_group_member'', ''{"user_group_id": {g_staff}}'', _tenant_id := {abc})', '32010');
select pg_temp.ac_expect('ABC''s admin takes AC Reader away'
    , 'select * from auth.create_action_step(''ac'', {abc_admin}, ''ac'', {a_join}, ''unassign_perm_set'', ''{"perm_set_code": "ac_reader"}'', _tenant_id := {abc})', '32010');

-- platform actions: backend and external steps only, tenant-1 permission
do $$
declare
    __full bigint := pg_temp.ac('full')::bigint;
    __a    int;
begin
    select a.__action_id from auth.create_action('ac', __full, 'ac', 'AC Platform Welcome', 'on_registration', '{"mode": "always"}'
        , _code := 'ac_platform', _is_platform := true) a into __a;
    insert into _ac values ('a_platform', __a);
    perform auth.create_action_step('ac', __full, 'ac', __a, 'provision_external');
end $$;

select pg_temp.ac_expect('a database step in a platform action'
    , 'select * from auth.create_action_step(''ac'', {full}, ''ac'', {a_platform}, ''add_tenant_user'')', '41003');
select pg_temp.ac_expect('ABC''s owner edits the platform action'
    , 'select auth.update_action(''ac'', {abc_owner}, ''ac'', {a_platform}, ''Mine'', ''{"mode": "always"}'', _tenant_id := {abc})', '41001');

do $$
declare
    __owner bigint := pg_temp.ac('abc_owner')::bigint;
    __admin bigint := pg_temp.ac('abc_admin')::bigint;
    __abc   int := pg_temp.ac('abc')::int;
    __a     int;
begin
    raise notice 'TEST 3: what may be built';

    -- ABC's admin may build what they hold: joining the tenant (Tenant Members' permissions)
    select a.__action_id from auth.create_action('ac', __admin, 'ac', 'AC Admin Join', 'on_entry'
        , '{"mode": "conditional", "conditions": [{"field": "email_domain", "op": "is", "values": ["never.abc"]}]}'
        , _code := 'ac_admin_join', _tenant_id := __abc) a into __a;
    perform auth.create_action_step('ac', __admin, 'ac', __a, 'add_tenant_user', _tenant_id := __abc);

    -- A2: Azure ABC staff join AC Staff, once
    select a.__action_id from auth.create_action('ac', __owner, 'ac', 'AC Staff', 'on_entry'
        , '{"mode": "conditional", "conditions": [{"field": "provider_groups", "op": "includes", "values": ["abc-staff"]}]}'
        , _code := 'ac_staff', _run_once_per_user := true, _tenant_id := __abc) a into __a;
    insert into _ac values ('a_staff', __a);
    perform auth.create_action_step('ac', __owner, 'ac', __a, 'add_group_member'
        , jsonb_build_object('user_group_id', pg_temp.ac('g_staff')::int), _condition_code := 'user_not_in_group', _tenant_id := __abc);

    -- A3: every login of an ABC user is reported to an external system
    select a.__action_id from auth.create_action('ac', __owner, 'ac', 'AC Audit', 'on_entry'
        , '{"mode": "conditional", "conditions": [{"field": "email_domain", "op": "is", "values": ["abc.com"]}]}'
        , _code := 'ac_audit', _tenant_id := __abc) a into __a;
    insert into _ac values ('a_audit', __a);
    perform auth.create_action_step('ac', __owner, 'ac', __a, 'provision_external', '{"department": "{data.department}"}', _tenant_id := __abc);

    -- A4: disabled, never runs
    select a.__action_id from auth.create_action('ac', __owner, 'ac', 'AC Off', 'on_registration', '{"mode": "always"}'
        , _code := 'ac_off', _tenant_id := __abc) a into __a;
    perform auth.create_action_step('ac', __owner, 'ac', __a, 'add_tenant_user', _tenant_id := __abc);
    perform auth.update_action('ac', __owner, 'ac', __a, 'AC Off', '{"mode": "always"}', _is_active := false, _tenant_id := __abc);

    -- A5: leaving ABC is reported
    select a.__action_id from auth.create_action('ac', __owner, 'ac', 'AC Leave', 'on_leave', '{"mode": "always"}'
        , _code := 'ac_leave', _tenant_id := __abc) a into __a;
    perform auth.create_action_step('ac', __owner, 'ac', __a, 'provision_external', '{"reason": "left"}', _tenant_id := __abc);

    -- C1: CDE's registration action for @cde.com
    select a.__action_id from auth.create_action('ac', pg_temp.ac('cde_admin')::bigint, 'ac', 'AC CDE Join', 'on_registration'
        , '{"mode": "conditional", "conditions": [{"field": "email_domain", "op": "is", "values": ["cde.com"]}]}'
        , _code := 'ac_cde_join', _tenant_id := pg_temp.ac('cde')::int) a into __a;
    perform auth.create_action_step('ac', pg_temp.ac('cde_admin')::bigint, 'ac', __a, 'add_tenant_user', _tenant_id := pg_temp.ac('cde')::int);

    perform pg_temp.ac_is('get_actions lists ABC''s actions with their steps'
        , (select string_agg(a.__code || ':' || a.__event_code || ':' || a.__is_active || ':' || jsonb_array_length(a.__steps), ',' order by a.__code)
           from auth.get_actions(__owner, 'ac', __abc) a)
        , 'ac_admin_join:on_entry:true:1,ac_audit:on_entry:true:1,ac_join:on_registration:true:3,ac_leave:on_leave:true:1,ac_off:on_registration:false:1,ac_staff:on_entry:true:1');
    perform pg_temp.ac_is('the steps of AC Join'
        , (select string_agg((s ->> 'step_type_code') || ':' || (s ->> 'executor_code'), ',' order by (s ->> 'sequence')::int)
           from auth.get_actions(__owner, 'ac', __abc) a cross join jsonb_array_elements(a.__steps) s
           where a.__code = 'ac_join')
        , 'add_tenant_user:database,assign_perm_set:database,send_welcome_email:backend');
    perform pg_temp.ac_is('CDE''s admin sees only CDE''s'
        , (select string_agg(a.__code, ',') from auth.get_actions(pg_temp.ac('cde_admin')::bigint, 'ac', pg_temp.ac('cde')::int) a)
        , 'ac_cde_join');
    perform pg_temp.ac_is('tenant 1 with the platform permission sees the platform action'
        , (select string_agg(a.__code || ':' || a.__is_platform, ',') from auth.get_actions(pg_temp.ac('full')::bigint, 'ac', 1) a
           where a.__code like 'ac\_%')
        , 'ac_platform:true');
    perform pg_temp.ac_is('the changes are journaled'
        , (select count(*)::text from public.journal j where j.event_id in (24001, 24002) and j.correlation_id = 'ac'
              and j.keys ->> 'action' = pg_temp.ac('a_join')), '4');
end $$;
