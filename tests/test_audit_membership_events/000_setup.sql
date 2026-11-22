set search_path = public, const, ext, stage, helpers, internal, unsecure, auth, triggers;

-- ============================================================================
-- SETUP
--   provider me_aad (group mapping); svc_authenticator (3) logs users in
--   tenant ME ABC: perm set "ME Reader" (users.read_users)
--     group "ME Staff"  (ME Reader), mapped to the me_aad group grp-staff
--     group "ME Picker" (grants nothing)
--   tenant ME CDE: group "ME CDE Staff" (tenant_member), mapped to grp-cde
--   actions
--     ABC: me_join (on_join), me_leave (on_leave)   - by the ABC owner
--     CDE: me_cde_join (on_join)                    - by the CDE owner
--     platform: me_platform_join (on_join)          - by me_full
--   users
--     me_owner     - owner row in ABC
--     me_cde_owner - owner row in CDE
--     me_full      - full_admin in tenant 1
--     me_bob, me_carl - nothing (bob is managed by admins, carl by hand)
-- ============================================================================
create temp table if not exists _me (key text primary key, val text);

do $$
declare
    __id    bigint;
    __abc   int;
    __cde   int;
    __g     int;
    __a     int;
    __name  text;
begin
    raise notice '';
    raise notice '=================================================================';
    raise notice 'Audit: tenant membership events (on_join / on_leave) - Starting';
    raise notice '=================================================================';

    insert into auth.provider (created_by, updated_by, code, is_active, allows_group_mapping, allows_group_sync)
    values ('me', 'me', 'me_aad', true, true, false);

    select t.__tenant_id from auth.create_tenant('me', 1, 'me', 'ME ABC', 'me_abc') t into __abc;
    select t.__tenant_id from auth.create_tenant('me', 1, 'me', 'ME CDE', 'me_cde') t into __cde;
    insert into _me values ('abc', __abc), ('cde', __cde);

    foreach __name in array array['owner', 'cde_owner', 'full', 'bob', 'carl']
    loop
        insert into auth.user_info (created_by, updated_by, user_type_code, username, original_username, display_name, email, can_login)
        values ('me', 'me', 'normal', 'me_' || __name, 'me_' || __name, 'ME ' || __name, 'me_' || __name || '@test.com', true)
        returning user_id into __id;
        insert into _me values (__name, __id);
    end loop;

    insert into auth.owner (created_by, tenant_id, user_group_id, user_id)
    values ('me', __abc, null, (select val from _me where key = 'owner')::bigint),
           ('me', __cde, null, (select val from _me where key = 'cde_owner')::bigint);
    perform unsecure.assign_permission_as_system(null::integer, (select val from _me where key = 'full')::bigint, 'full_admin', null, 1);

    perform unsecure.create_perm_set('me', 1, 'me', 'ME Reader', _permissions := array['users.read_users'], _tenant_id := __abc);

    -- mapped and manual members
    select g.__user_group_id from unsecure.create_user_group('me', 1, 'me', 'ME Staff', _tenant_id := __abc) g into __g;
    perform unsecure.assign_permission('me', 1, 'me', __g, null, 'me_reader', _tenant_id := __abc);
    insert into auth.user_group_mapping (created_by, user_group_id, provider_code, mapped_object_id)
    values ('me', __g, 'me_aad', 'grp-staff');
    insert into _me values ('g_staff', __g);

    select g.__user_group_id from unsecure.create_user_group('me', 1, 'me', 'ME Picker', _tenant_id := __abc) g into __g;
    insert into _me values ('g_picker', __g);

    select g.__user_group_id from unsecure.create_user_group('me', 1, 'me', 'ME CDE Staff', _is_external := true, _tenant_id := __cde) g into __g;
    perform unsecure.assign_permission('me', 1, 'me', __g, null, 'tenant_member', _tenant_id := __cde);
    insert into auth.user_group_mapping (created_by, user_group_id, provider_code, mapped_object_id)
    values ('me', __g, 'me_aad', 'grp-cde');

    -- the actions
    select a.__action_id from auth.create_action('me', (select val from _me where key = 'owner')::bigint, 'me'
        , 'ME Join', 'on_join', '{"mode": "always"}', 'me_join', _tenant_id := __abc) a into __a;
    perform auth.create_action_step('me', (select val from _me where key = 'owner')::bigint, 'me', __a
        , 'provision_external', '{"reason": "join"}', _tenant_id := __abc);

    select a.__action_id from auth.create_action('me', (select val from _me where key = 'owner')::bigint, 'me'
        , 'ME Leave', 'on_leave', '{"mode": "always"}', 'me_leave', _tenant_id := __abc) a into __a;
    perform auth.create_action_step('me', (select val from _me where key = 'owner')::bigint, 'me', __a
        , 'provision_external', '{"reason": "leave"}', _tenant_id := __abc);

    select a.__action_id from auth.create_action('me', (select val from _me where key = 'cde_owner')::bigint, 'me'
        , 'ME CDE Join', 'on_join', '{"mode": "always"}', 'me_cde_join', _tenant_id := __cde) a into __a;
    perform auth.create_action_step('me', (select val from _me where key = 'cde_owner')::bigint, 'me', __a
        , 'provision_external', '{"reason": "join"}', _tenant_id := __cde);

    select a.__action_id from auth.create_action('me', (select val from _me where key = 'full')::bigint, 'me'
        , 'ME Platform Join', 'on_join', '{"mode": "always"}', 'me_platform_join', _is_platform := true) a into __a;
    perform auth.create_action_step('me', (select val from _me where key = 'full')::bigint, 'me', __a
        , 'provision_external', '{"reason": "{data.tenant_code}"}');

    raise notice 'PASS: setup (ABC=%, CDE=%)', __abc, __cde;
end $$;

create or replace function pg_temp.me(_key text) returns text language sql as $$ select val from _me where key = _key $$;

-- runs _sql (with {key} placeholders from _me) and expects sqlstate _code
create or replace function pg_temp.me_expect(_label text, _sql text, _code text) returns void
    language plpgsql
as
$$
declare
    __sql   text := _sql;
    __r     record;
    __state text;
    __msg   text;
begin
    for __r in select key, val from _me order by length(key) desc loop
        __sql := replace(__sql, '{' || __r.key || '}', __r.val);
    end loop;
    begin
        execute __sql;
        raise notice 'FAIL: % - no error raised (expected %)', _label, _code;
        return;
    exception when others then
        get stacked diagnostics __state = returned_sqlstate, __msg = message_text;
    end;
    if __state = _code then
        raise notice 'PASS: % - %', _label, _code;
    else
        raise notice 'FAIL: % - got % (expected %): %', _label, __state, _code, __msg;
    end if;
end;
$$;

create or replace function pg_temp.me_is(_label text, _actual text, _expected text) returns void
    language plpgsql
as
$$
begin
    if _actual is not distinct from _expected then
        raise notice 'PASS: % (%)', _label, coalesce(_actual, 'null');
    else
        raise notice 'FAIL: % - got %, expected %', _label, coalesce(_actual, 'null'), coalesce(_expected, 'null');
    end if;
end;
$$;

-- the user's tenant action runs, oldest first
create or replace function pg_temp.me_runs(_user_id bigint) returns text
    language sql
as
$$
select coalesce(string_agg(a.code, ',' order by r.action_run_id), '')
from auth.action_run r
         inner join auth.action a on a.action_id = r.action_id
where r.user_id = _user_id
  and a.tenant_id is not null
  and a.code like 'me\_%';
$$;

-- the user's snapshot row in ABC: 'none', 'member' or '<strikes> missing'
create or replace function pg_temp.me_state(_user_id bigint) returns text
    language sql
as
$$
select coalesce((select case
                            when s.missing_since is null then 'member'
                            else s.not_found_strike_count || ' missing' end
                 from auth.tenant_membership_state s
                 where s.user_id = _user_id
                   and s.tenant_id = (select val::int from _me where key = 'abc')), 'none');
$$;

-- logs a user in through me_aad with the given groups, returns the user id
create or replace function pg_temp.me_login(_name text, _groups text[]) returns bigint
    language plpgsql
as
$$
declare
    __r record;
begin
    select * from auth.ensure_user_from_provider('me', 3, 'me', 'me_aad', 'uid-' || _name, 'oid-' || _name
        , 'me_' || _name, initcap(_name), _name || '@abc.com', null) into __r;
    if __r.__user_id is null then
        raise exception 'FAIL: login of % failed: %', _name, __r.__outcome_code;
    end if;
    perform auth.ensure_groups_and_permissions('me', 3, 'me', __r.__user_id, 'me_aad', _groups, null);
    return __r.__user_id;
end;
$$;

-- sets a tenant_membership system parameter
create or replace function pg_temp.me_param(_code text, _value bigint) returns void
    language sql
as
$$
update const.sys_param
set number_value = _value
  , text_value   = _value::text
where group_code = 'tenant_membership'
  and code = _code;
$$;
