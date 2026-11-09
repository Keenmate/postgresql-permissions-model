set search_path = public, const, ext, stage, helpers, internal, unsecure, auth, triggers;

-- ============================================================================
-- SETUP (provisioning as system)
--   provider gs_aad: group mapping + sync
--   tenant ABC:
--     "ABC Azure users"  synced, mapped to Azure abc, holds tenant_member
--     "Product owners"   synced picker list, mapped to Azure o1, o2, o3,
--                        grants nothing
--   svc_group_syncer (6) runs the sync, svc_authenticator (3) logs users in
-- ============================================================================
create temp table if not exists _gs (key text primary key, val bigint);

do $$
declare
    __abc int;
    __g   int;
    __po  int;
begin
    raise notice '';
    raise notice '=================================================================';
    raise notice 'Audit: external group sync - Starting';
    raise notice '=================================================================';

    insert into auth.provider (created_by, updated_by, code, is_active, allows_group_mapping, allows_group_sync)
    values ('gs', 'gs', 'gs_aad', true, true, true);

    select t.__tenant_id from auth.create_tenant('gs', 1, 'gs', 'GS ABC', 'gs_abc') t into __abc;

    select g.__user_group_id
    from auth.create_external_user_group('gs', 1, 'gs', 'ABC Azure users', 'gs_aad'
        , _mapped_object_id := 'abc', _mapped_object_name := 'Azure ABC', _tenant_id := __abc) g
    into __g;
    update auth.user_group set is_synced = true, create_missing_users_on_sync = true where user_group_id = __g;
    perform unsecure.assign_permission('gs', 1, 'gs', __g, null, 'tenant_member', _tenant_id := __abc);

    select g.__user_group_id
    from auth.create_external_user_group('gs', 1, 'gs', 'Product owners', 'gs_aad'
        , _mapped_object_id := 'o1', _mapped_object_name := 'Azure O1', _tenant_id := __abc) g
    into __po;
    perform auth.create_user_group_mapping('gs', 1, 'gs', __po, 'gs_aad', 'o2', 'Azure O2', _tenant_id := __abc);
    perform auth.create_user_group_mapping('gs', 1, 'gs', __po, 'gs_aad', 'o3', 'Azure O3', _tenant_id := __abc);
    update auth.user_group set is_synced = true, create_missing_users_on_sync = true where user_group_id = __po;

    insert into _gs values ('abc', __abc), ('g', __g), ('po', __po);
    insert into _gs select 'm_' || mapped_object_id, user_group_mapping_id from auth.user_group_mapping
    where user_group_id in (__g, __po);

    raise notice 'PASS: setup (ABC=%, ABC Azure users=%, Product owners=%)', __abc, __g, __po;
end $$;

-- what the syncer read from Azure: replaces the staged members of one mapping
create or replace function pg_temp.gs_stage(_mapped text, _names text[]) returns void
    language plpgsql
as
$$
declare
    __m int := (select val from _gs where key = 'm_' || _mapped);
begin
    delete from stage.external_group_member where user_group_mapping_id = __m;
    insert into stage.external_group_member (created_by, user_group_id, user_group_mapping_id, member_upn, member_display_name, member_email)
    select 'gs', (select user_group_id from auth.user_group_mapping where user_group_mapping_id = __m), __m
         , n || '@gs.com', initcap(n), n || '@gs.com'
    from unnest(_names) n;
end;
$$;

create or replace function pg_temp.gs_members(_group_key text) returns text
    language sql
as
$$
    select coalesce(string_agg(distinct split_part(ui.username, '@', 1), ',' order by split_part(ui.username, '@', 1)), '-')
    from auth.user_group_member ugm
             inner join auth.user_info ui on ui.user_id = ugm.user_id
    where ugm.user_group_id = (select val from _gs where key = _group_key)
$$;

create or replace function pg_temp.gs_tenant_members() returns text
    language sql
as
$$
    select coalesce(string_agg(distinct split_part(ui.username, '@', 1), ',' order by split_part(ui.username, '@', 1)), '-')
    from auth.tenant_memberships tm
             inner join auth.user_info ui on ui.user_id = tm.user_id
    where tm.tenant_id = (select val from _gs where key = 'abc')
      and ui.username like '%@gs.com'
$$;

create or replace function pg_temp.gs_login(_name text, _groups text[]) returns text
    language plpgsql
as
$$
declare
    __r record;
begin
    select * from auth.ensure_user_from_provider('gs', 3, 'gs', 'gs_aad', 'uid-' || _name, 'oid-' || _name
        , _name || '@gs.com', initcap(_name), _name || '@gs.com') into __r;
    if __r.__user_id is not null then
        perform auth.ensure_groups_and_permissions('gs', 3, 'gs', __r.__user_id, 'gs_aad', _groups, null);
    end if;
    return __r.__outcome_code;
end;
$$;

create or replace function pg_temp.gs_is(_what text, _actual text, _expected text) returns void
    language plpgsql
as
$$
begin
    if _actual is not distinct from _expected then
        raise notice 'PASS: %', _what;
    else
        raise notice 'FAIL: % - expected %, got %', _what, _expected, _actual;
    end if;
end;
$$;
