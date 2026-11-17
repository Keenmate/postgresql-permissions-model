/*
 * PostgreSQL Permissions Model — update v2.23
 * ===========================================
 *
 * Platform groups (D-13, step 4 of audit/design-d13-tenant-actions.md).
 *
 * Support staff who oversee tenants without being their members. A platform
 * group lives entirely in tenant 1: the group, its members, mappings, rules
 * and perm set. It has a scope: every tenant except tenant 1
 * (is_for_all_tenants), or a list (auth.platform_group_scope; list tenant 1
 * to cover it). A tenant opts out with auth.tenant.allows_platform_access,
 * set from tenant 1, which excludes it even from "all".
 *
 *  - The permission rebuild gives a member the group's perm sets and
 *    permissions in every tenant of the scope (view auth.platform_access).
 *    The group grants nothing in tenant 1 itself unless tenant 1 is listed.
 *  - The tenants contain nothing: no group, no mapping, no membership
 *    (auth.tenant_memberships ignores platform groups), so platform members
 *    are not in user lists, pickers or notifications.
 *  - Members see the tenants in their own tenant list
 *    (get_user_available_tenants.__is_platform_access) and may select them.
 *  - Journal: what a platform member does in a tenant they are not a member
 *    of is stored as "Platform support"; the person is kept in
 *    journal.platform_user_id / platform_created_by and shown only to tenant-1
 *    readers with platform.read_platform_objects.
 *  - Tenant 1: platform.manage_platform_objects (groups, members, mappings,
 *    perm sets, scopes, opt-outs) and platform.read_platform_objects (seeing
 *    them), in full_admin. Tenant-1 admins without them don't see platform
 *    groups at all.
 *
 * New: auth.create_platform_group, auth.update_platform_group_scope,
 * auth.get_platform_groups, auth.update_tenant_platform_access.
 */

set search_path = public, const, ext, stage, helpers, internal, unsecure, auth, triggers;

select *
from public.start_version_update('2.23', 'Platform groups',
                                 _component := 'postgresql_permissionmodel',
                                 _description := 'Platform groups live in tenant 1 with a scope (all tenants or a list) and grant their perm sets in the tenants in scope; tenants see nothing and can opt out; journal shows Platform support; platform.manage/read_platform_objects in tenant 1.');


/***
 *    tables
 */

alter table auth.user_group
    add column if not exists is_platform        boolean default false not null,
    add column if not exists is_for_all_tenants boolean default false not null;

alter table auth.user_group
    drop constraint if exists user_group_platform_in_tenant_1;
alter table auth.user_group
    add constraint user_group_platform_in_tenant_1 check (not is_platform or tenant_id = 1);

alter table auth.user_group
    drop constraint if exists user_group_all_tenants_is_platform;
alter table auth.user_group
    add constraint user_group_all_tenants_is_platform check (not is_for_all_tenants or is_platform);

create table if not exists auth.platform_group_scope
(
    created_at              timestamptz default now()     not null,
    created_by              text        default 'unknown' not null,
    platform_group_scope_id integer generated always as identity primary key,
    user_group_id           integer                       not null references auth.user_group on delete cascade,
    tenant_id               integer                       not null references auth.tenant on delete cascade,
    constraint platform_group_scope_created_by_check check (length(created_by) <= 250),
    constraint uq_platform_group_scope unique (user_group_id, tenant_id)
);

create index if not exists ix_platform_group_scope_tenant on auth.platform_group_scope (tenant_id);

alter table auth.tenant
    add column if not exists allows_platform_access boolean default true not null;

-- the person behind a "Platform support" entry, for tenant-1 readers only
alter table public.journal
    add column if not exists platform_user_id    bigint,
    add column if not exists platform_created_by text;


/***
 *    error codes and events
 */

insert into const.event_code (event_id, code, category_code, is_system, source)
values (13040, 'platform_group_scope_updated', 'group_event', true, 'core'),
       (11012, 'tenant_platform_access_updated', 'tenant_event', true, 'core'),
       (33027, 'err_user_group_not_platform', 'user_error', true, 'core')
on conflict do nothing;

insert into const.event_message (event_id, language_code, message_template)
values (13040, 'en', 'Scope of platform group "{group_title}" was updated by {actor}'),
       (11012, 'en', 'Platform access of tenant (id: {target_tenant_id}) was set to {allows_platform_access} by {actor}'),
       (33027, 'en', 'User group (id: {user_group_id}) is not a platform group')
on conflict do nothing;

-- 33027: a platform-only operation on an ordinary group
create or replace function error.raise_33027(_user_group_id integer) returns void
    language plpgsql
as
$$
begin
    raise exception 'User group (id: %) is not a platform group', _user_group_id
        using errcode = '33027';
end;
$$;


/***
 *    permissions
 */

select unsecure.create_permission_as_system('Platform', '', false, _source := 'core')
where not exists(select from auth.permission where full_code = 'platform');
select unsecure.create_permission_as_system('Manage platform objects', 'platform', true, _source := 'core')
where not exists(select from auth.permission where full_code = 'platform.manage_platform_objects');
select unsecure.create_permission_as_system('Read platform objects', 'platform', true, _source := 'core')
where not exists(select from auth.permission where full_code = 'platform.read_platform_objects');

select unsecure.create_perm_set_permissions('update_v2.23', 1, null, ps.perm_set_id
    , array ['platform.manage_platform_objects', 'platform.read_platform_objects'], 1)
from auth.perm_set ps
where ps.tenant_id = 1
  and ps.code = 'full_admin';


/***
 *    who has platform access where
 */

-- (tenant, user, group): the user is in an active platform group whose scope
-- contains the live tenant, and the tenant allows platform access. Mapped
-- memberships count only with an active provider and identity, like everywhere.
create or replace view auth.platform_access (tenant_id, user_id, user_group_id) as
select t.tenant_id
     , ugm.user_id
     , ug.user_group_id
from auth.user_group_member ugm
         inner join auth.user_group ug on ug.user_group_id = ugm.user_group_id
         left join auth.user_group_mapping m on m.user_group_mapping_id = ugm.mapping_id
         left join auth.provider pr on pr.code = m.provider_code
         left join auth.user_identity uid on uid.user_id = ugm.user_id and uid.provider_code = m.provider_code
         inner join auth.tenant t on t.deleted_at is null
    and t.allows_platform_access
    and ((ug.is_for_all_tenants and t.tenant_id <> 1)
        or exists(select
                  from auth.platform_group_scope s
                  where s.user_group_id = ug.user_group_id
                    and s.tenant_id = t.tenant_id))
where ug.is_platform
  and ug.is_active
  and (ugm.mapping_id is null
    or m.provider_code is null
    or (coalesce(pr.is_active, false) and coalesce(uid.is_active, true)));

-- the user acts in the tenant through platform access only (not a member there)
create or replace function unsecure.is_acting_as_platform_support(_user_id bigint, _tenant_id integer) returns boolean
    stable
    language sql
as
$$
select exists(select
              from auth.platform_access pa
              where pa.user_id = _user_id
                and pa.tenant_id = _tenant_id)
           and not exists(select
                          from auth.tenant_memberships tm
                          where tm.user_id = _user_id
                            and tm.tenant_id = _tenant_id);
$$;

-- a platform group needs platform.manage_platform_objects (or read) in tenant 1
create or replace function unsecure.validate_platform_group_access(_user_id bigint, _correlation_id text,
                                                                   _user_group_id integer,
                                                                   _is_manage boolean default true) returns void
    language plpgsql
as
$$
begin
    if exists(select from auth.user_group ug where ug.user_group_id = _user_group_id and ug.is_platform) then
        perform auth.has_permission(_user_id, _correlation_id
            , case when _is_manage then 'platform.manage_platform_objects' else 'platform.read_platform_objects' end, 1);
    end if;
end;
$$;

-- the group belongs to the tenant (33011); a platform group also needs the platform permission
create or replace function unsecure.validate_user_group_access(_user_id bigint, _correlation_id text,
                                                               _user_group_id integer, _tenant_id integer,
                                                               _is_manage boolean default true) returns void
    language plpgsql
as
$$
begin
    perform unsecure.validate_user_group_in_tenant(_user_group_id, _tenant_id);
    perform unsecure.validate_platform_group_access(_user_id, _correlation_id, _user_group_id, _is_manage);
end;
$$;

-- every id is a live tenant (34003)
create or replace function unsecure.validate_platform_scope(_scope_tenant_ids integer[]) returns void
    language plpgsql
as
$$
declare
    __tenant_id integer;
begin
    select i
    from unnest(_scope_tenant_ids) i
    where not exists(select from auth.tenant t where t.tenant_id = i and t.deleted_at is null)
    limit 1
    into __tenant_id;

    if __tenant_id is not null then
        perform error.raise_34003(__tenant_id::text);
    end if;
end;
$$;

-- members of the platform group get a fresh permission rebuild in every tenant
create or replace function unsecure.invalidate_platform_group_members_cache(_updated_by text, _user_group_id integer) returns void
    language sql
as
$$
update auth.user_permission_cache
set expiration_date = now()
  , updated_by      = _updated_by
  , updated_at      = now()
where user_id in (select ugm.user_id
                  from auth.user_group_member ugm
                  where ugm.user_group_id = _user_group_id);
$$;


/***
 *    platform groups
 */

create or replace function auth.create_platform_group(_created_by text, _user_id bigint, _correlation_id text, _title text,
                                                      _is_for_all_tenants boolean default false,
                                                      _scope_tenant_ids integer[] default null)
    returns table(__user_group_id integer)
    rows 1
    language plpgsql
as
$$
declare
    ___user_group_id integer;
begin
    perform auth.has_permission(_user_id, _correlation_id, 'platform.manage_platform_objects', 1);
    perform unsecure.validate_platform_scope(_scope_tenant_ids);

    select g.__user_group_id
    from unsecure.create_user_group(_created_by, _user_id, _correlation_id, _title, _tenant_id := 1) g
    into ___user_group_id;

    update auth.user_group
    set is_platform        = true
      , is_for_all_tenants = coalesce(_is_for_all_tenants, false)
    where user_group_id = ___user_group_id;

    insert into auth.platform_group_scope (created_by, user_group_id, tenant_id)
    select distinct _created_by, ___user_group_id, i
    from unnest(_scope_tenant_ids) i;

    perform public.create_journal_message_for_entity(_created_by, _user_id, _correlation_id
        , 13040  -- platform_group_scope_updated
        , 'group', ___user_group_id
        , jsonb_build_object('group_title', _title, 'is_for_all_tenants', coalesce(_is_for_all_tenants, false)
            , 'scope_tenant_ids', to_jsonb(_scope_tenant_ids))
        , 1);

    return query select ___user_group_id;
end;
$$;

create or replace function auth.update_platform_group_scope(_updated_by text, _user_id bigint, _correlation_id text,
                                                            _user_group_id integer, _is_for_all_tenants boolean,
                                                            _scope_tenant_ids integer[] default null) returns void
    language plpgsql
as
$$
declare
    __title text;
begin
    perform auth.has_permission(_user_id, _correlation_id, 'platform.manage_platform_objects', 1);
    perform unsecure.validate_user_group_in_tenant(_user_group_id, 1);

    select ug.title
    from auth.user_group ug
    where ug.user_group_id = _user_group_id
      and ug.is_platform
    into __title;

    if __title is null then
        perform error.raise_33027(_user_group_id);
    end if;

    perform unsecure.validate_platform_scope(_scope_tenant_ids);

    update auth.user_group
    set is_for_all_tenants = coalesce(_is_for_all_tenants, false)
      , updated_by         = _updated_by
      , updated_at         = now()
    where user_group_id = _user_group_id;

    delete
    from auth.platform_group_scope s
    where s.user_group_id = _user_group_id
      and s.tenant_id <> all (coalesce(_scope_tenant_ids, array []::integer[]));

    insert into auth.platform_group_scope (created_by, user_group_id, tenant_id)
    select distinct _updated_by, _user_group_id, i
    from unnest(_scope_tenant_ids) i
    on conflict (user_group_id, tenant_id) do nothing;

    perform unsecure.invalidate_platform_group_members_cache(_updated_by, _user_group_id);

    perform public.create_journal_message_for_entity(_updated_by, _user_id, _correlation_id
        , 13040  -- platform_group_scope_updated
        , 'group', _user_group_id
        , jsonb_build_object('group_title', __title, 'is_for_all_tenants', coalesce(_is_for_all_tenants, false)
            , 'scope_tenant_ids', to_jsonb(_scope_tenant_ids))
        , 1);
end;
$$;

create or replace function auth.get_platform_groups(_user_id bigint, _correlation_id text)
    returns table
            (
                __user_group_id     integer,
                __code              text,
                __title             text,
                __is_active         boolean,
                __is_for_all_tenants boolean,
                __scope_tenant_ids  integer[],
                __member_count      bigint
            )
    stable
    language plpgsql
as
$$
begin
    perform auth.has_permission(_user_id, _correlation_id, 'platform.read_platform_objects', 1);

    return query
        select ug.user_group_id
             , ug.code
             , ug.title
             , ug.is_active
             , ug.is_for_all_tenants
             , coalesce((select array_agg(s.tenant_id order by s.tenant_id)
                         from auth.platform_group_scope s
                         where s.user_group_id = ug.user_group_id), array []::integer[])
             , (select count(*) from auth.user_group_member ugm where ugm.user_group_id = ug.user_group_id)
        from auth.user_group ug
        where ug.is_platform
        order by ug.title;
end;
$$;

-- tenant 1 decides whether a tenant takes platform access at all
create or replace function auth.update_tenant_platform_access(_updated_by text, _user_id bigint, _correlation_id text,
                                                              _target_tenant_id integer,
                                                              _allows_platform_access boolean) returns void
    language plpgsql
as
$$
begin
    perform auth.has_permission(_user_id, _correlation_id, 'platform.manage_platform_objects', 1);

    if not exists(select from auth.tenant t where t.tenant_id = _target_tenant_id) then
        perform error.raise_34003(_target_tenant_id::text);
    end if;

    update auth.tenant
    set allows_platform_access = _allows_platform_access
      , updated_by             = _updated_by
      , updated_at             = now()
    where tenant_id = _target_tenant_id;

    -- everybody re-derives their permissions in the tenant
    update auth.user_permission_cache
    set expiration_date = now()
      , updated_by      = _updated_by
      , updated_at      = now()
    where tenant_id = _target_tenant_id;

    perform public.create_journal_message_for_entity(_updated_by, _user_id, _correlation_id
        , 11012  -- tenant_platform_access_updated
        , 'tenant', _target_tenant_id
        , jsonb_build_object('target_tenant_id', _target_tenant_id, 'allows_platform_access', _allows_platform_access)
        , 1);
end;
$$;


/***
 *    available tenants
 */

drop function if exists auth.get_user_available_tenants(bigint, text, bigint, integer);

create or replace function auth.get_user_available_tenants(_user_id bigint, _correlation_id text, _target_user_id bigint,
                                                           _tenant_id integer default 1)
    returns table
            (
                __tenant_id          integer,
                __tenant_uuid        text,
                __tenant_code        text,
                __tenant_title       text,
                __tenant_is_default  boolean,
                __is_platform_access boolean
            )
    language plpgsql
as
$$
declare
    __necessary_permission_code text := 'users.get_available_tenants';
begin
    if _user_id <> _target_user_id and not auth.has_permission(_user_id, _correlation_id, __necessary_permission_code, _tenant_id)
    then
        perform internal.throw_no_permission(_user_id, __necessary_permission_code);
    end if;

    -- tenants the user is a member of (D-03), then the ones they support through a platform group
    return query
        select t.tenant_id
             , t.uuid::text
             , t.code
             , t.title
             , t.is_default
             , not exists(select
                          from auth.tenant_memberships tm
                          where tm.tenant_id = t.tenant_id
                            and tm.user_id = _target_user_id)
        from auth.tenant t
        where t.deleted_at is null
          and (exists(select
                      from auth.tenant_memberships tm
                      where tm.tenant_id = t.tenant_id
                        and tm.user_id = _target_user_id)
            or exists(select
                      from auth.platform_access pa
                      where pa.tenant_id = t.tenant_id
                        and pa.user_id = _target_user_id))
        order by t.title;
end;
$$;


/***
 *    the functions that change
 */

create or replace function unsecure.recalculate_user_permissions(_created_by text, _target_user_id bigint, _tenant_id integer DEFAULT NULL::integer)
    returns TABLE(__tenant_id integer, __tenant_uuid uuid, __groups text[], __permissions text[], __short_code_permissions text[])
    language plpgsql
as
$$
declare
    __perm_cache_timeout_in_s bigint;
    __expiration_date         timestamptz;
    __is_active               boolean;
    __is_locked               boolean;
begin

    -- Check if user is active and not locked
    select is_active, is_locked
    from auth.user_info
    where user_id = _target_user_id
    into __is_active, __is_locked;

    if __is_active is null then
        perform error.raise_33001(_target_user_id, null);
    end if;

    if not __is_active then
        perform error.raise_33003(_target_user_id);
    end if;

    if __is_locked then
        perform error.raise_33004(_target_user_id);
    end if;

    if _tenant_id is not null and exists(
            select
            from auth.user_permission_cache
            where tenant_id = _tenant_id
              and user_id = _target_user_id
              and expiration_date > now())
    then

        return query
            select _tenant_id
                 , upc.tenant_uuid
                 , upc.groups
                 , upc.permissions
                 , upc.short_code_permissions
            from auth.user_permission_cache upc
            where upc.tenant_id = _tenant_id
              and upc.user_id = _target_user_id;
    else
        select number_value
        from const.sys_param sp
        where sp.group_code = 'auth'
          and sp.code = 'perm_cache_timeout_in_s'
        into __perm_cache_timeout_in_s;

        if
            (__perm_cache_timeout_in_s is null)
        then
            __perm_cache_timeout_in_s := 300;
        end if;

        drop table if exists __temp_users_groups_permissions;
        create temporary table __temp_users_groups_permissions
        (
            tenant_id                integer,
            tenant_uuid              uuid,
            group_codes              text[],
            permission_codes         text[],
            short_code_permission_codes text[]
        ) on commit drop;

        -- Only memberships that grant: active group, live tenant, and for mapped
        -- (external / synced) memberships an active provider and a not-disabled
        -- identity of the user at that provider.
        with ugs as (
            select distinct ug.tenant_id
                          , t.uuid as tenant_uuid
                          , ug.user_group_id
                          , ug.code as group_code
            from auth.user_group_member ugm
                     inner join auth.user_group ug on ug.user_group_id = ugm.user_group_id
                     inner join auth.tenant t on t.tenant_id = ug.tenant_id
                     left join auth.user_group_mapping m on m.user_group_mapping_id = ugm.mapping_id
                     left join auth.provider pr on pr.code = m.provider_code
                     left join auth.user_identity uid on uid.user_id = ugm.user_id and uid.provider_code = m.provider_code
            where ugm.user_id = _target_user_id
              and ug.is_active
              and not ug.is_platform  -- platform groups grant in the tenants of their scope (v2.23)
              and t.deleted_at is null
              and (ugm.mapping_id is null
                or m.provider_code is null  -- rule mapping (v2.21)
                or (coalesce(pr.is_active, false) and coalesce(uid.is_active, true))))
           , group_assignments as (
            select distinct pa.tenant_id
                          , ug.tenant_uuid
                          , ep.permission_code as full_code
                          , ep.permission_short_code as short_code
            from ugs ug
                     inner join auth.permission_assignment pa
                                on ug.user_group_id = pa.user_group_id and pa.tenant_id = ug.tenant_id
                     inner join auth.effective_permissions ep on pa.perm_set_id = ep.perm_set_id
            where ep.perm_set_is_assignable = true
              and ep.permission_is_assignable = true
            union
            select distinct pa.tenant_id
                          , ug.tenant_uuid
                          , sp.full_code
                          , sp.short_code
            from ugs ug
                     inner join auth.permission_assignment pa
                                on ug.user_group_id = pa.user_group_id and pa.tenant_id = ug.tenant_id
                     inner join auth.permission p on pa.permission_id = p.permission_id
                     inner join auth.permission sp
                                on sp.node_path <@ p.node_path and sp.is_assignable = true)
           , user_assignments as (
            select distinct pa.tenant_id
                          , t.uuid             as tenant_uuid
                          , ep.permission_code as full_code
                          , ep.permission_short_code as short_code
            from auth.permission_assignment pa
                     inner join auth.tenant t on pa.tenant_id = t.tenant_id and t.deleted_at is null
                     inner join auth.effective_permissions ep
                                on pa.perm_set_id = ep.perm_set_id
            where pa.user_id = _target_user_id
              and ep.perm_set_is_assignable = true
              and ep.permission_is_assignable = true
            union
            select distinct pa.tenant_id
                          , t.uuid as tenant_uuid
                          , sp.full_code
                          , sp.short_code
            from auth.permission_assignment pa
                     inner join auth.tenant t on pa.tenant_id = t.tenant_id and t.deleted_at is null
                     inner join auth.permission p
                                on pa.permission_id = p.permission_id
                     inner join auth.permission sp
                                on sp.node_path <@ p.node_path and sp.is_assignable = true
            where pa.user_id = _target_user_id)
           , owner_assignments as (
            -- a tenant-wide owner holds the tenant's tenant_owner perm set (D-05)
            select distinct o.tenant_id
                          , t.uuid                   as tenant_uuid
                          , ep.permission_code       as full_code
                          , ep.permission_short_code as short_code
            from auth.owner o
                     inner join auth.tenant t on t.tenant_id = o.tenant_id and t.deleted_at is null
                     inner join auth.perm_set ps on ps.tenant_id = o.tenant_id and ps.code = 'tenant_owner'
                     inner join auth.effective_permissions ep on ep.perm_set_id = ps.perm_set_id
            where o.user_id = _target_user_id
              and o.user_group_id is null
              and ep.permission_is_assignable = true)
           , platform_assignments as (
            -- a platform group's perm sets and permissions, in every tenant of its scope (v2.23)
            select distinct pac.tenant_id
                          , t.uuid                   as tenant_uuid
                          , ep.permission_code       as full_code
                          , ep.permission_short_code as short_code
            from auth.platform_access pac
                     inner join auth.tenant t on t.tenant_id = pac.tenant_id
                     inner join auth.permission_assignment pa on pa.user_group_id = pac.user_group_id
                     inner join auth.effective_permissions ep on pa.perm_set_id = ep.perm_set_id
            where pac.user_id = _target_user_id
              and ep.perm_set_is_assignable = true
              and ep.permission_is_assignable = true
            union
            select distinct pac.tenant_id
                          , t.uuid as tenant_uuid
                          , sp.full_code
                          , sp.short_code
            from auth.platform_access pac
                     inner join auth.tenant t on t.tenant_id = pac.tenant_id
                     inner join auth.permission_assignment pa on pa.user_group_id = pac.user_group_id
                     inner join auth.permission p on pa.permission_id = p.permission_id
                     inner join auth.permission sp
                                on sp.node_path <@ p.node_path and sp.is_assignable = true
            where pac.user_id = _target_user_id)
           , user_permissions as (
            select distinct ga.tenant_id
                          , ga.tenant_uuid
                          , ga.full_code
                          , ga.short_code
            from group_assignments ga
            union
            select ua.tenant_id
                 , ua.tenant_uuid
                 , ua.full_code
                 , ua.short_code
            from user_assignments ua
            union
            select oa.tenant_id
                 , oa.tenant_uuid
                 , oa.full_code
                 , oa.short_code
            from owner_assignments oa
            union
            select pla.tenant_id
                 , pla.tenant_uuid
                 , pla.full_code
                 , pla.short_code
            from platform_assignments pla
            order by full_code)
        insert
        into __temp_users_groups_permissions(tenant_id, tenant_uuid, group_codes, permission_codes, short_code_permission_codes)
        select data.tenant_id
             , data.tenant_uuid
             , coalesce(array_agg(distinct data.groups) filter ( where data.groups is not null ), array []::text[])
             , coalesce(array_agg(distinct data.perms) filter ( where data.perms is not null ), array []::text[])
             , coalesce(array_agg(distinct data.short_code_perms) filter ( where data.short_code_perms is not null ), array []::text[])
        from (
                 select ug.tenant_id
                      , ug.tenant_uuid
                      , ug.group_code as groups
                      , null          as perms
                      , null          as short_code_perms
                 from ugs ug
                 union
                 select up.tenant_id
                      , up.tenant_uuid
                      , null
                      , up.full_code::text
                      , up.short_code
                 from user_permissions up) data
        group by data.tenant_id, data.tenant_uuid;

        __expiration_date := now() + interval '1 second' * __perm_cache_timeout_in_s;

        insert into auth.user_permission_cache (created_by, user_id, tenant_id, tenant_uuid, groups, permissions,
                                                short_code_permissions, expiration_date)
        select _created_by
             , _target_user_id
             , tugp.tenant_id
             , tugp.tenant_uuid
             , tugp.group_codes
             , tugp.permission_codes
             , tugp.short_code_permission_codes
             , __expiration_date
        from __temp_users_groups_permissions tugp
        on conflict (user_id, tenant_id )
            do update
            set updated_at              = now()
              , updated_by              = _created_by
              , groups                  = excluded.groups
              , permissions             = excluded.permissions
              , short_code_permissions  = excluded.short_code_permissions
              , expiration_date         = __expiration_date;

        return query
            select ugp.tenant_id
                 , ugp.tenant_uuid
                 , ugp.group_codes
                 , ugp.permission_codes
                 , ugp.short_code_permission_codes
            from __temp_users_groups_permissions ugp
            where _tenant_id is null
               or ugp.tenant_id = _tenant_id
            order by ugp.tenant_id;
    end if;
end;
$$;

create or replace view auth.tenant_memberships (tenant_id, user_id, source_code) as
select ug.tenant_id
     , ugm.user_id
     , 'group'::text
from auth.user_group_member ugm
         inner join auth.user_group ug on ug.user_group_id = ugm.user_group_id
         left join auth.user_group_mapping m on m.user_group_mapping_id = ugm.mapping_id
         left join auth.provider pr on pr.code = m.provider_code
         left join auth.user_identity uid on uid.user_id = ugm.user_id and uid.provider_code = m.provider_code
where ug.is_active
  and not ug.is_platform  -- platform members are never members of the tenants they support (v2.23)
  and (ugm.mapping_id is null
    or m.provider_code is null  -- rule mapping (v2.21)
    or (coalesce(pr.is_active, false) and coalesce(uid.is_active, true)))
  -- only groups that grant something; a picker list grants nothing
  and (exists(select from auth.permission_assignment gpa where gpa.user_group_id = ug.user_group_id)
    or exists(select from auth.resource_access gra
              where gra.user_group_id = ug.user_group_id and not gra.is_deny)
    or exists(select from auth.resource_role_assignment grra
                       inner join const.resource_role grr on grr.code = grra.role_code and grr.is_active
              where grra.user_group_id = ug.user_group_id))
union all
select pa.tenant_id
     , pa.user_id
     , 'assignment'::text
from auth.permission_assignment pa
where pa.user_id is not null
union all
select o.tenant_id
     , o.user_id
     , 'owner'::text
from auth.owner o
union all
select ra.tenant_id
     , ra.user_id
     , 'resource_access'::text
from auth.resource_access ra
where ra.user_id is not null
  and not ra.is_deny
union all
select rra.tenant_id
     , rra.user_id
     , 'resource_role'::text
from auth.resource_role_assignment rra
         inner join const.resource_role rr on rr.code = rra.role_code and rr.is_active
where rra.user_id is not null;

-- tenant_id -> affected user_ids
-- Used for: tenant_purged
create or replace view auth.notify_tenant_users
            (tenant_id, user_id) as
select distinct tm.tenant_id
              , tm.user_id::integer
from auth.tenant_memberships tm;


-- Tenant 1 gets the Tenant Members group every other tenant has (add_tenant_user)
do
$$
declare
    __group_id integer;
begin
    if not exists(select from auth.user_group where tenant_id = 1 and code = 'tenant_members') then
        select g.__user_group_id
        from unsecure.create_user_group('update_v2.17', 1, null, 'Tenant Members'
            , true, true, false, true, _tenant_id := 1) g
        into __group_id;

        if exists(select from auth.perm_set where tenant_id = 1 and code = 'tenant_member') then
            perform unsecure.assign_permission('update_v2.17', 1, null
                , __group_id, null, 'tenant_member', _tenant_id := 1);
        end if;
    end if;
end;
$$;

create or replace function unsecure.get_cached_group_ids(
    _user_id   bigint,
    _tenant_id integer
) returns integer[]
    language plpgsql
as
$$
declare
    __group_ids               integer[];
    __perm_cache_timeout_in_s bigint;
    __expiration_date         timestamptz;
begin
    -- Check for non-expired cache entry
    select group_ids
    from auth.user_group_id_cache
    where user_id = _user_id
      and tenant_id = _tenant_id
      and expiration_date > now()
    into __group_ids;

    if found then
        return __group_ids;
    end if;

    -- Cache miss or expired — resolve from source tables
    select coalesce(array_agg(ug.user_group_id), '{}')
    from auth.user_group_member ugm
    inner join auth.user_group ug on ug.user_group_id = ugm.user_group_id
        and ug.is_active = true
        and ug.tenant_id = _tenant_id
        and not ug.is_platform
    where ugm.user_id = _user_id
    into __group_ids;

    -- Read TTL from sys_param (same as permission cache)
    select number_value
    from const.sys_param sp
    where sp.group_code = 'auth'
      and sp.code = 'perm_cache_timeout_in_s'
    into __perm_cache_timeout_in_s;

    if __perm_cache_timeout_in_s is null then
        __perm_cache_timeout_in_s := 300;
    end if;

    __expiration_date := now() + interval '1 second' * __perm_cache_timeout_in_s;

    -- Upsert cache entry
    insert into auth.user_group_id_cache (
        created_by, updated_by, user_id, tenant_id, group_ids, expiration_date
    ) values (
        'cache', 'cache', _user_id, _tenant_id, __group_ids, __expiration_date
    )
    on conflict (user_id, tenant_id) do update
    set group_ids = excluded.group_ids,
        expiration_date = excluded.expiration_date,
        updated_by = 'cache',
        updated_at = now();

    return __group_ids;
end;
$$;

create or replace function unsecure.invalidate_group_members_permission_cache(_updated_by text, _user_group_id integer, _tenant_id integer DEFAULT 1) returns void
    language plpgsql
as
$$
begin
    update auth.user_permission_cache
    set expiration_date = now(),
        updated_by = _updated_by,
        updated_at = now()
    -- a platform group's members hold its permissions in other tenants too (v2.23)
    where (tenant_id = _tenant_id
        or exists(select from auth.user_group ug where ug.user_group_id = _user_group_id and ug.is_platform))
      and user_id in (
          select user_id
          from auth.user_group_member
          where user_group_id = _user_group_id
      );
end;
$$;

create or replace function unsecure.invalidate_perm_set_users_permission_cache(_updated_by text, _perm_set_id integer, _tenant_id integer DEFAULT 1) returns void
    language plpgsql
as
$$
begin
    -- Soft invalidate cache for users who have this perm_set directly assigned
    update auth.user_permission_cache
    set expiration_date = now(),
        updated_by = _updated_by,
        updated_at = now()
    where tenant_id = _tenant_id
      and user_id in (
          select user_id
          from auth.permission_assignment
          where perm_set_id = _perm_set_id
            and user_id is not null
      );

    -- Soft invalidate cache for users who are members of groups that have this perm_set assigned
    update auth.user_permission_cache
    set expiration_date = now(),
        updated_by = _updated_by,
        updated_at = now()
    where tenant_id = _tenant_id
      and user_id in (
          select ugm.user_id
          from auth.permission_assignment pa
          inner join auth.user_group_member ugm on ugm.user_group_id = pa.user_group_id
          where pa.perm_set_id = _perm_set_id
      );

    -- Soft invalidate cache for owners when this is their tenant's tenant_owner perm set
    update auth.user_permission_cache
    set expiration_date = now(),
        updated_by = _updated_by,
        updated_at = now()
    where tenant_id = _tenant_id
      and user_id in (
          select o.user_id
          from auth.perm_set ps
          inner join auth.owner o on o.tenant_id = ps.tenant_id and o.user_group_id is null
          where ps.perm_set_id = _perm_set_id
            and ps.code = 'tenant_owner'
      );
    -- members of platform groups hold the set in the tenants of the scope (v2.23)
    update auth.user_permission_cache
    set expiration_date = now(),
        updated_by = _updated_by,
        updated_at = now()
    where user_id in (
          select ugm.user_id
          from auth.permission_assignment pa
          inner join auth.user_group ug on ug.user_group_id = pa.user_group_id and ug.is_platform
          inner join auth.user_group_member ugm on ugm.user_group_id = pa.user_group_id
          where pa.perm_set_id = _perm_set_id
      );
end;
$$;

create or replace function triggers.cache_user_group_member_insert() returns trigger
    language plpgsql
as
$$
begin
    perform unsecure.invalidate_user_group_id_cache(NEW.user_id, null);
    -- a platform group grants in other tenants (v2.23)
    if exists(select from auth.user_group ug where ug.user_group_id = NEW.user_group_id and ug.is_platform) then
        perform unsecure.clear_permission_cache('trigger', NEW.user_id, null);
    end if;
    return NEW;
end;
$$;

create or replace function triggers.cache_user_group_before_delete() returns trigger
    language plpgsql
as
$$
declare
    __affected_user_ids bigint[];
begin
    select array_agg(user_id)
    from auth.user_group_member
    where user_group_id = OLD.user_group_id
    into __affected_user_ids;

    if __affected_user_ids is not null then
        perform unsecure.invalidate_users_permission_cache('trigger', __affected_user_ids
            , case when OLD.is_platform then null else OLD.tenant_id end);
        -- Hard-clear group ID cache for all affected members
        perform unsecure.invalidate_user_group_id_cache(uid, OLD.tenant_id)
        from unnest(__affected_user_ids) as uid;
    end if;

    return OLD;
end;
$$;

create or replace function auth.update_user_last_selected_tenant(_updated_by text, _user_id bigint, _correlation_id text, _target_user_id bigint, _tenant_uuid text, _tenant_id integer DEFAULT 1)
    returns TABLE(__used_id bigint, __tenant_id integer)
    rows 1
    language plpgsql
as
$$
declare
    __tenant_id int;
begin
    if _user_id <> _target_user_id
    then
        perform auth.has_permission(_user_id, _correlation_id, 'users.update_last_selected_tenant', _tenant_id);
    end if;

    -- the target user must be a member of the tenant (D-03), not the caller
    select t.tenant_id
    from auth.tenant t
    where t.uuid = _tenant_uuid::uuid
      and t.deleted_at is null
      and (exists(select from auth.tenant_memberships tm
                  where tm.tenant_id = t.tenant_id
                    and tm.user_id = _target_user_id)
        or exists(select from auth.platform_access pa
                  where pa.tenant_id = t.tenant_id
                    and pa.user_id = _target_user_id))
    into __tenant_id;

    if __tenant_id is null
    then
        perform error.raise_34001(_tenant_uuid, _target_user_id::text);
    end if;

    return query
        update auth.user_info
            set updated_at = now()
                , updated_by = _updated_by
                , last_selected_tenant_id = __tenant_id
            where user_id = _target_user_id
            returning user_id, last_selected_tenant_id;


    if _user_id <> _target_user_id and _user_id <> 1
    then
        perform public.create_journal_message_for_entity('system', _user_id, _correlation_id
                , 10002  -- user_updated
                , 'user', _target_user_id
                , jsonb_build_object('username', _target_user_id::text, 'tenant_id', __tenant_id
                    , 'action', 'last_selected_tenant_updated')
                , 1);
    end if;
end;
$$;

create or replace function public.create_journal_message(
    _created_by text,
    _user_id bigint,
    _correlation_id text,
    _event_id integer,
    _keys jsonb default null,
    _payload jsonb default null,
    _tenant_id integer default 1,
    _request_context jsonb default null
) returns table(
    __created_at      timestamptz,
    __created_by      text,
    __correlation_id  text,
    __journal_id      bigint,
    __tenant_id       integer,
    __event_id        integer,
    __user_id         bigint,
    __keys            jsonb,
    __data_payload    jsonb,
    __request_context jsonb
)
    rows 1
    language plpgsql
as
$$
declare
    __platform_user_id    bigint;
    __platform_created_by text;
begin
    -- platform support acting in a tenant they aren't a member of: the tenant sees "Platform support",
    -- the person is kept apart for tenant-1 readers (v2.23)
    if _tenant_id is distinct from 1 and _user_id is not null and _user_id <> 1
        and unsecure.is_acting_as_platform_support(_user_id, _tenant_id) then
        __platform_user_id := _user_id;
        __platform_created_by := _created_by;
        _user_id := null;
        _created_by := 'Platform support';
    end if;

    -- Check if we should log based on journal level and event type
    if not helpers.should_log_journal(helpers.is_event_read_only(_event_id)) then
        return;
    end if;

    -- Notify if storage mode requires it
    if helpers.should_notify_storage('journal') then
        perform unsecure.notify_journal_event(
            _created_by, _user_id, _correlation_id, _event_id,
            _keys, _payload, _tenant_id, _request_context);
    end if;

    -- Only INSERT if storage mode is 'local' or 'both'
    if not helpers.should_store_locally('journal') then
        return;
    end if;

    return query
        insert into journal (created_by, user_id, correlation_id, event_id, keys, data_payload, tenant_id, request_context
                           , platform_user_id, platform_created_by)
        values (_created_by, _user_id, _correlation_id, _event_id, _keys, _payload, _tenant_id, _request_context
               , __platform_user_id, __platform_created_by)
        returning created_at, created_by, correlation_id, journal_id, tenant_id, event_id, user_id, keys, data_payload, request_context;
end;
$$;

create or replace function public.search_journal(
    _user_id bigint,
    _correlation_id text default null,
    _search_text text default null,
    _from timestamptz default null,
    _to timestamptz default null,
    _target_user_id bigint default null,
    _event_id integer default null,
    _event_category text default null,
    _keys_criteria jsonb default null,
    _payload_criteria jsonb default null,
    _request_context_criteria jsonb default null,
    _page integer default 1,
    _page_size integer default 10,
    _tenant_id integer default 1
)
    returns table(
        __journal_id bigint,
        __event_id integer,
        __event_code text,
        __event_category text,
        __user_id bigint,
        __message text,
        __keys jsonb,
        __request_context jsonb,
        __created_at timestamptz,
        __created_by text,
        __correlation_id text,
        __total_items bigint
    )
    stable
    language plpgsql
as
$$
declare
    __can_read_global_journal bool;
    __normalized_search text;
    __can_read_platform bool;
begin
    __can_read_global_journal = auth.has_permission(_user_id, _correlation_id, 'journal.read_global_journal', _throw_err := false);

    if (_tenant_id = 1) then
        if not __can_read_global_journal then
            perform internal.throw_no_permission(_user_id, 'journal.read_global_journal');
        end if;
    else
        perform auth.has_permission(_user_id, _correlation_id, 'journal.read_journal', _tenant_id);
    end if;

    __normalized_search := helpers.normalize_text(_search_text);
    -- the person behind "Platform support" entries: tenant-1 readers with the platform permission (v2.23)
    __can_read_platform := _tenant_id = 1
        and auth.has_permission(_user_id, _correlation_id, 'platform.read_platform_objects', 1, _throw_err := false);

    return query
        with filtered_rows as (
            select j.journal_id
                 , j.created_at as journal_created_at
                 , count(1) over () as total_items
            from journal j
            left join const.event_code ec on ec.event_id = j.event_id
            where (helpers.is_empty_string(__normalized_search) or
                   j.data_payload::text ilike '%' || __normalized_search || '%')
              and ((_tenant_id = 1 and __can_read_global_journal) or j.tenant_id = _tenant_id)
              and (_target_user_id is null or j.user_id = _target_user_id
                or (__can_read_platform and j.platform_user_id = _target_user_id))
              and (_event_id is null or j.event_id = _event_id)
              and (_event_category is null or ec.category_code = _event_category)
              and (_keys_criteria is null or j.keys @> _keys_criteria)
              and (_payload_criteria is null or j.data_payload @> _payload_criteria)
              and (_request_context_criteria is null or j.request_context @> _request_context_criteria)
              and (_correlation_id is null or j.correlation_id = _correlation_id)
              and j.created_at between coalesce(_from, now() - interval '100 years')
                                   and coalesce(_to, now() + interval '100 years')
            order by j.created_at desc
            offset ((_page - 1) * _page_size) limit _page_size
        )
        select j.journal_id
             , j.event_id
             , ec.code
             , ec.category_code
             , case when __can_read_platform then coalesce(j.platform_user_id, j.user_id) else j.user_id end
             , format_journal_message(
                   get_event_message_template(j.event_id),
                   j.data_payload,
                   case when __can_read_platform then coalesce(j.platform_created_by, j.created_by) else j.created_by end
               )
             , j.keys
             , j.request_context
             , j.created_at
             , case when __can_read_platform then coalesce(j.platform_created_by, j.created_by) else j.created_by end
             , j.correlation_id
             , fr.total_items
        from filtered_rows fr
        inner join journal j on fr.journal_id = j.journal_id and j.created_at = fr.journal_created_at
        left join const.event_code ec on ec.event_id = j.event_id
        order by j.created_at desc;
end;
$$;

create or replace function auth.update_user_group(_updated_by text, _user_id bigint, _correlation_id text, _user_group_id integer, _title text, _is_assignable boolean, _is_active boolean, _is_external boolean, _tenant_id integer DEFAULT 1)
    returns TABLE(__user_group_id integer)
    rows 1
    language plpgsql
as
$$
begin
	perform
		auth.has_permission(_user_id, _correlation_id, 'groups.update_group', _tenant_id);

	perform unsecure.validate_user_group_access(_user_id, _correlation_id, _user_group_id, _tenant_id);

	return query
		update auth.user_group
			set updated_by = _updated_by
				, updated_at = now()
				, title = _title
				, is_assignable = _is_assignable
				, is_active = _is_active
				, is_external = _is_external
			where tenant_id = _tenant_id
				and user_group_id = _user_group_id
			returning user_group_id;

	perform public.create_journal_message_for_entity(_updated_by, _user_id, _correlation_id
			, 13002  -- group_updated
			, 'group', _user_group_id
			, jsonb_build_object('group_title', _title
				, 'is_assignable', _is_assignable, 'is_active', _is_active, 'is_external', _is_external)
			, _tenant_id);
end;
$$;

create or replace function auth.delete_user_group(_deleted_by text, _user_id bigint, _correlation_id text, _user_group_id integer, _tenant_id integer DEFAULT 1)
    returns TABLE(__user_group_id integer)
    rows 1
    language plpgsql
as
$$
declare
	__is_system bool;
begin

	perform
		auth.has_permission(_user_id, _correlation_id, 'groups.delete_group', _tenant_id);

	perform unsecure.validate_user_group_access(_user_id, _correlation_id, _user_group_id, _tenant_id);

	select is_system, tenant_id
	from auth.user_group ug
	where ug.user_group_id = _user_group_id
	into __is_system;

	if
		__is_system is null then
		perform error.raise_52171(_user_group_id);
	end if;

	if
		__is_system then
		perform error.raise_52271(_user_group_id);
	end if;

	return query
		delete
			from auth.user_group
				where tenant_id = _tenant_id
					and user_group_id = _user_group_id
				returning user_group_id;

	perform public.create_journal_message_for_entity(_deleted_by, _user_id, _correlation_id
			, 13003  -- group_deleted
			, 'group', _user_group_id
			, jsonb_build_object('group_title', _user_group_id::text)
			, _tenant_id);
end;
$$;

create or replace function auth.enable_user_group(_updated_by text, _user_id bigint, _correlation_id text, _user_group_id integer, _tenant_id integer DEFAULT 1)
    returns TABLE(__user_group_id integer, __is_active boolean, __is_assignable boolean, __updated_at timestamp with time zone, __updated_by text)
    rows 1
    language plpgsql
as
$$
begin
	perform
		auth.has_permission(_user_id, _correlation_id, 'groups.update_group', _tenant_id);

	perform unsecure.validate_user_group_access(_user_id, _correlation_id, _user_group_id, _tenant_id);

	return query
		update auth.user_group
			set updated_by = _updated_by
				, updated_at = now()
				, is_active = true
			where tenant_id = _tenant_id
				and user_group_id = _user_group_id
			returning user_group_id
				, is_active
				, is_assignable
				, updated_at
				, updated_by;

	perform public.create_journal_message_for_entity(_updated_by, _user_id, _correlation_id
			, 13002  -- group_updated (enabled)
			, 'group', _user_group_id
			, jsonb_build_object('group_title', _user_group_id::text, 'action', 'enabled')
			, _tenant_id);
end;
$$;

create or replace function auth.disable_user_group(_updated_by text, _user_id bigint, _correlation_id text, _user_group_id integer, _tenant_id integer DEFAULT 1)
    returns TABLE(__user_group_id integer, __is_active boolean, __is_assignable boolean, __updated_at timestamp with time zone, __updated_by text)
    rows 1
    language plpgsql
as
$$
begin
	perform
		auth.has_permission(_user_id, _correlation_id, 'groups.update_group', _tenant_id);

	perform unsecure.validate_user_group_access(_user_id, _correlation_id, _user_group_id, _tenant_id);

	return query
		update auth.user_group
			set updated_by = _updated_by
				, updated_at = now()
				, is_active = false
			where tenant_id = _tenant_id
				and user_group_id = _user_group_id
			returning user_group_id
				, is_active
				, is_assignable
				, updated_at
				, updated_by;

	perform public.create_journal_message_for_entity(_updated_by, _user_id, _correlation_id
			, 13002  -- group_updated (disabled)
			, 'group', _user_group_id
			, jsonb_build_object('group_title', _user_group_id::text, 'action', 'disabled')
			, _tenant_id);
end;
$$;

create or replace function auth.lock_user_group(_updated_by text, _user_id bigint, _correlation_id text, _user_group_id integer, _tenant_id integer DEFAULT 1)
    returns TABLE(__user_group_id integer, __is_active boolean, __is_assignable boolean, __updated_at timestamp with time zone, __updated_by text)
    rows 1
    language plpgsql
as
$$
begin
	perform
		auth.has_permission(_user_id, _correlation_id, 'groups.lock_group', _tenant_id);

	perform unsecure.validate_user_group_access(_user_id, _correlation_id, _user_group_id, _tenant_id);

	return query
		update auth.user_group
			set updated_by = _updated_by
				, updated_at = now()
				, is_assignable = false
			where tenant_id = _tenant_id
				and user_group_id = _user_group_id
			returning user_group_id
				, is_active
				, is_assignable
				, updated_at
				, updated_by;

	perform public.create_journal_message_for_entity(_updated_by, _user_id, _correlation_id
			, 13002  -- group_updated (locked)
			, 'group', _user_group_id
			, jsonb_build_object('group_title', _user_group_id::text, 'action', 'locked')
			, _tenant_id);
end;
$$;

create or replace function auth.unlock_user_group(_updated_by text, _user_id bigint, _correlation_id text, _user_group_id integer, _tenant_id integer DEFAULT 1)
    returns TABLE(__user_group_id integer, __is_active boolean, __is_assignable boolean, __updated_at timestamp with time zone, __updated_by text)
    rows 1
    language plpgsql
as
$$
begin
	perform
		auth.has_permission(_user_id, _correlation_id, 'groups.update_group', _tenant_id);

	perform unsecure.validate_user_group_access(_user_id, _correlation_id, _user_group_id, _tenant_id);

	return query
		update auth.user_group
			set updated_by = _updated_by
				, updated_at = now()
				, is_assignable = true
			where tenant_id = _tenant_id
				and user_group_id = _user_group_id
			returning user_group_id
				, is_active
				, is_assignable
				, updated_at
				, updated_by;

	perform public.create_journal_message_for_entity(_updated_by, _user_id, _correlation_id
			, 13002  -- group_updated (unlocked)
			, 'group', _user_group_id
			, jsonb_build_object('group_title', _user_group_id::text, 'action', 'unlocked')
			, _tenant_id);
end;
$$;

create or replace function auth.set_user_group_as_external(_updated_by text, _user_id bigint, _correlation_id text, _user_group_id integer, _tenant_id integer DEFAULT 1) returns void
    language plpgsql
as
$$
declare
	__user_group_code text;
begin
	perform
		auth.has_permission(_user_id, _correlation_id, 'groups.update_group', _tenant_id);

	perform unsecure.validate_user_group_access(_user_id, _correlation_id, _user_group_id, _tenant_id);

	delete
	from auth.user_group_member ugm
	where ugm.user_group_id = _user_group_id
		and ugm.member_type_code = 'manual';

	update auth.user_group
	set updated_at  = now()
		, updated_by  = _updated_by
		, is_external = true
	where user_group_id = _user_group_id
	returning code
		into __user_group_code;

	perform public.create_journal_message_for_entity(_updated_by, _user_id, _correlation_id
			, 13002  -- group_updated (set as external)
			, 'group', _user_group_id
			, jsonb_build_object('group_title', __user_group_code, 'action', 'set_external')
			, _tenant_id);
end;
$$;

create or replace function auth.set_user_group_as_hybrid(_updated_by text, _user_id bigint, _correlation_id text, _user_group_id integer, _tenant_id integer DEFAULT 1) returns void
    language plpgsql
as
$$
begin
	perform
		auth.has_permission(_user_id, _correlation_id, 'groups.update_group', _tenant_id);

	perform unsecure.validate_user_group_access(_user_id, _correlation_id, _user_group_id, _tenant_id);

	update auth.user_group
	set updated_at  = now()
		, updated_by  = _updated_by
		, is_external = false
	where user_group_id = _user_group_id;

	perform public.create_journal_message_for_entity(_updated_by, _user_id, _correlation_id
			, 13002  -- group_updated (set as hybrid)
			, 'group', _user_group_id
			, jsonb_build_object('group_title', _user_group_id::text, 'action', 'set_hybrid')
			, _tenant_id);
end;
$$;

create or replace function auth.set_user_group_as_internal(_updated_by text, _user_id bigint, _correlation_id text, _user_group_id integer, _tenant_id integer DEFAULT 1) returns void
    language plpgsql
as
$$
declare
	__user_group_code text;
begin
	perform
		auth.has_permission(_user_id, _correlation_id, 'groups.update_group', _tenant_id);

	perform unsecure.validate_user_group_access(_user_id, _correlation_id, _user_group_id, _tenant_id);

	-- Delete all external/sync members (keep manual members intact)
	delete
	from auth.user_group_member ugm
	where ugm.user_group_id = _user_group_id
		and ugm.member_type_code <> 'manual';

	-- Delete all mappings for this group
	delete
	from auth.user_group_mapping ugm
	where ugm.user_group_id = _user_group_id;

	update auth.user_group
	set updated_at  = now()
		, updated_by  = _updated_by
		, is_external = false
		, is_synced   = false
		, create_missing_users_on_sync = false
	where user_group_id = _user_group_id
	returning code
		into __user_group_code;

	perform public.create_journal_message_for_entity(_updated_by, _user_id, _correlation_id
			, 13002  -- group_updated (set as internal)
			, 'group', _user_group_id
			, jsonb_build_object('group_title', __user_group_code, 'action', 'set_internal')
			, _tenant_id);
end;
$$;

create or replace function auth.create_user_group_member(_created_by text, _user_id bigint, _correlation_id text, _user_group_id integer, _target_user_id bigint, _tenant_id integer DEFAULT 1)
    returns TABLE(__user_group_member_id bigint)
    rows 1
    language plpgsql
as
$$
begin
	perform auth.can_manage_user_group(_user_id, _correlation_id, _user_group_id, 'groups.create_member', _tenant_id);

	perform unsecure.validate_user_group_access(_user_id, _correlation_id, _user_group_id, _tenant_id);
	-- D-19: the group's permissions; its owners may add and remove members anyway
	perform unsecure.validate_user_group_permissions_held(_user_id, _correlation_id, _user_group_id, _tenant_id
		, _allows_group_owner := true);

	return query
		select *
		from unsecure.create_user_group_member(_created_by, _user_id, _correlation_id
			, _user_group_id, _target_user_id, _tenant_id);
end;

$$;

create or replace function auth.delete_user_group_member(_deleted_by text, _user_id bigint, _correlation_id text, _user_group_id integer, _target_user_id bigint, _tenant_id integer DEFAULT 1) returns void
    language plpgsql
as
$$
declare
	__user_group_code text;
	__user_upn        text;
begin
	perform auth.can_manage_user_group(_user_id, _correlation_id, _user_group_id, 'groups.delete_member', _tenant_id);

	perform unsecure.validate_user_group_access(_user_id, _correlation_id, _user_group_id, _tenant_id);
	-- D-19: the group's permissions; its owners may add and remove members anyway
	perform unsecure.validate_user_group_permissions_held(_user_id, _correlation_id, _user_group_id, _tenant_id
		, _allows_group_owner := true);

	select code
	from auth.user_group
	where user_group_id = _user_group_id
	into __user_group_code;

	select code
	from auth.user_info
	where user_id = _target_user_id
	into __user_upn;

	if exists(select from auth.user_group_member
		where user_group_id = _user_group_id
			and user_id = _target_user_id
			and member_type_code in ('external', 'synced')) then
		raise exception 'Cannot manually remove externally managed group member (type: %). Remove the mapping or sync source instead.',
			(select member_type_code from auth.user_group_member
				where user_group_id = _user_group_id and user_id = _target_user_id and member_type_code in ('external', 'synced') limit 1)
			using errcode = 'restricted_operation';
	end if;

	delete
	from auth.user_group_member
	where user_group_id = _user_group_id
		and user_id = _target_user_id
		and member_type_code = 'manual';

	perform public.create_journal_message_for_entity(_deleted_by, _user_id, _correlation_id
			, 13011  -- group_member_removed
			, 'group', _user_group_id
			, jsonb_build_object('username', __user_upn, 'group_title', __user_group_code
				, 'target_user_id', _target_user_id)
			, _tenant_id);
end;
$$;

create or replace function auth.create_user_group_rule_mapping(_created_by text, _user_id bigint, _correlation_id text,
                                                               _user_group_id integer, _rule jsonb default null,
                                                               _rule_id integer default null, _tenant_id integer default 1)
    returns table(__user_group_mapping_id integer, __user_group_id integer)
    rows 1
    language plpgsql
as
$$
declare
    __is_active  boolean;
    __is_synced  boolean;
    __mapping_id integer;
    __rule_title text;
begin
    perform auth.has_permission(_user_id, _correlation_id, 'groups.create_mapping', _tenant_id);
    perform unsecure.validate_user_group_access(_user_id, _correlation_id, _user_group_id, _tenant_id);
    -- D-19: a mapping hands out what the group grants
    perform unsecure.validate_user_group_permissions_held(_user_id, _correlation_id, _user_group_id, _tenant_id);

    select ug.is_active, ug.is_synced
    from auth.user_group ug
    where ug.user_group_id = _user_group_id
    into __is_active, __is_synced;

    if not __is_active then
        perform error.raise_52172(_user_group_id);
    end if;

    if __is_synced then
        perform error.raise_33026(_user_group_id);
    end if;

    if (_rule is null) = (_rule_id is null) then
        perform error.raise_40001('a rule mapping takes either a rule or a rule id');
    end if;

    if _rule is not null then
        perform unsecure.validate_rule(_rule);
    else
        perform unsecure.validate_rule_in_tenant(_rule_id, _tenant_id, _allows_global := true);
        select r.title from auth.rule r where r.rule_id = _rule_id into __rule_title;
    end if;

    insert into auth.user_group_mapping (created_by, user_group_id, rule, rule_id)
    values (_created_by, _user_group_id, _rule, _rule_id)
    returning user_group_mapping_id into __mapping_id;

    -- users join at their next login or permission rebuild (within the cache timeout)

    perform public.create_journal_message_for_entity(_created_by, _user_id, _correlation_id
        , 13020  -- group_mapping_created
        , 'group', _user_group_id
        , jsonb_build_object('group_title', _user_group_id::text
            , 'mapping_name', coalesce(__rule_title, 'rule')
            , 'rule_id', _rule_id, 'rule', _rule)
        , _tenant_id);

    return query select __mapping_id, _user_group_id;
end;
$$;

create or replace function auth.ensure_user_group_mapping(_created_by text, _user_id bigint, _correlation_id text, _user_group_id integer, _provider_code text, _mapped_object_id text default null, _mapped_object_name text default null, _mapped_role text default null, _tenant_id integer default 1)
    returns table(__user_group_mapping_id integer, __user_group_id integer, __is_new boolean)
    rows 1
    language plpgsql
as
$$
declare
    __existing_mapping_id int;
    __existing_group_id int;
    __new_mapping_id int;
    __new_group_id int;
begin
    perform auth.has_permission(_user_id, _correlation_id, 'groups.create_mapping', _tenant_id);
    perform unsecure.validate_user_group_access(_user_id, _correlation_id, _user_group_id, _tenant_id);

    select user_group_mapping_id, user_group_id
    from auth.user_group_mapping
    where user_group_id = _user_group_id
      and provider_code = _provider_code
      and coalesce(mapped_object_id, '') = coalesce(lower(_mapped_object_id), '')
      and coalesce(mapped_role, '') = coalesce(lower(_mapped_role), '')
    into __existing_mapping_id, __existing_group_id;

    if __existing_mapping_id is not null then
        return query select __existing_mapping_id, __existing_group_id, false;
        return;
    end if;

    select m.__user_group_mapping_id, m.__user_group_id
    from auth.create_user_group_mapping(_created_by, _user_id, _correlation_id,
        _user_group_id, _provider_code, _mapped_object_id, _mapped_object_name, _mapped_role, _tenant_id) m
    into __new_mapping_id, __new_group_id;

    return query select __new_mapping_id, __new_group_id, true;
end;
$$;

create or replace function auth.create_owner(_created_by text, _user_id bigint, _correlation_id text, _target_user_id bigint, _user_group_id integer DEFAULT NULL::integer, _tenant_id integer DEFAULT 1)
    returns TABLE(__owner_id bigint)
    rows 1
    language plpgsql
as
$$
begin

	-- Verify user is owner or has appropriate permission
	perform unsecure.verify_owner_or_permission(_user_id, _correlation_id, _user_group_id, _tenant_id);

	if _user_group_id is not null then
		perform unsecure.validate_user_group_access(_user_id, _correlation_id, _user_group_id, _tenant_id);
	end if;

	return query
		insert into auth.owner (created_by, tenant_id, user_group_id, user_id)
			values (_created_by, _tenant_id, _user_group_id, _target_user_id)
			returning owner_id;

	perform public.create_journal_message_for_entity(_created_by, _user_id, _correlation_id
			, 11010  -- tenant_user_added
			, 'tenant', _tenant_id
			, jsonb_build_object('username', _target_user_id::text, 'tenant_title', _tenant_id::text
				, 'user_group_id', _user_group_id, 'action', 'owner_added')
			, _tenant_id);
end;
$$;

create or replace function auth.delete_owner(_deleted_by text, _user_id bigint, _correlation_id text, _target_user_id bigint, _user_group_id integer, _tenant_id integer DEFAULT 1) returns void
    language plpgsql
as
$$
begin
	-- Verify user is owner or has appropriate permission
	perform unsecure.verify_owner_or_permission(_user_id, _correlation_id, _user_group_id, _tenant_id);

	if _user_group_id is not null then
		perform unsecure.validate_user_group_access(_user_id, _correlation_id, _user_group_id, _tenant_id);
	end if;

	delete
	from auth.owner
	where user_id = _target_user_id
		and tenant_id = _tenant_id
		and user_group_id is not distinct from _user_group_id;

	perform public.create_journal_message_for_entity(_deleted_by, _user_id, _correlation_id
			, 11011  -- tenant_user_removed
			, 'tenant', _tenant_id
			, jsonb_build_object('username', _target_user_id::text, 'tenant_title', _tenant_id::text
				, 'user_group_id', _user_group_id, 'action', 'owner_removed')
			, _tenant_id);
end;
$$;

create or replace function auth.get_user_group_by_id(_requested_by text, _user_id bigint, _correlation_id text, _user_group_id integer, _tenant_id integer DEFAULT 1)
    returns TABLE(__user_group_id integer, __tenant_id integer, __title text, __code text, __is_system boolean, __is_external boolean, __is_assignable boolean, __is_active boolean)
    language plpgsql
as
$$
begin
	perform
		auth.has_permission(_user_id, _correlation_id, 'groups.get_group', _tenant_id);

	perform unsecure.validate_user_group_access(_user_id, _correlation_id, _user_group_id, _tenant_id, _is_manage := false);

	return query
		select *
		from unsecure.get_user_group_by_id(_requested_by, _user_id, _user_group_id, _tenant_id);
end
$$;

create or replace function auth.get_assigned_group_permissions(_requested_by text, _user_id bigint, _correlation_id text, _user_group_id integer, _tenant_id integer DEFAULT 1)
    returns TABLE(__permissions jsonb, __perm_set_title text, __perm_set_id integer, __perm_set_code text, __assignment_id bigint)
    language plpgsql
as
$$
begin
	perform auth.has_permission(_user_id, _correlation_id, 'groups.get_permissions', _tenant_id);

	perform unsecure.validate_user_group_access(_user_id, _correlation_id, _user_group_id, _tenant_id, _is_manage := false);

	return query select *
							 from unsecure.get_assigned_group_permissions(_requested_by, _user_id, _user_group_id, _tenant_id);
end;
$$;

create or replace function auth.assign_permission(_created_by text, _user_id bigint, _correlation_id text, _user_group_id integer, _target_user_id bigint, _perm_set_code text, _permission_full_code text, _tenant_id integer DEFAULT 1)
    returns table(
        __created_at    timestamptz,
        __created_by    text,
        __assignment_id bigint,
        __tenant_id     integer,
        __user_group_id integer,
        __user_id       bigint,
        __perm_set_id   integer,
        __permission_id integer
    )
    language plpgsql
as
$$
begin
	perform
		auth.has_permission(_user_id, _correlation_id, 'permissions.assign_permission', _tenant_id);
	perform unsecure.validate_platform_group_access(_user_id, _correlation_id, _user_group_id);

	-- D-19: only what the caller holds
	perform unsecure.validate_permissions_held(_user_id, _correlation_id
		, unsecure.get_grant_permission_codes(_perm_set_code, array [_permission_full_code], _tenant_id), _tenant_id);

	return query
		select created_at, created_by, assignment_id, tenant_id, user_group_id, user_id, perm_set_id, permission_id
		from unsecure.assign_permission(_created_by, _user_id, _correlation_id
			, _user_group_id, _target_user_id
			, _perm_set_code
			, _permission_full_code
			, _tenant_id);
end;

$$;

create or replace function auth.unassign_permission(_deleted_by text, _user_id bigint, _correlation_id text, _assignment_id bigint, _tenant_id integer DEFAULT 1)
    returns table(
        __created_at    timestamptz,
        __created_by    text,
        __assignment_id bigint,
        __tenant_id     integer,
        __user_group_id integer,
        __user_id       bigint,
        __perm_set_id   integer,
        __permission_id integer
    )
    language plpgsql
as
$$
begin
	perform
		auth.has_permission(_user_id, _correlation_id, 'permissions.unassign_permission', _tenant_id);
	perform unsecure.validate_platform_group_access(_user_id, _correlation_id
		, (select pa.user_group_id from auth.permission_assignment pa where pa.assignment_id = _assignment_id));

	-- D-19: only what the caller holds (removals included)
	perform unsecure.validate_permissions_held(_user_id, _correlation_id
		, (select unsecure.get_perm_set_permission_codes(array [pa.perm_set_id])
					|| unsecure.get_permission_codes(array [p.full_code::text])
			 from auth.permission_assignment pa
						left join auth.permission p on p.permission_id = pa.permission_id
			 where pa.assignment_id = _assignment_id
				 and pa.tenant_id = _tenant_id)
		, _tenant_id);

	return query
		select created_at, created_by, assignment_id, tenant_id, user_group_id, user_id, perm_set_id, permission_id
		from unsecure.unassign_permission(_deleted_by, _user_id, _correlation_id, _assignment_id, _tenant_id);
end;
$$;

create or replace function auth.create_user_group_mapping(_created_by text, _user_id bigint, _correlation_id text, _user_group_id integer, _provider_code text, _mapped_object_id text DEFAULT NULL::text, _mapped_object_name text DEFAULT NULL::text, _mapped_role text DEFAULT NULL::text, _tenant_id integer DEFAULT 1)
    returns TABLE(__user_group_mapping_id integer, __user_group_id integer)
    rows 1
    language plpgsql
as
$$
declare
	__is_group_active bool;
begin

	if
		_mapped_object_id is null and _mapped_role is null then
		perform error.raise_52174();

	end if;

	perform auth.validate_provider_allows_group_mapping(_provider_code);

	perform
		auth.has_permission(_user_id, _correlation_id, 'groups.create_mapping', _tenant_id);
	perform unsecure.validate_platform_group_access(_user_id, _correlation_id, _user_group_id);

	-- The group must live in _tenant_id and be active
	select ug.is_active
	from auth.user_group ug
	where ug.user_group_id = _user_group_id
		and ug.tenant_id = _tenant_id
	into __is_group_active;

	if
		__is_group_active is null then
		perform error.raise_52171(_user_group_id);
	end if;

	if not __is_group_active then
		perform error.raise_52172(_user_group_id);
	end if;
	-- D-19: a mapping hands out what the group grants
	perform unsecure.validate_user_group_permissions_held(_user_id, _correlation_id, _user_group_id, _tenant_id);

	-- Same key as uq_user_group_mapping
	if exists(select
						from auth.user_group_mapping ugm
						where ugm.user_group_id = _user_group_id
							and ugm.provider_code = _provider_code
							and coalesce(ugm.mapped_object_id, '') = coalesce(lower(_mapped_object_id), '')
							and coalesce(ugm.mapped_role, '') = coalesce(lower(_mapped_role), '')) then
		perform error.raise_33023(_user_group_id, _provider_code, _mapped_object_id, _mapped_role);
	end if;

	return query insert into auth.user_group_mapping (created_by, user_group_id, provider_code, mapped_object_id,
																										mapped_object_name,
																										mapped_role)
		values ( _created_by, _user_group_id, _provider_code, lower(_mapped_object_id), _mapped_object_name
					 , lower(_mapped_role))
		returning user_group_mapping_id, user_group_id;


	with affected_users as (select user_id
													from auth.user_identity uid
													where lower(_mapped_object_id) = any (provider_groups)
														 or lower(_mapped_object_id) = any (provider_roles))
	update auth.user_permission_cache
	set updated_by      = _created_by
		, updated_at      = now()
		, expiration_date = now() - '1 sec':: interval
	where user_id in (select user_id
										from affected_users);


	perform public.create_journal_message_for_entity(_created_by, _user_id, _correlation_id
			, 13020  -- group_mapping_created
			, 'group', _user_group_id
			, jsonb_build_object('group_title', _user_group_id::text
				, 'mapping_name', coalesce(_mapped_object_name, _mapped_object_id, _mapped_role)
				, 'provider_code', _provider_code
				, 'mapped_object_id', _mapped_object_id, 'mapped_role', _mapped_role)
			, _tenant_id);
end;
$$;

create or replace function auth.delete_user_group_mapping(_deleted_by text, _user_id bigint, _correlation_id text, _user_group_mapping_id integer, _tenant_id integer DEFAULT 1) returns void
    language plpgsql
as
$$
declare
	__user_group_id      int;
	__provider_code      text;
	__mapped_object_id   text;
	__mapped_object_name text;
	__mapped_role        text;
begin
	perform
		auth.has_permission(_user_id, _correlation_id, 'groups.delete_mapping', _tenant_id);
	perform unsecure.validate_platform_group_access(_user_id, _correlation_id
		, (select ugm.user_group_id from auth.user_group_mapping ugm where ugm.user_group_mapping_id = _user_group_mapping_id));

	if not exists(select
								from auth.user_group_mapping ugm
										 inner join auth.user_group ug on ug.user_group_id = ugm.user_group_id
								where ugm.user_group_mapping_id = _user_group_mapping_id
									and ug.tenant_id = _tenant_id) then
		perform error.raise_33022(_user_group_mapping_id, _tenant_id);
	end if;
	-- D-19: removing a mapping takes away what the group grants
	perform unsecure.validate_user_group_permissions_held(_user_id, _correlation_id
		, (select ugm.user_group_id from auth.user_group_mapping ugm where ugm.user_group_mapping_id = _user_group_mapping_id)
		, _tenant_id);

	-- expire user_permission_cache for affected users
	with affected_users as (select user_id
													from auth.user_group_member ugm
													where ugm.mapping_id = _user_group_mapping_id)
	update auth.user_permission_cache
	set updated_by      = _deleted_by
		, updated_at      = now()
		, expiration_date = now() - '1 sec':: interval
	where user_id in (select user_id
										from affected_users);

	delete
	from auth.user_group_mapping
	where user_group_mapping_id = _user_group_mapping_id
	returning user_group_id, provider_code, mapped_object_id, mapped_object_name, mapped_role
		into __user_group_id, __provider_code, __mapped_object_id, __mapped_object_name, __mapped_role;


	perform public.create_journal_message_for_entity(_deleted_by, _user_id, _correlation_id
			, 13021  -- group_mapping_deleted
			, 'group', __user_group_id
			, jsonb_build_object('group_title', __user_group_id::text
				, 'mapping_name', coalesce(__mapped_object_name, __mapped_object_id, __mapped_role)
				, 'provider_code', __provider_code
				, 'mapped_object_id', __mapped_object_id, 'mapped_role', __mapped_role)
			, _tenant_id);
end;
$$;

create or replace function auth.get_user_group_members(_requested_by text, _user_id bigint, _correlation_id text, _user_group_id integer, _tenant_id integer DEFAULT 1)
    returns TABLE(__created timestamp with time zone, __created_by text, __member_id bigint, __member_type_code text, __user_id bigint, __user_display_name text, __user_is_system boolean, __user_is_active boolean, __user_is_locked boolean, __mapping_id integer, __mapping_mapped_object_name text, __mapping_provider_code text)
    rows 1
    language plpgsql
as
$$
begin
	perform
		auth.has_permission(_user_id, _correlation_id, 'groups.get_members', _tenant_id);
	perform unsecure.validate_platform_group_access(_user_id, _correlation_id, _user_group_id, _is_manage := false);

	return query
		select *
		from unsecure.get_user_group_members(_requested_by, _user_id
			, _user_group_id, _tenant_id);
end;
$$;

create or replace function auth.get_user_group_mappings(_requested_by text, _user_id bigint, _correlation_id text, _user_group_id integer, _tenant_id integer default 1, _target_tenant_id integer default null)
    returns table(
        __created_at            timestamptz,
        __created_by            text,
        __user_group_mapping_id integer,
        __user_group_id         integer,
        __provider_code         text,
        __mapped_object_id      text,
        __mapped_object_name    text,
        __mapped_role           text,
        __rule_id               integer,
        __rule                  jsonb
    )
    language plpgsql
as
$$
declare
	__effective_tenant_id int;
begin

	__effective_tenant_id := internal.resolve_cross_tenant_access(
		_user_id, _correlation_id, 'groups.get_all_mappings', 'groups.get_mapping', _tenant_id, _target_tenant_id);
	perform unsecure.validate_platform_group_access(_user_id, _correlation_id, _user_group_id, _is_manage := false);

	return query select ugm.created_at, ugm.created_by, ugm.user_group_mapping_id, ugm.user_group_id, ugm.provider_code, ugm.mapped_object_id, ugm.mapped_object_name, ugm.mapped_role
					  , ugm.rule_id, coalesce(ugm.rule, r.rule)
				 from auth.user_group_mapping ugm
					 inner join auth.user_group ug on ugm.user_group_id = ug.user_group_id
					 left join auth.rule r on r.rule_id = ugm.rule_id
				 where ugm.user_group_id = _user_group_id
				   and (__effective_tenant_id is null or ug.tenant_id = __effective_tenant_id);

	-- Read operation - journal message omitted (use journal level 'all' to log reads)
end;
$$;

create or replace function auth.search_user_groups(
    _user_id bigint,
    _correlation_id text default null,
    _search_criteria jsonb default null,
    _page integer default 1,
    _page_size integer default 30,
    _tenant_id integer default 1,
    _target_tenant_id integer default null
)
    returns TABLE(
        __user_group_id integer,
        __title text,
        __code text,
        __is_system boolean,
        __is_external boolean,
        __is_assignable boolean,
        __is_active boolean,
        __member_count bigint,
        __total_items bigint,
        __tenant_id integer,
        __tenant_code text,
        __tenant_title text
    )
    stable
    rows 100
    language plpgsql
    set search_path = public, const, ext, stage, helpers, internal, unsecure, auth, triggers
as
$$
declare
    __search_text text;
    __is_active boolean;
    __is_external boolean;
    __is_system boolean;
    __effective_tenant_id int;
    __can_read_platform bool;
begin
    __effective_tenant_id := internal.resolve_cross_tenant_access(
        _user_id, _correlation_id, 'groups.get_all_groups', 'groups.get_group', _tenant_id, _target_tenant_id);

    __can_read_platform := auth.has_permission(_user_id, _correlation_id, 'platform.read_platform_objects', 1, _throw_err := false);
    __search_text := helpers.normalize_text(_search_criteria ->> 'search_text');
    __is_active := (_search_criteria ->> 'is_active')::boolean;
    __is_external := (_search_criteria ->> 'is_external')::boolean;
    __is_system := (_search_criteria ->> 'is_system')::boolean;

    _page := coalesce(_page, 1);
    _page_size := least(coalesce(_page_size, 30), 100);

    return query
        with filtered_groups as (
            select ug.user_group_id
                 , count(*) over () as total_items
            from auth.user_group ug
            where (__effective_tenant_id is null or ug.tenant_id = __effective_tenant_id)
              and (not ug.is_platform or __can_read_platform)
              and (__is_active is null or ug.is_active = __is_active)
              and (__is_external is null or ug.is_external = __is_external)
              and (__is_system is null or ug.is_system = __is_system)
              and (helpers.is_empty_string(__search_text)
                   or ug.nrm_search_data like '%' || __search_text || '%')
            order by ug.title
            offset ((_page - 1) * _page_size) limit _page_size
        ),
        member_counts as (
            select ugm.user_group_id, count(ugm.member_id) as member_count
            from auth.user_group_member ugm
            where ugm.user_group_id in (select user_group_id from filtered_groups)
            group by ugm.user_group_id
        )
        select ug.user_group_id
             , ug.title
             , ug.code
             , ug.is_system
             , ug.is_external
             , ug.is_assignable
             , ug.is_active
             , coalesce(mc.member_count, 0)
             , fg.total_items
             , t.tenant_id
             , t.code
             , t.title
        from filtered_groups fg
                 inner join auth.user_group ug on fg.user_group_id = ug.user_group_id
                 inner join auth.tenant t on t.tenant_id = ug.tenant_id
                 left join member_counts mc on ug.user_group_id = mc.user_group_id;
end;
$$;

create or replace function auth.get_tenant_groups(_requested_by text, _user_id bigint, _correlation_id text, _tenant_id integer DEFAULT 1, _target_tenant_id integer default null)
    returns TABLE(__user_group_id integer, __group_code text, __group_title text, __is_external boolean, __is_assignable boolean, __is_active boolean, __members_count bigint)
    language plpgsql
as
$$
declare
	__effective_tenant_id int;
	__can_read_platform bool;
begin
	__effective_tenant_id := internal.resolve_cross_tenant_access(
		_user_id, _correlation_id, 'tenants.get_all_groups', 'tenants.get_groups', _tenant_id, _target_tenant_id);

	__can_read_platform := auth.has_permission(_user_id, _correlation_id, 'platform.read_platform_objects', 1, _throw_err := false);
	return query
		select ugs.user_group_id
				 , ugs.group_code
				 , ugs.group_title
				 , ugs.is_external
				 , ugs.is_assignable
				 , ugs.is_active
				 , count(ugs.user_id)
		from auth.user_group_members ugs
		where (__effective_tenant_id is null or ugs.tenant_id = __effective_tenant_id)
			and (__can_read_platform
				or not exists(select from auth.user_group g where g.user_group_id = ugs.user_group_id and g.is_platform))
		group by ugs.user_group_id, ugs.group_title, ugs.group_code, ugs.is_external, ugs.is_assignable, ugs.is_active
		order by ugs.group_title;

	-- Read operation - journal message omitted (use journal level 'all' to log reads)
end;
$$;

create or replace function auth.search_user_group_mappings(
	_user_id bigint,
	_correlation_id text default null,
	_search_criteria jsonb default null,
	_page integer default 1,
	_page_size integer default 30,
	_tenant_id integer default 1,
	_target_tenant_id integer default null
)
	returns table(
		__user_group_mapping_id integer,
		__user_group_id integer,
		__user_group_title text,
		__user_group_code text,
		__provider_code text,
		__mapped_object_id text,
		__mapped_object_name text,
		__mapped_role text,
		__rule_id integer,
		__rule jsonb,
		__total_items bigint
	)
	stable
	rows 100
	language plpgsql
	set search_path = public, const, ext, stage, helpers, internal, unsecure, auth, triggers
as
$$
declare
	__search_text text;
	__provider_code text;
	__mapped_object_id text;
	__mapped_role text;
	__effective_tenant_id int;
	__can_read_platform bool;
begin
	__effective_tenant_id := internal.resolve_cross_tenant_access(
		_user_id, _correlation_id, 'groups.get_all_mappings', 'groups.get_mapping', _tenant_id, _target_tenant_id);

	__can_read_platform := auth.has_permission(_user_id, _correlation_id, 'platform.read_platform_objects', 1, _throw_err := false);
	__search_text := helpers.normalize_text(_search_criteria ->> 'search_text');
	__provider_code := _search_criteria ->> 'provider_code';
	__mapped_object_id := _search_criteria ->> 'mapped_object_id';
	__mapped_role := _search_criteria ->> 'mapped_role';

	_page := coalesce(_page, 1);
	_page_size := least(coalesce(_page_size, 30), 100);

	return query
		with filtered_mappings as (
			select ugm.user_group_mapping_id
				 , count(*) over () as total_items
			from auth.user_group_mapping ugm
				inner join auth.user_group ug on ugm.user_group_id = ug.user_group_id
			where (__effective_tenant_id is null or ug.tenant_id = __effective_tenant_id)
			  and (not ug.is_platform or __can_read_platform)
			  and (__provider_code is null or ugm.provider_code = __provider_code)
			  and (__mapped_object_id is null or ugm.mapped_object_id = __mapped_object_id)
			  and (__mapped_role is null or ugm.mapped_role = __mapped_role)
			  and (helpers.is_empty_string(__search_text)
				   or ugm.mapped_object_id ilike '%' || __search_text || '%'
				   or ugm.mapped_object_name ilike '%' || __search_text || '%'
				   or ugm.mapped_role ilike '%' || __search_text || '%'
				   or ug.title ilike '%' || __search_text || '%')
			order by ug.title, ugm.provider_code, ugm.mapped_object_name
			offset ((_page - 1) * _page_size) limit _page_size
		)
		select ugm.user_group_mapping_id
			 , ugm.user_group_id
			 , ug.title
			 , ug.code
			 , ugm.provider_code
			 , ugm.mapped_object_id
			 , ugm.mapped_object_name
			 , ugm.mapped_role
			 , ugm.rule_id
			 , coalesce(ugm.rule, r.rule)
			 , fm.total_items
		from filtered_mappings fm
			inner join auth.user_group_mapping ugm on fm.user_group_mapping_id = ugm.user_group_mapping_id
			inner join auth.user_group ug on ugm.user_group_id = ug.user_group_id
			left join auth.rule r on r.rule_id = ugm.rule_id;
end;
$$;


select *
from public.stop_version_update('2.23', _component := 'postgresql_permissionmodel');
