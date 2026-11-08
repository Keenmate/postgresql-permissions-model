/*
 * PostgreSQL Permissions Model — update v2.12
 * ===========================================
 *
 * Ownership is a perm set, not a bypass (audit decision D-05, option b).
 *
 * A tenant owner works like a SharePoint site collection owner: a super admin
 * of their own tenant - every resource, every standard operation, configuring
 * the tenant - and nothing in other tenants, nothing global.
 *
 *  - auth.has_permissions returned true for a tenant-wide owner for ANY
 *    permission code, including global, tenant-1-only ones (create tenants,
 *    providers, the permission tree, global user state). The shortcut is gone.
 *    Owners now hold their tenant's 'tenant_owner' perm set, derived from the
 *    owner row in the permission rebuild: cached, visible in the cache like any
 *    grant, and removed at once when the owner row goes (new trigger).
 *  - tenant_owner holds the run-own-tenant permissions (tenants, groups,
 *    assignments and perm sets, API keys, invitations, MFA policies, resource
 *    grants, user reads, journal). It now exists in every tenant;
 *    create_tenant copies it like tenant_admin and tenant_member.
 *  - can_manage_user_group: no tenant-owner shortcut. Members manage each
 *    other when the group allows it, owners of the group manage its members,
 *    everybody else needs the permission. A permission holder may now manage
 *    an owned group too (it used to get 52401).
 *  - verify_owner_or_permission: appointing owners needs
 *    tenants.assign_owner / assign_group_owner. Tenant owners hold them through
 *    tenant_owner; group owners may only manage members of their group.
 *  - Resource access keeps the owner bypass (an owner sees every resource of
 *    their tenant), but only for an active, unlocked owner of a live tenant.
 *    A disabled or locked owner, or the owner of a soft-deleted tenant, saw
 *    every resource.
 *  - create_tenant inserts the owner row itself instead of calling
 *    auth.create_owner (auth -> auth).
 */

set search_path = public, const, ext, stage, helpers, internal, unsecure, auth, triggers;

select *
from public.start_version_update('2.12', 'Ownership is a perm set, not a bypass',
                                 _component := 'postgresql_permissionmodel',
                                 _description := 'Tenant owners hold their tenant''s tenant_owner perm set (derived from the owner row, cached) instead of passing every permission check; group owners only manage members of their group; resource owner bypass only for an active owner of a live tenant.');


/***
 *    ███████╗██╗   ██╗███╗   ██╗ ██████╗████████╗██╗ ██████╗ ███╗   ██╗███████╗
 *    ██╔════╝██║   ██║████╗  ██║██╔════╝╚══██╔══╝██║██╔═══██╗████╗  ██║██╔════╝
 *    █████╗  ██║   ██║██╔██╗ ██║██║        ██║   ██║██║   ██║██╔██╗ ██║███████╗
 *    ██╔══╝  ██║   ██║██║╚██╗██║██║        ██║   ██║██║   ██║██║╚██╗██║╚════██║
 *    ██║     ╚██████╔╝██║ ╚████║╚██████╗   ██║   ██║╚██████╔╝██║  ██║███████║
 *    ╚═╝      ╚═════╝ ╚═╝  ╚═══╝ ╚═════╝   ╚═╝   ╚═╝ ╚═════╝ ╚═╝  ╚═══╝╚══════╝
 *
 */

-- True when _user_id is a tenant-wide owner of _tenant_id, is active and not
-- locked, and the tenant is not soft-deleted. Never raises.
create or replace function unsecure.is_active_tenant_owner(_user_id bigint, _tenant_id integer) returns boolean
    stable
    language sql
as
$$
select exists(select
              from auth.owner o
                       inner join auth.user_info ui on ui.user_id = o.user_id
                       inner join auth.tenant t on t.tenant_id = o.tenant_id
              where o.user_id = _user_id
                and o.tenant_id = _tenant_id
                and o.user_group_id is null
                and ui.is_active
                and not ui.is_locked
                and t.deleted_at is null);
$$;

-- ----------------------------------------------------------------------------
-- Permission check and rebuild: owners hold the tenant_owner perm set
-- ----------------------------------------------------------------------------

create or replace function auth.has_permissions(_target_user_id bigint, _correlation_id text, _permission_full_codes text[], _tenant_id integer DEFAULT 1, _throw_err boolean DEFAULT true) returns boolean
    stable
    language plpgsql
as
$$
declare
    __perms                   text[];
    __expiration_date         timestamptz;
    __last_used_provider_code text;
    __is_active               boolean;
    __is_locked               boolean;
begin

    if (_target_user_id = 1)
    then
        return true;
    end if;

    -- User and tenant state are checked on every call, before the owner shortcut
    -- and the cache, so a missed cache invalidation can never grant access.
    select ui.is_active, ui.is_locked, ui.last_used_provider_code
    from auth.user_info ui
    where ui.user_id = _target_user_id
    into __is_active, __is_locked, __last_used_provider_code;

    if __is_active is null then
        if _throw_err then
            perform error.raise_52103(_target_user_id);
        end if;
        return false;
    end if;

    if not __is_active then
        if _throw_err then
            perform error.raise_33003(_target_user_id);
        end if;
        return false;
    end if;

    if __is_locked then
        if _throw_err then
            perform error.raise_33004(_target_user_id);
        end if;
        return false;
    end if;

    -- nobody holds permissions without a tenant or inside a soft-deleted tenant (owners included);
    -- a null tenant used to grant whatever the user held in any tenant
    if _tenant_id is null
        or exists(select from auth.tenant t where t.tenant_id = _tenant_id and t.deleted_at is not null) then
        __perms := array []::text[];
    else
        -- owners hold their tenant's tenant_owner perm set through the cache (D-05)
        select permissions
             , expiration_date
        from auth.user_permission_cache upc
        where upc.tenant_id = _tenant_id
          and user_id = _target_user_id
        into __perms, __expiration_date;

        if __expiration_date is null or __expiration_date <= now()
        then
            perform unsecure.recalculate_user_groups('permission_check'
                , _target_user_id
                , __last_used_provider_code
                );

            select __permissions
            from unsecure.recalculate_user_permissions('permission_check', _target_user_id, _tenant_id)
            into __perms;
        end if;
    end if;

    if exists(
            select
            from unnest(__perms) p
                     inner join unnest(_permission_full_codes) rp on p = rp)
    then
        return true;
    end if;

    if (_throw_err)
    then
        perform public.create_journal_message_for_entity('system', _target_user_id, _correlation_id
            , 32001  -- err_no_permission
            , 'perm', _target_user_id
            , jsonb_build_object('username', _target_user_id::text
                , 'permission_codes', array_to_string(_permission_full_codes, '; '))
            , _tenant_id);

        perform
            internal.throw_no_permission(_target_user_id, _permission_full_codes, _tenant_id);
    end if;

    return false;
end ;
$$;

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
              and t.deleted_at is null
              and (ugm.mapping_id is null
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
end;
$$;

-- ----------------------------------------------------------------------------
-- Group management and owner appointment without owner shortcuts
-- ----------------------------------------------------------------------------

create or replace function auth.can_manage_user_group(_user_id bigint, _correlation_id text, _user_group_id integer, _permission_full_code text, _tenant_id integer DEFAULT 1) returns boolean
    language plpgsql
as
$$
declare
	__can_members_manage_others bool;
begin
	select ug.can_members_manage_others
	from auth.user_group ug
	where ug.user_group_id = _user_group_id
	into __can_members_manage_others;

	-- members may manage each other when the group allows it
	if __can_members_manage_others and _user_group_id = any (unsecure.get_cached_group_ids(_user_id, _tenant_id)) then
		return true;
	end if;

	-- owners of this group manage its members (D-05: that is all a group owner may do)
	if exists(select
	          from auth.owner o
	          where o.user_id = _user_id
	            and o.tenant_id = _tenant_id
	            and o.user_group_id = _user_group_id) then
		return true;
	end if;

	-- everybody else needs the permission; tenant owners hold it through tenant_owner
	perform auth.has_permission(_user_id, _correlation_id, _permission_full_code, _tenant_id);

	return true;
end;
$$;

create or replace function unsecure.verify_owner_or_permission(_user_id bigint, _correlation_id text, _user_group_id integer, _tenant_id integer DEFAULT 1) returns void
    language plpgsql
as
$$
begin
    -- D-05: no owner shortcut. Tenant owners hold tenants.assign_owner / assign_group_owner
    -- through the tenant_owner perm set; group owners may not appoint owners.
    if _user_group_id is not null then
        perform auth.has_permission(_user_id, _correlation_id
            , 'tenants.assign_group_owner', _tenant_id);
    else
        perform auth.has_permission(_user_id, _correlation_id
            , 'tenants.assign_owner', _tenant_id);
    end if;
end;
$$;

-- ----------------------------------------------------------------------------
-- Resource access: owner bypass only for an active owner of a live tenant
-- ----------------------------------------------------------------------------

create or replace function auth.has_resource_access(
    _user_id        bigint,
    _correlation_id text,
    _resource_type  text,
    _resource_id    jsonb   default '{}'::jsonb,
    _required_flag  text    default 'read',
    _tenant_id      integer default 1,
    _throw_err      boolean default true,
    _resource_path  text    default null
) returns boolean
    language plpgsql
as
$$
declare
    __cached_group_ids integer[];
    __root_type        text;
    __ancestor         record;
    __ancestor_key     jsonb;
    __resource_path_lt ext.ltree;
begin
    perform unsecure.validate_resource_identifier(_resource_id, _resource_path);

    if _user_id = 1 then
        return true;
    end if;

    if unsecure.is_active_tenant_owner(_user_id, _tenant_id) then
        return true;
    end if;

    __cached_group_ids := unsecure.get_cached_group_ids(_user_id, _tenant_id);
    __root_type        := split_part(_resource_type, '.', 1);
    _resource_id      := coalesce(_resource_id, '{}'::jsonb);
    __resource_path_lt := ext.text2ltree(_resource_path);

    for __ancestor in
        select rt.code, rt.key_schema
        from const.resource_type rt
        where rt.path @> (select path from const.resource_type where code = _resource_type)
          and rt.is_active = true
        order by ext.nlevel(rt.path) desc
    loop
        -- Build the id-component lookup key for this ancestor
        if __ancestor.key_schema is not null and __ancestor.key_schema <> '{}'::jsonb then
            select coalesce(jsonb_object_agg(k, _resource_id->k), '{}'::jsonb)
            from jsonb_object_keys(__ancestor.key_schema) as k
            where _resource_id ? k
            into __ancestor_key;
        else
            __ancestor_key := _resource_id;
        end if;

        __ancestor_key := coalesce(__ancestor_key, '{}'::jsonb);

        -- (a) User-level DENY
        if exists (
            select 1 from auth.resource_access ra
            where ra.root_type = __root_type
              and ra.resource_type = __ancestor.code
              and ra.tenant_id = _tenant_id
              and (ra.resource_path is null
                   or (__resource_path_lt is not null and __resource_path_lt <@ ra.resource_path))
              and (ra.resource_id = '{}'::jsonb or ra.resource_id = __ancestor_key)
              and ra.user_id = _user_id
              and ra.access_flag = _required_flag
              and ra.is_deny = true
        ) then
            if _throw_err then
                perform error.raise_35001(_user_id, _resource_type, _resource_id, _tenant_id);
            end if;
            return false;
        end if;

        -- (b) User-level GRANT
        if exists (
            select 1 from auth.resource_access ra
            where ra.root_type = __root_type
              and ra.resource_type = __ancestor.code
              and ra.tenant_id = _tenant_id
              and (ra.resource_path is null
                   or (__resource_path_lt is not null and __resource_path_lt <@ ra.resource_path))
              and (ra.resource_id = '{}'::jsonb or ra.resource_id = __ancestor_key)
              and ra.user_id = _user_id
              and ra.access_flag = _required_flag
              and ra.is_deny = false
        ) then
            return true;
        end if;

        -- (c) User role GRANT
        if exists (
            select 1 from auth.resource_role_assignment rra
            inner join const.resource_role_flag rrf
                on rrf.resource_role_code = rra.role_code
            where rra.root_type = __root_type
              and rra.resource_type = __ancestor.code
              and rra.tenant_id = _tenant_id
              and (rra.resource_path is null
                   or (__resource_path_lt is not null and __resource_path_lt <@ rra.resource_path))
              and (rra.resource_id = '{}'::jsonb or rra.resource_id = __ancestor_key)
              and rra.user_id = _user_id
              and rrf.access_flag_code = _required_flag
        ) then
            return true;
        end if;

        -- (d) Group-level GRANT
        if exists (
            select 1 from auth.resource_access ra
            where ra.root_type = __root_type
              and ra.resource_type = __ancestor.code
              and ra.tenant_id = _tenant_id
              and (ra.resource_path is null
                   or (__resource_path_lt is not null and __resource_path_lt <@ ra.resource_path))
              and (ra.resource_id = '{}'::jsonb or ra.resource_id = __ancestor_key)
              and ra.user_group_id = any(__cached_group_ids)
              and ra.access_flag = _required_flag
              and ra.is_deny = false
        ) then
            return true;
        end if;

        -- (e) Group role GRANT
        if exists (
            select 1 from auth.resource_role_assignment rra
            inner join const.resource_role_flag rrf
                on rrf.resource_role_code = rra.role_code
            where rra.root_type = __root_type
              and rra.resource_type = __ancestor.code
              and rra.tenant_id = _tenant_id
              and (rra.resource_path is null
                   or (__resource_path_lt is not null and __resource_path_lt <@ rra.resource_path))
              and (rra.resource_id = '{}'::jsonb or rra.resource_id = __ancestor_key)
              and rra.user_group_id = any(__cached_group_ids)
              and rrf.access_flag_code = _required_flag
        ) then
            return true;
        end if;
    end loop;

    if _throw_err then
        perform error.raise_35001(_user_id, _resource_type, _resource_id, _tenant_id);
    end if;

    return false;
end;
$$;

create or replace function auth.filter_accessible_resources(
    _user_id         bigint,
    _correlation_id  text,
    _resource_type   text,
    _resource_ids    jsonb[] default null,
    _required_flag   text    default 'read',
    _tenant_id       integer default 1,
    _resource_paths  text[]  default null
) returns table(__resource_id jsonb)
    language plpgsql
as
$$
declare
    __cached_group_ids   integer[];
    __root_type          text;
    __ancestor_types     text[];
    __resource_paths_lt  ext.ltree[];
begin
    if _resource_ids is null and _resource_paths is null then
        return;
    end if;

    if _resource_paths is not null then
        select array_agg(ext.text2ltree(p))
        from unnest(_resource_paths) as p
        into __resource_paths_lt;
    end if;

    if _user_id = 1 or unsecure.is_active_tenant_owner(_user_id, _tenant_id) then
        if _resource_ids is not null then
            return query select unnest(_resource_ids);
        end if;
        if _resource_paths is not null then
            return query select jsonb_build_object('path', p) from unnest(_resource_paths) as p;
        end if;
        return;
    end if;

    __cached_group_ids := unsecure.get_cached_group_ids(_user_id, _tenant_id);
    __root_type        := split_part(_resource_type, '.', 1);

    select array_agg(rt.code)
    from const.resource_type rt
    where rt.path @> (select path from const.resource_type where code = _resource_type)
      and rt.is_active = true
    into __ancestor_types;

    -- ID-based filtering (composite-key rows only; path rows are excluded)
    if _resource_ids is not null then
        return query
        select r.id
        from unnest(_resource_ids) as r(id)
        where not exists (
            select 1 from auth.resource_access ra
            where ra.root_type = __root_type
              and ra.resource_type = any(__ancestor_types)
              and ra.tenant_id = _tenant_id
              and ra.resource_path is null
              and ra.resource_id @> r.id
              and ra.user_id = _user_id
              and ra.access_flag = _required_flag
              and ra.is_deny = true
        )
        and (
            exists (
                select 1 from auth.resource_access ra
                where ra.root_type = __root_type
                  and ra.resource_type = any(__ancestor_types)
                  and ra.tenant_id = _tenant_id
                  and ra.resource_path is null
                  and ra.resource_id @> r.id
                  and ra.user_id = _user_id
                  and ra.access_flag = _required_flag
                  and ra.is_deny = false
            )
            or exists (
                select 1 from auth.resource_role_assignment rra
                inner join const.resource_role_flag rrf
                    on rrf.resource_role_code = rra.role_code
                where rra.root_type = __root_type
                  and rra.resource_type = any(__ancestor_types)
                  and rra.tenant_id = _tenant_id
                  and rra.resource_path is null
                  and rra.resource_id @> r.id
                  and rra.user_id = _user_id
                  and rrf.access_flag_code = _required_flag
            )
            or exists (
                select 1 from auth.resource_access ra
                where ra.root_type = __root_type
                  and ra.resource_type = any(__ancestor_types)
                  and ra.tenant_id = _tenant_id
                  and ra.resource_path is null
                  and ra.resource_id @> r.id
                  and ra.user_group_id = any(__cached_group_ids)
                  and ra.access_flag = _required_flag
                  and ra.is_deny = false
            )
            or exists (
                select 1 from auth.resource_role_assignment rra
                inner join const.resource_role_flag rrf
                    on rrf.resource_role_code = rra.role_code
                where rra.root_type = __root_type
                  and rra.resource_type = any(__ancestor_types)
                  and rra.tenant_id = _tenant_id
                  and rra.resource_path is null
                  and rra.resource_id @> r.id
                  and rra.user_group_id = any(__cached_group_ids)
                  and rrf.access_flag_code = _required_flag
            )
        );
    end if;

    -- Path-based filtering (ancestor-walk via <@)
    if __resource_paths_lt is not null then
        return query
        select jsonb_build_object('path', p.path::text)
        from unnest(__resource_paths_lt) as p(path)
        where not exists (
            select 1 from auth.resource_access ra
            where ra.root_type = __root_type
              and ra.resource_type = any(__ancestor_types)
              and ra.tenant_id = _tenant_id
              and ra.resource_path is not null
              and p.path <@ ra.resource_path
              and ra.user_id = _user_id
              and ra.access_flag = _required_flag
              and ra.is_deny = true
        )
        and (
            exists (
                select 1 from auth.resource_access ra
                where ra.root_type = __root_type
                  and ra.resource_type = any(__ancestor_types)
                  and ra.tenant_id = _tenant_id
                  and ra.resource_path is not null
                  and p.path <@ ra.resource_path
                  and ra.user_id = _user_id
                  and ra.access_flag = _required_flag
                  and ra.is_deny = false
            )
            or exists (
                select 1 from auth.resource_role_assignment rra
                inner join const.resource_role_flag rrf
                    on rrf.resource_role_code = rra.role_code
                where rra.root_type = __root_type
                  and rra.resource_type = any(__ancestor_types)
                  and rra.tenant_id = _tenant_id
                  and rra.resource_path is not null
                  and p.path <@ rra.resource_path
                  and rra.user_id = _user_id
                  and rrf.access_flag_code = _required_flag
            )
            or exists (
                select 1 from auth.resource_access ra
                where ra.root_type = __root_type
                  and ra.resource_type = any(__ancestor_types)
                  and ra.tenant_id = _tenant_id
                  and ra.resource_path is not null
                  and p.path <@ ra.resource_path
                  and ra.user_group_id = any(__cached_group_ids)
                  and ra.access_flag = _required_flag
                  and ra.is_deny = false
            )
            or exists (
                select 1 from auth.resource_role_assignment rra
                inner join const.resource_role_flag rrf
                    on rrf.resource_role_code = rra.role_code
                where rra.root_type = __root_type
                  and rra.resource_type = any(__ancestor_types)
                  and rra.tenant_id = _tenant_id
                  and rra.resource_path is not null
                  and p.path <@ rra.resource_path
                  and rra.user_group_id = any(__cached_group_ids)
                  and rrf.access_flag_code = _required_flag
            )
        );
    end if;
end;
$$;

create or replace function auth.get_resource_access_flags(
    _user_id        bigint,
    _correlation_id text,
    _resource_type  text,
    _resource_id    jsonb   default '{}'::jsonb,
    _tenant_id      integer default 1,
    _resource_path  text    default null
) returns table(__access_flag text, __source text)
    language plpgsql
as
$$
declare
    __cached_group_ids integer[];
    __root_type        text;
    __ancestor_types   text[];
    __resource_path_lt ext.ltree;
begin
    perform unsecure.validate_resource_identifier(_resource_id, _resource_path);

    if _user_id = 1 then
        return query
            select raf.code, 'system'::text
            from const.resource_access_flag raf;
        return;
    end if;

    if unsecure.is_active_tenant_owner(_user_id, _tenant_id) then
        return query
            select raf.code, 'owner'::text
            from const.resource_access_flag raf;
        return;
    end if;

    __cached_group_ids := unsecure.get_cached_group_ids(_user_id, _tenant_id);
    __root_type        := split_part(_resource_type, '.', 1);
    _resource_id      := coalesce(_resource_id, '{}'::jsonb);
    __resource_path_lt := ext.text2ltree(_resource_path);

    select array_agg(rt.code)
    from const.resource_type rt
    where rt.path @> (select path from const.resource_type where code = _resource_type)
      and rt.is_active = true
    into __ancestor_types;

    return query
    with matching as (
        select ra.access_flag, ra.is_deny, ra.user_id, ra.user_group_id, null::text as role_code
        from auth.resource_access ra
        where ra.root_type = __root_type
          and ra.resource_type = any(__ancestor_types)
          and ra.tenant_id = _tenant_id
          and (ra.resource_path is null
               or (__resource_path_lt is not null and __resource_path_lt <@ ra.resource_path))
          and (ra.resource_id = '{}'::jsonb or ra.resource_id @> _resource_id)
          and (ra.user_id = _user_id or ra.user_group_id = any(__cached_group_ids))
        union all
        select rrf.access_flag_code, false, rra.user_id, rra.user_group_id, rra.role_code
        from auth.resource_role_assignment rra
        inner join const.resource_role_flag rrf
            on rrf.resource_role_code = rra.role_code
        where rra.root_type = __root_type
          and rra.resource_type = any(__ancestor_types)
          and rra.tenant_id = _tenant_id
          and (rra.resource_path is null
               or (__resource_path_lt is not null and __resource_path_lt <@ rra.resource_path))
          and (rra.resource_id = '{}'::jsonb or rra.resource_id @> _resource_id)
          and (rra.user_id = _user_id or rra.user_group_id = any(__cached_group_ids))
    ),
    denied_flags as (
        select access_flag
        from matching
        where user_id = _user_id and is_deny = true
    ),
    direct_grants as (
        select distinct access_flag, 'direct'::text as source
        from matching
        where user_id = _user_id
          and is_deny = false
          and role_code is null
          and access_flag not in (select access_flag from denied_flags)
    ),
    user_role_grants as (
        select distinct m.access_flag,
               ('role:' || m.role_code)::text as source
        from matching m
        where m.user_id = _user_id
          and m.role_code is not null
          and m.access_flag not in (select access_flag from denied_flags)
          and m.access_flag not in (select access_flag from direct_grants)
    ),
    group_grants as (
        select distinct on (m.access_flag) m.access_flag, ug.title as source
        from matching m
        inner join auth.user_group ug on ug.user_group_id = m.user_group_id
        where m.user_group_id is not null
          and m.is_deny = false
          and m.role_code is null
          and m.access_flag not in (select access_flag from denied_flags)
          and m.access_flag not in (select access_flag from direct_grants)
          and m.access_flag not in (select access_flag from user_role_grants)
        order by m.access_flag, ug.title
    ),
    group_role_grants as (
        select distinct on (m.access_flag) m.access_flag,
               (ug.title || ' (role:' || m.role_code || ')')::text as source
        from matching m
        inner join auth.user_group ug on ug.user_group_id = m.user_group_id
        where m.user_group_id is not null
          and m.role_code is not null
          and m.access_flag not in (select access_flag from denied_flags)
          and m.access_flag not in (select access_flag from direct_grants)
          and m.access_flag not in (select access_flag from user_role_grants)
          and m.access_flag not in (select access_flag from group_grants)
        order by m.access_flag, ug.title
    )
    select * from direct_grants
    union all select * from user_role_grants
    union all select * from group_grants
    union all select * from group_role_grants;
end;
$$;

create or replace function auth.get_resource_access_matrix(
    _user_id        bigint,
    _correlation_id text,
    _resource_type  text,
    _resource_id    jsonb   default '{}'::jsonb,
    _tenant_id      integer default 1,
    _resource_path  text    default null
) returns table(
    __resource_type text,
    __access_flag   text,
    __source        text
)
    language plpgsql
as
$$
declare
    __cached_group_ids integer[];
    __root_type        text;
    __is_owner         boolean;
    __resource_path_lt ext.ltree;
begin
    perform unsecure.validate_resource_identifier(_resource_id, _resource_path);

    -- System user gets all valid flags on all descendant types
    if _user_id = 1 then
        return query
            select rt.code, raf.code, 'system'::text
            from const.resource_type rt
            cross join const.resource_access_flag raf
            where rt.path <@ (select path from const.resource_type where code = _resource_type)
              and rt.is_active = true
              and (not exists (select 1 from const.resource_type_flag rtf where rtf.resource_type_code = rt.code)
                   or exists (select 1 from const.resource_type_flag rtf where rtf.resource_type_code = rt.code and rtf.access_flag_code = raf.code));
        return;
    end if;

    -- Tenant owner gets all valid flags on all descendant types
    __is_owner := unsecure.is_active_tenant_owner(_user_id, _tenant_id);
    if __is_owner then
        return query
            select rt.code, raf.code, 'owner'::text
            from const.resource_type rt
            cross join const.resource_access_flag raf
            where rt.path <@ (select path from const.resource_type where code = _resource_type)
              and rt.is_active = true
              and (not exists (select 1 from const.resource_type_flag rtf where rtf.resource_type_code = rt.code)
                   or exists (select 1 from const.resource_type_flag rtf where rtf.resource_type_code = rt.code and rtf.access_flag_code = raf.code));
        return;
    end if;

    __cached_group_ids := unsecure.get_cached_group_ids(_user_id, _tenant_id);
    __root_type        := split_part(_resource_type, '.', 1);
    _resource_id      := coalesce(_resource_id, '{}'::jsonb);
    __resource_path_lt := ext.text2ltree(_resource_path);

    return query
    with descendant_types as (
        select rt.code, rt.path
        from const.resource_type rt
        where rt.path <@ (select path from const.resource_type where code = _resource_type)
          and rt.is_active = true
    ),
    denied_flags as (
        select ra.resource_type, ra.access_flag
        from auth.resource_access ra
        where ra.root_type = __root_type
          and ra.tenant_id = _tenant_id
          and (ra.resource_path is null
               or (__resource_path_lt is not null and __resource_path_lt <@ ra.resource_path))
          and (ra.resource_id = '{}'::jsonb or ra.resource_id @> _resource_id)
          and ra.user_id = _user_id
          and ra.is_deny = true
          and ra.resource_type in (select dt.code from descendant_types dt)
    ),
    direct_grants as (
        select ra.resource_type, ra.access_flag, 'direct'::text as source
        from auth.resource_access ra
        where ra.root_type = __root_type
          and ra.tenant_id = _tenant_id
          and (ra.resource_path is null
               or (__resource_path_lt is not null and __resource_path_lt <@ ra.resource_path))
          and (ra.resource_id = '{}'::jsonb or ra.resource_id @> _resource_id)
          and ra.user_id = _user_id
          and ra.is_deny = false
          and ra.resource_type in (select dt.code from descendant_types dt)
    ),
    user_role_grants as (
        select rra.resource_type, rrf.access_flag_code as access_flag,
               ('role:' || rra.role_code)::text as source
        from auth.resource_role_assignment rra
        inner join const.resource_role_flag rrf
            on rrf.resource_role_code = rra.role_code
        where rra.root_type = __root_type
          and rra.tenant_id = _tenant_id
          and (rra.resource_path is null
               or (__resource_path_lt is not null and __resource_path_lt <@ rra.resource_path))
          and (rra.resource_id = '{}'::jsonb or rra.resource_id @> _resource_id)
          and rra.user_id = _user_id
          and rra.resource_type in (select dt.code from descendant_types dt)
    ),
    group_grants as (
        select distinct on (ra.resource_type, ra.access_flag)
            ra.resource_type, ra.access_flag, ug.title as source
        from auth.resource_access ra
        inner join auth.user_group ug on ug.user_group_id = ra.user_group_id
        where ra.root_type = __root_type
          and ra.tenant_id = _tenant_id
          and (ra.resource_path is null
               or (__resource_path_lt is not null and __resource_path_lt <@ ra.resource_path))
          and (ra.resource_id = '{}'::jsonb or ra.resource_id @> _resource_id)
          and ra.user_group_id = any(__cached_group_ids)
          and ra.is_deny = false
          and ra.resource_type in (select dt.code from descendant_types dt)
        order by ra.resource_type, ra.access_flag, ug.title
    ),
    group_role_grants as (
        select distinct on (rra.resource_type, rrf.access_flag_code)
               rra.resource_type, rrf.access_flag_code as access_flag,
               (ug.title || ' (role:' || rra.role_code || ')')::text as source
        from auth.resource_role_assignment rra
        inner join const.resource_role_flag rrf
            on rrf.resource_role_code = rra.role_code
        inner join auth.user_group ug on ug.user_group_id = rra.user_group_id
        where rra.root_type = __root_type
          and rra.tenant_id = _tenant_id
          and (rra.resource_path is null
               or (__resource_path_lt is not null and __resource_path_lt <@ rra.resource_path))
          and (rra.resource_id = '{}'::jsonb or rra.resource_id @> _resource_id)
          and rra.user_group_id = any(__cached_group_ids)
          and rra.resource_type in (select dt.code from descendant_types dt)
        order by rra.resource_type, rrf.access_flag_code, ug.title
    ),
    all_grants as (
        -- Priority: direct > user_role > group > group_role
        select dg.resource_type, dg.access_flag, dg.source from direct_grants dg
        union all
        select urg.resource_type, urg.access_flag, urg.source from user_role_grants urg
        where not exists (
            select 1 from direct_grants dg2
            where dg2.resource_type = urg.resource_type and dg2.access_flag = urg.access_flag
        )
        union all
        select gg.resource_type, gg.access_flag, gg.source from group_grants gg
        where not exists (
            select 1 from direct_grants dg3
            where dg3.resource_type = gg.resource_type and dg3.access_flag = gg.access_flag
        )
        and not exists (
            select 1 from user_role_grants urg2
            where urg2.resource_type = gg.resource_type and urg2.access_flag = gg.access_flag
        )
        union all
        select grg.resource_type, grg.access_flag, grg.source from group_role_grants grg
        where not exists (
            select 1 from direct_grants dg4
            where dg4.resource_type = grg.resource_type and dg4.access_flag = grg.access_flag
        )
        and not exists (
            select 1 from user_role_grants urg3
            where urg3.resource_type = grg.resource_type and urg3.access_flag = grg.access_flag
        )
        and not exists (
            select 1 from group_grants gg2
            where gg2.resource_type = grg.resource_type and gg2.access_flag = grg.access_flag
        )
    ),
    explicit_grants as (
        -- Filter out denied flags
        select ag.resource_type, ag.access_flag, ag.source
        from all_grants ag
        where not exists (
            select 1 from denied_flags df
            where df.resource_type = ag.resource_type
              and df.access_flag = ag.access_flag
        )
    ),
    -- Inheritance: parent grant cascades to children (unless denied or explicit)
    inherited_grants as (
        select dt.code as resource_type, eg.access_flag, eg.source
        from explicit_grants eg
        inner join const.resource_type parent_rt on parent_rt.code = eg.resource_type
        inner join descendant_types dt on dt.path <@ parent_rt.path and dt.code <> eg.resource_type
        where not exists (
            select 1 from denied_flags df
            where df.resource_type = dt.code
              and df.access_flag = eg.access_flag
        )
        and not exists (
            select 1 from explicit_grants eg2
            where eg2.resource_type = dt.code
              and eg2.access_flag = eg.access_flag
        )
    )
    select eg.resource_type, eg.access_flag, eg.source from explicit_grants eg
    union all
    select ig.resource_type, ig.access_flag, ig.source from inherited_grants ig;
end;
$$;

-- ----------------------------------------------------------------------------
-- create_tenant copies tenant_owner
-- ----------------------------------------------------------------------------

create or replace function auth.create_tenant(_created_by text, _user_id bigint, _correlation_id text, _title text, _code text DEFAULT NULL::text, _is_removable boolean DEFAULT true, _is_assignable boolean DEFAULT true, _tenant_owner_id bigint DEFAULT NULL::bigint, _tenant_id integer DEFAULT 1)
    returns TABLE(__tenant_id integer, __uuid uuid, __title text, __code text, __is_removable boolean, __is_assignable boolean, __access_type_code text, __is_default boolean)
    rows 1
    language plpgsql
as
$$
declare
	__last_item auth.tenant;
	__tenant_owner_group_id
							int;
	__tenant_member_group_id
							int;
	__code text;
begin
	perform
		auth.has_permission(_user_id, _correlation_id, 'tenants.create_tenant', 1);  -- tenant 1 only

	__code := coalesce(_code, helpers.get_code(_title));

	-- Burn the code in the permanent identity ledger before creating the tenant.
	-- unique(code) makes any previously-used code (live, soft-deleted or purged)
	-- impossible to reuse; wrap the violation in a friendly error.
	begin
		insert into auth.tenant_identity (code, title, created_by)
		values (__code, _title, _created_by);
	exception when unique_violation then
		perform error.raise_34004(__code);
	end;

	insert into auth.tenant (created_by, updated_by, title, code, is_removable, is_assignable)
	values (_created_by, _created_by, _title, __code, _is_removable, _is_assignable)
	returning *
		into __last_item;

	-- Backfill the ledger with the real uuid + tenant_id now the row exists
	update auth.tenant_identity
	   set uuid = __last_item.uuid, original_tenant_id = __last_item.tenant_id
	 where code = __code;

	perform public.create_journal_message_for_entity(_created_by, _user_id, _correlation_id
			, 11001  -- tenant_created
			, 'tenant', __last_item.tenant_id
			, jsonb_build_object('tenant_title', __last_item.title, 'tenant_code', __last_item.code
				, 'is_assignable', _is_assignable, 'is_removable', _is_removable)
			, 1);

	-- Create tenant admins
	select __user_group_id
	from unsecure.create_user_group(_created_by, _user_id, _correlation_id, 'Tenant Admins'
		, true, true, false, true, _tenant_id := __last_item.tenant_id)
	into __tenant_owner_group_id;

	perform
		unsecure.copy_perm_set(_created_by, _user_id, _correlation_id, 'tenant_admin', 1,
													 __last_item.tenant_id::int);
	perform
		unsecure.assign_permission(_created_by, _user_id, _correlation_id
			, __tenant_owner_group_id, null, 'tenant_admin', _tenant_id := __last_item.tenant_id);

	-- Create tenant members
	select __user_group_id
	from unsecure.create_user_group(_created_by, _user_id, _correlation_id, 'Tenant Members'
		, true, true, false, true, _tenant_id := __last_item.tenant_id)
	into __tenant_member_group_id;

	perform
		unsecure.copy_perm_set(_created_by, _user_id, _correlation_id, 'tenant_member', 1,
													 __last_item.tenant_id::int);
	perform
		unsecure.assign_permission(_created_by, _user_id, _correlation_id
			, __tenant_member_group_id, null, 'tenant_member', _tenant_id := __last_item.tenant_id);

	-- Owners hold the tenant's tenant_owner perm set (D-05)
	perform
		unsecure.copy_perm_set(_created_by, _user_id, _correlation_id, 'tenant_owner', 1,
													 __last_item.tenant_id::int);

	if
		(_tenant_owner_id is not null)
	then
		insert into auth.owner (created_by, tenant_id, user_group_id, user_id)
		values (_created_by, __last_item.tenant_id, null, _tenant_owner_id);

		perform public.create_journal_message_for_entity(_created_by, _user_id, _correlation_id
				, 11010  -- tenant_user_added
				, 'tenant', __last_item.tenant_id
				, jsonb_build_object('username', _tenant_owner_id::text, 'tenant_title', __last_item.title
					, 'user_group_id', null, 'action', 'owner_added')
				, __last_item.tenant_id);
	end if;

	return query
		select tenant_id
				 , uuid
				 , title
				 , code
				 , is_removable
				 , is_assignable
				 , access_type_code
				 , is_default
		from auth.tenant
		where tenant_id = __last_item.tenant_id;
end;
$$;


-- ----------------------------------------------------------------------------
-- Owner rows expire the owner's cache in that tenant
-- ----------------------------------------------------------------------------

create or replace function triggers.cache_owner_change() returns trigger
    language plpgsql
as
$$
begin
    if TG_OP in ('UPDATE', 'DELETE') then
        perform unsecure.invalidate_users_permission_cache('trigger', array [OLD.user_id], OLD.tenant_id);
    end if;
    if TG_OP in ('INSERT', 'UPDATE') then
        perform unsecure.invalidate_users_permission_cache('trigger', array [NEW.user_id], NEW.tenant_id);
    end if;
    return null;
end;
$$;

drop trigger if exists trg_auth_owner_cache on auth.owner;
create trigger trg_auth_owner_cache
    after insert or update or delete
    on auth.owner
    for each row
execute function triggers.cache_owner_change();


/***
 *    ██████╗  █████╗ ████████╗ █████╗
 *    ██╔══██╗██╔══██╗╚══██╔══╝██╔══██╗
 *    ██║  ██║███████║   ██║   ███████║
 *    ██║  ██║██╔══██║   ██║   ██╔══██║
 *    ██████╔╝██║  ██║   ██║   ██║  ██║
 *    ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝
 *
 * tenant_owner = run-own-tenant permissions, in every tenant. Tenant 1's set is
 * the template create_tenant copies. The helpers invalidate the cache of every
 * holder, owners included.
 */

do $$
declare
    __perms text[] := array [
        'tenants.get_tenants', 'tenants.read_tenants', 'tenants.get_users', 'tenants.get_groups',
        'tenants.update_tenant', 'tenants.delete_tenant', 'tenants.assign_owner', 'tenants.assign_group_owner',
        'groups.create_group', 'groups.update_group', 'groups.delete_group', 'groups.lock_group',
        'groups.get_group', 'groups.get_groups', 'groups.get_members', 'groups.get_permissions',
        'groups.create_member', 'groups.delete_member',
        'groups.create_mapping', 'groups.delete_mapping', 'groups.get_mapping',
        'permissions.assign_permission', 'permissions.unassign_permission',
        'permissions.create_permission_set', 'permissions.update_permission_set', 'permissions.delete_permission_set',
        'permissions.get_perm_sets', 'permissions.read_perm_sets', 'permissions.read_permissions',
        'api_keys.create_api_key', 'api_keys.delete_api_key', 'api_keys.search', 'api_keys.update_api_key',
        'api_keys.update_api_secret', 'api_keys.update_permissions', 'api_keys.read_outbound_secret',
        'invitations.create_invitation', 'invitations.get_invitations', 'invitations.revoke_invitation',
        'invitations.manage_templates',
        'mfa.mfa_policy.create_mfa_policy', 'mfa.mfa_policy.delete_mfa_policy', 'mfa.mfa_policy.get_mfa_policies',
        'resources.grant_access', 'resources.deny_access', 'resources.revoke_access', 'resources.update_access',
        'resources.get_grants',
        'users.read_users', 'users.read_user_group_memberships', 'users.get_permissions', 'users.get_data',
        'users.get_user_identity', 'users.add_to_default_groups', 'users.read_user_events',
        'journal.read_journal', 'journal.get_payload'
        ];
    __missing text[];
    __ps      record;
    __current text[];
    __t       record;
begin
    select array_agg(c)
    from unnest(__perms) c
    where not exists(select from auth.permission p where p.full_code = c::ext.ltree)
    into __missing;
    if __missing is not null then
        raise exception 'tenant_owner: unknown permissions %', __missing;
    end if;

    -- tenant 1 first: it is the template for the others
    for __ps in
        select perm_set_id, tenant_id
        from auth.perm_set
        where code = 'tenant_owner'
        order by (tenant_id = 1) desc, tenant_id
    loop
        select array_agg(p.full_code::text)
        from auth.perm_set_perm psp
                 inner join auth.permission p on p.permission_id = psp.permission_id
        where psp.perm_set_id = __ps.perm_set_id
        into __current;

        if __current is not null then
            perform unsecure.delete_perm_set_permissions('update_v2.12', 1, null, __ps.perm_set_id
                , __current, __ps.tenant_id);
        end if;

        perform unsecure.create_perm_set_permissions('update_v2.12', 1, null, __ps.perm_set_id
            , __perms, __ps.tenant_id);
    end loop;

    -- every other tenant gets its own copy
    for __t in
        select t.tenant_id
        from auth.tenant t
        where not exists(select from auth.perm_set ps where ps.tenant_id = t.tenant_id and ps.code = 'tenant_owner')
    loop
        perform unsecure.copy_perm_set('update_v2.12', 1, null, 'tenant_owner', 1, __t.tenant_id);
    end loop;

    -- owners had no cache rows of their own (they bypassed the cache)
    update auth.user_permission_cache upc
    set expiration_date = now(), updated_by = 'update_v2.12', updated_at = now()
    where exists(select from auth.owner o where o.user_id = upc.user_id and o.tenant_id = upc.tenant_id);
end;
$$;


select *
from public.stop_version_update('2.12', _component := 'postgresql_permissionmodel');
