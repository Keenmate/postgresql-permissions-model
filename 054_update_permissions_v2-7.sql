/*
 * PostgreSQL Permissions Model — update v2.7
 * ==========================================
 *
 * Disabled and deleted state removes access (audit decision D-06, RBAC part).
 * Switching something off now counts for nothing at the moment of the check,
 * not only after the cache expires. No data is deleted; switching it back on
 * restores access.
 *
 *  - Disabled groups granted permissions: the cache rebuild read the view
 *    auth.user_group_members, which includes inactive groups, so the rebuild
 *    that followed a group disable re-granted everything. The rebuild now skips
 *    inactive groups.
 *  - Soft-deleted tenants regained permissions: soft delete cleared the cache,
 *    the rebuild did not check tenant.deleted_at. The rebuild skips soft-deleted
 *    tenants, and auth.has_permissions denies inside a soft-deleted tenant,
 *    owners included.
 *  - The owner shortcut in auth.has_permissions ran before any state check, so a
 *    disabled or locked tenant owner passed every check. User state is now
 *    checked first, on every call (one primary-key lookup), so a missed cache
 *    invalidation can no longer grant access.
 *  - Mapped (external / synced) memberships count only while the provider is
 *    active and the user's identity at that provider is not disabled. Identity
 *    enable/disable now invalidates the user's cache (new trigger); provider
 *    re-enable does too, not only disable.
 *  - _throw_err := false returned nothing but raised 33003 / 33004 / 33001 for a
 *    disabled, locked or unknown user; it now returns false.
 *  - Group permission assignments only count in the group's own tenant (they are
 *    written there since v2.1; older mismatched rows produced stray cache rows).
 */

set search_path = public, const, ext, stage, helpers, internal, unsecure, auth, triggers;

select *
from public.start_version_update('2.7', 'Disabled and deleted state removes access',
                                 _component := 'postgresql_permissionmodel',
                                 _description := 'Permission rebuild skips inactive groups, soft-deleted tenants and mapped memberships of inactive providers/identities; has_permissions checks user and tenant state before the owner shortcut and the cache; _throw_err false never raises.');


/***
 *    ███████╗██╗   ██╗███╗   ██╗ ██████╗████████╗██╗ ██████╗ ███╗   ██╗███████╗
 *    ██╔════╝██║   ██║████╗  ██║██╔════╝╚══██╔══╝██║██╔═══██╗████╗  ██║██╔════╝
 *    █████╗  ██║   ██║██╔██╗ ██║██║        ██║   ██║██║   ██║██╔██╗ ██║███████╗
 *    ██╔══╝  ██║   ██║██║╚██╗██║██║        ██║   ██║██║   ██║██║╚██╗██║╚════██║
 *    ██║     ╚██████╔╝██║ ╚████║╚██████╗   ██║   ██║╚██████╔╝██║ ╚████║███████║
 *    ╚═╝      ╚═════╝ ╚═╝  ╚═══╝ ╚═════╝   ╚═╝   ╚═╝ ╚═════╝ ╚═╝  ╚═══╝╚══════╝
 *
 */

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

    -- nobody holds permissions inside a soft-deleted tenant (owners included)
    if exists(select from auth.tenant t where t.tenant_id = _tenant_id and t.deleted_at is not null) then
        __perms := array []::text[];
    else
        -- NOT REALLY SAFE FOR SOME INTERNAL/SYSTEM PERMISSIONS (see audit decision D-05)
        if (auth.is_owner(_target_user_id, _correlation_id, null, _tenant_id))
        then
            return true;
        end if;

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

create or replace function triggers.cache_provider_status_change() returns trigger
    language plpgsql
as
$$
declare
    __affected_user_ids bigint[];
begin
    if OLD.is_active is distinct from NEW.is_active then
        select array_agg(distinct ui.user_id)
        from auth.user_identity ui
        where ui.provider_code = NEW.code
        into __affected_user_ids;

        if __affected_user_ids is not null then
            perform unsecure.invalidate_users_permission_cache('trigger', __affected_user_ids, null);
        end if;
    end if;

    return NEW;
end;
$$;

-- ---------------------------------------------------------------------------
-- Identity enable / disable changes which mapped memberships count: expire the
-- user's permission cache (all tenants).
-- ---------------------------------------------------------------------------
create or replace function triggers.cache_user_identity_status_change() returns trigger
    language plpgsql
as
$$
begin
    if OLD.is_active is distinct from NEW.is_active then
        perform unsecure.invalidate_users_permission_cache('trigger', array [NEW.user_id], null);
    end if;
    return NEW;
end;
$$;

drop trigger if exists trg_cache_user_identity_status on auth.user_identity;
create trigger trg_cache_user_identity_status
    after update
    on auth.user_identity
    for each row
execute function triggers.cache_user_identity_status_change();


select *
from public.stop_version_update('2.7', _component := 'postgresql_permissionmodel');
