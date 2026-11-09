/*
 * PostgreSQL Permissions Model — update v2.17
 * ===========================================
 *
 * Tenant membership is computed (audit decision D-03).
 *
 * auth.tenant_user was written only by the invitation action add_tenant_user,
 * yet search_users filtered on it, while get_tenant_users / get_tenant_members /
 * get_user_available_tenants / update_user_last_selected_tenant used direct
 * group membership. A user with a direct grant, an owner row or a resource
 * grant in a tenant had real access there but did not show up in any of these
 * reads and could not even select the tenant.
 *
 * Membership is not stored any more, it is computed: a user is a member of
 * tenant T when something grants them something in T -
 *
 *  - a membership in an active group of T that grants something (a
 *    permission / perm set assignment, or a resource grant or role) - direct,
 *    or mapped through an active provider and a not-disabled identity, as in
 *    the permission rebuild. A group that grants nothing (a list of
 *    candidates, e.g. potential product owners) does not make its members
 *    tenant members,
 *  - a permission / perm set assigned to them directly in T,
 *  - an owner row in T (tenant or group owner),
 *  - a resource grant (not a deny) or a resource role of an active role in T.
 *
 * The new view auth.tenant_memberships gives that one rule; every read uses it:
 * search_users, get_tenant_users, get_tenant_members (now also lists members
 * without groups), get_user_available_tenants, update_user_last_selected_tenant
 * (which checked the CALLER's membership instead of the target's),
 * notify_tenant_users and the invitation condition user_not_in_tenant.
 *
 * The invitation action add_tenant_user adds the user to the tenant's built-in
 * Tenant Members group (tenant 1 gets one too). auth.tenant_user is dropped;
 * its rows never granted anything. The view is named tenant_memberships so it
 * is not confused with that group (code tenant_members), an ordinary group
 * filled by admins and add_tenant_user, never at login.
 *
 * Tenant error codes 34004-34007 were raised but never registered.
 *
 * get_tenant_members checks tenants.get_users / tenants.get_all_users (like
 * get_tenant_users) instead of tenants.get_tenants / tenants.get_all_tenants.
 */

set search_path = public, const, ext, stage, helpers, internal, unsecure, auth, triggers;

select *
from public.start_version_update('2.17', 'Tenant membership is computed',
                                 _component := 'postgresql_permissionmodel',
                                 _description := 'One computed membership rule (auth.tenant_memberships: group, direct grant, owner, resource grant) for every tenant member read; auth.tenant_user dropped; add_tenant_user adds to Tenant Members.');


-- 34004-34007 were raised but never registered
insert into const.event_code (event_id, code, category_code, is_system, source)
values (34004, 'err_tenant_code_used_before', 'tenant_error', true, 'core')
     , (34005, 'err_tenant_already_deleted', 'tenant_error', true, 'core')
     , (34006, 'err_tenant_not_deleted', 'tenant_error', true, 'core')
     , (34007, 'err_tenant_protected', 'tenant_error', true, 'core')
     , (34008, 'err_tenant_members_group_missing', 'tenant_error', true, 'core')
on conflict do nothing;

insert into const.event_message (event_id, language_code, message_template)
values (34004, 'en', 'Tenant code "{code}" has been used before and cannot be reused')
     , (34005, 'en', 'Tenant (uuid: {tenant_uuid}) is already deleted')
     , (34006, 'en', 'Tenant (uuid: {tenant_uuid}) is not deleted')
     , (34007, 'en', 'Tenant (id: {tenant_id}) is protected and cannot be deleted')
     , (34008, 'en', 'Tenant (id: {tenant_id}) has no Tenant Members group')
on conflict do nothing;

-- 34008: the tenant has no Tenant Members group (invitation action add_tenant_user)
create or replace function error.raise_34008(_tenant_id integer) returns void
    language plpgsql
as
$$
begin
    raise exception 'Tenant (id: %) has no Tenant Members group', _tenant_id
        using errcode = '34008';
end;
$$;


-- Lookups by user (available tenants, search) and by tenant (member lists)
create index if not exists ix_user_group_member_user on auth.user_group_member (user_id);
create index if not exists ix_permission_assignment_user on auth.permission_assignment (user_id) where user_id is not null;
create index if not exists ix_ra_user_tenant on auth.resource_access (user_id, tenant_id) where user_id is not null and not is_deny;
create index if not exists ix_ra_tenant_user on auth.resource_access (tenant_id, user_id) where user_id is not null and not is_deny;
create index if not exists ix_rra_user_tenant on auth.resource_role_assignment (user_id, tenant_id) where user_id is not null;
create index if not exists ix_rra_tenant_user on auth.resource_role_assignment (tenant_id, user_id) where user_id is not null;
create index if not exists ix_ra_group_grant on auth.resource_access (user_group_id) where user_group_id is not null and not is_deny;
create index if not exists ix_rra_group on auth.resource_role_assignment (user_group_id) where user_group_id is not null;


-- tenant_id, user_id -> why the user belongs to the tenant (one row per source,
-- a user can appear several times). Same filters as the permission rebuild.
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
  and (ugm.mapping_id is null
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


create or replace function auth.search_users(
    _user_id bigint,
    _correlation_id text default null,
    _search_criteria jsonb default null,
    _page integer default 1,
    _page_size integer default 30,
    _tenant_id integer default 1,
    _target_tenant_id integer default null
)
    returns TABLE(
        __user_id bigint,
        __code text,
        __uuid text,
        __username text,
        __email text,
        __display_name text,
        __user_type_code text,
        __is_active boolean,
        __is_locked boolean,
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
    __user_type_code text;
    __is_active boolean;
    __is_locked boolean;
    __effective_tenant_id int;
begin
    __effective_tenant_id := internal.resolve_cross_tenant_access(
        _user_id, _correlation_id, 'users.read_all_users', 'users.read_users', _tenant_id, _target_tenant_id);

    __search_text := helpers.normalize_text(_search_criteria ->> 'search_text');
    __user_type_code := _search_criteria ->> 'user_type_code';
    __is_active := (_search_criteria ->> 'is_active')::boolean;
    __is_locked := (_search_criteria ->> 'is_locked')::boolean;

    _page := coalesce(_page, 1);
    _page_size := least(coalesce(_page_size, 30), 100);

    return query
        with filtered_users as (
            select ui.user_id
                 , count(*) over () as total_items
            from auth.user_info ui
            where (__user_type_code is null or ui.user_type_code = __user_type_code)
              and (__is_active is null or ui.is_active = __is_active)
              and (__is_locked is null or ui.is_locked = __is_locked)
              and (helpers.is_empty_string(__search_text)
                   or ui.nrm_search_data like '%' || __search_text || '%')
              and (__effective_tenant_id is null or exists(select 1 from auth.tenant_memberships tm where tm.user_id = ui.user_id and tm.tenant_id = __effective_tenant_id))
            order by ui.display_name
            offset ((_page - 1) * _page_size) limit _page_size
        )
        select ui.user_id
             , ui.code
             , ui.uuid::text
             , ui.username
             , ui.email
             , ui.display_name
             , ui.user_type_code
             , ui.is_active
             , ui.is_locked
             , fu.total_items
        from filtered_users fu
                 inner join auth.user_info ui on fu.user_id = ui.user_id;
end;
$$;


create or replace function auth.get_tenant_users(_requested_by text, _user_id bigint, _correlation_id text, _tenant_id integer DEFAULT 1, _target_tenant_id integer default null)
    returns TABLE(__user_id bigint, __username text, __display_name text, __user_groups text[])
    language plpgsql
as
$$
declare
	__effective_tenant_id int;
begin
	__effective_tenant_id := internal.resolve_cross_tenant_access(
		_user_id, _correlation_id, 'tenants.get_all_users', 'tenants.get_users', _tenant_id, _target_tenant_id);

	-- members by the computed rule (D-03); members without groups get an empty list
	return query
		with members as (
			select distinct tm.user_id
			from auth.tenant_memberships tm
			where __effective_tenant_id is null or tm.tenant_id = __effective_tenant_id)
		select ui.user_id
				 , ui.username
				 , ui.display_name
				 , coalesce(array_agg(distinct jsonb_build_object(variadic
							array ['user_group_id', ugs.user_group_id::text, 'code', ugs.group_code, 'title', ugs.group_title])::text)
						filter (where ugs.user_group_id is not null), '{}')
		from members m
					 inner join auth.user_info ui on ui.user_id = m.user_id
					 left join auth.user_group_members ugs
										 on ugs.user_id = m.user_id
											 and (__effective_tenant_id is null or ugs.tenant_id = __effective_tenant_id)
		group by ui.user_id, ui.username, ui.display_name
		order by ui.display_name;
	-- Read operation - journal message omitted (use journal level 'all' to log reads)
end;
$$;


create or replace function auth.get_tenant_members(_requested_by text, _user_id bigint, _correlation_id text, _tenant_id integer DEFAULT 1, _target_tenant_id integer default null)
    returns TABLE(__user_id bigint, __user_display_name text, __user_code text, __user_uuid text, __user_tenant_groups text)
    language plpgsql
as
$$
declare
	__effective_tenant_id int;
begin
	-- same data as get_tenant_users, same permissions (was tenants.get_tenants / get_all_tenants)
	__effective_tenant_id := internal.resolve_cross_tenant_access(
		_user_id, _correlation_id, 'tenants.get_all_users', 'tenants.get_users', _tenant_id, _target_tenant_id);

	-- members by the computed rule (D-03); members without groups get '[]'
	return query
		with members as (
			select distinct tm.user_id
			from auth.tenant_memberships tm
			where __effective_tenant_id is null or tm.tenant_id = __effective_tenant_id)
		select ui.user_id
				 , ui.display_name
				 , ui.code
				 , ui.uuid::text
				 , coalesce(array_to_json(array_agg(distinct
						jsonb_build_object('user_group_id', ugs.user_group_id, 'group_title', ugs.group_title,
															 'group_code', ugs.group_code))
						filter (where ugs.user_group_id is not null))::text, '[]')
		from members m
					 inner join auth.user_info ui on ui.user_id = m.user_id
					 left join auth.user_group_members ugs
										 on ugs.user_id = m.user_id
											 and (__effective_tenant_id is null or ugs.tenant_id = __effective_tenant_id)
		group by ui.user_id, ui.display_name, ui.code, ui.uuid
		order by ui.display_name;
	-- Read operation - journal message omitted (use journal level 'all' to log reads)
end;
$$;


create or replace function auth.get_user_available_tenants(_user_id bigint, _correlation_id text, _target_user_id bigint, _tenant_id integer DEFAULT 1)
    returns TABLE(__tenant_id integer, __tenant_uuid text, __tenant_code text, __tenant_title text, __tenant_is_default boolean)
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

    -- tenants the user is a member of by the computed rule (D-03)
    return query
        select distinct t.tenant_id
             , t.uuid::text
             , t.code
             , t.title
             , t.is_default
        from auth.tenant_memberships tm
                 inner join auth.tenant t on t.tenant_id = tm.tenant_id
        where tm.user_id = _target_user_id
          and t.deleted_at is null
        order by t.title;
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
      and exists(select from auth.tenant_memberships tm
                 where tm.tenant_id = t.tenant_id
                   and tm.user_id = _target_user_id)
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


create or replace function unsecure.evaluate_invitation_condition(
    _condition_code  text,
    _target_user_id  bigint,
    _tenant_id       integer,
    _payload         jsonb
) returns boolean
    language plpgsql
as
$$
declare
    ___group_id integer;
    ___perm_set_code text;
    ___resource_type text;
    ___resource_id jsonb;
begin
    case _condition_code
        when 'always' then
            return true;

        when 'user_not_in_tenant' then
            if _target_user_id is null then
                return true;  -- user doesn't exist yet, condition met
            end if;
            return not exists(
                select 1 from auth.tenant_memberships
                where tenant_id = _tenant_id and user_id = _target_user_id
            );

        when 'user_not_in_group' then
            if _target_user_id is null then
                return true;
            end if;
            ___group_id := (_payload->>'user_group_id')::integer;
            return not exists(
                select 1 from auth.user_group_member
                where user_group_id = ___group_id and user_id = _target_user_id
            );

        when 'user_has_no_perm_set' then
            if _target_user_id is null then
                return true;
            end if;
            ___perm_set_code := _payload->>'perm_set_code';
            return not exists(
                select 1 from auth.permission_assignment pa
                inner join auth.perm_set ps on ps.perm_set_id = pa.perm_set_id
                where pa.user_id = _target_user_id
                  and pa.tenant_id = _tenant_id
                  and ps.code = ___perm_set_code
            );

        when 'user_has_no_resource_access' then
            if _target_user_id is null then
                return true;
            end if;
            ___resource_type := _payload->>'resource_type';
            ___resource_id := _payload->'resource_id';
            return not exists(
                select 1 from auth.resource_access
                where tenant_id = _tenant_id
                  and resource_type = ___resource_type
                  and resource_id = ___resource_id
                  and user_id = _target_user_id
                  and not is_deny
            );

        else
            -- Unknown condition — default to execute
            return true;
    end case;
end;
$$;


create or replace function unsecure.execute_database_action(
    _updated_by            text,
    _user_id               bigint,
    _correlation_id        text,
    _invitation_action_id  bigint,
    _invitation_id         bigint,
    _target_user_id        bigint,
    _action_type_code      text,
    _payload               jsonb,
    _tenant_id             integer
) returns void
    language plpgsql
as
$$
declare
    ___group_id integer;
    ___perm_set_code text;
    ___permission_full_code text;
    ___resource_type text;
    ___resource_id jsonb;
    ___access_flags text[];
begin
    case _action_type_code
        when 'add_tenant_user' then
            -- membership is computed (D-03): join the tenant's Tenant Members group
            select ug.user_group_id
            from auth.user_group ug
            where ug.tenant_id = _tenant_id
              and ug.code = 'tenant_members'
            into ___group_id;

            if ___group_id is null then
                perform error.raise_34008(_tenant_id);
            end if;

            if not exists(select from auth.user_group_member
                          where user_group_id = ___group_id and user_id = _target_user_id and mapping_id is null) then
                perform unsecure.create_user_group_member(
                    _updated_by, _user_id, _correlation_id,
                    ___group_id, _target_user_id, _tenant_id
                );
            end if;

        when 'add_group_member' then
            ___group_id := (_payload->>'user_group_id')::integer;
            perform unsecure.create_user_group_member(
                _updated_by, _user_id, _correlation_id,
                ___group_id, _target_user_id, _tenant_id
            );

        when 'assign_perm_set' then
            ___perm_set_code := _payload->>'perm_set_code';
            perform unsecure.assign_permission(
                _updated_by, _user_id, _correlation_id,
                null, _target_user_id, ___perm_set_code, null, _tenant_id
            );

        when 'assign_permission' then
            ___permission_full_code := _payload->>'permission_code';
            perform unsecure.assign_permission(
                _updated_by, _user_id, _correlation_id,
                null, _target_user_id, null, ___permission_full_code, _tenant_id
            );

        when 'assign_resource_access' then
            ___resource_type := _payload->>'resource_type';
            ___resource_id := _payload->'resource_id';
            ___access_flags := array(select jsonb_array_elements_text(_payload->'access_flags'));
            if ___access_flags is null or array_length(___access_flags, 1) is null then
                ___access_flags := array['read'];
            end if;
            perform auth.assign_resource_access(
                _updated_by, _user_id, _correlation_id,
                ___resource_type, ___resource_id,
                _target_user_id, null, ___access_flags, _tenant_id
            );

        else
            -- Unknown database action type — treat as no-op
            null;
    end case;
end;
$$;


create or replace function unsecure.delete_tenant(_deleted_by text, _user_id bigint, _correlation_id text, _tenant_id integer)
    returns table(__tenant_id integer, __uuid uuid, __code text)
    language plpgsql
as
$$
declare
    __last_item auth.tenant;
begin
    -- Explicit cleanup in dependency order (no reliance on CASCADE)

    -- Caches (ephemeral, safe to delete)
    delete from auth.user_permission_cache where tenant_id = _tenant_id;
    delete from auth.user_group_id_cache where tenant_id = _tenant_id;

    -- Resource ACL
    delete from auth.resource_role_assignment where tenant_id = _tenant_id;
    delete from auth.resource_access where tenant_id = _tenant_id;

    -- Ownership
    delete from auth.owner where tenant_id = _tenant_id;

    -- Permission assignments (before perm_sets and groups)
    delete from auth.permission_assignment where tenant_id = _tenant_id;

    -- Perm set permissions (before perm_sets)
    delete from auth.perm_set_perm where perm_set_id in (
        select perm_set_id from auth.perm_set where tenant_id = _tenant_id
    );
    delete from auth.perm_set where tenant_id = _tenant_id;

    -- Group members and mappings (before groups)
    delete from auth.user_group_member where user_group_id in (
        select user_group_id from auth.user_group where tenant_id = _tenant_id
    );
    delete from auth.user_group_mapping where user_group_id in (
        select user_group_id from auth.user_group where tenant_id = _tenant_id
    );
    delete from auth.user_group where tenant_id = _tenant_id;

    -- Tenant users

    -- Invitations (if any)
    delete from auth.invitation_action where invitation_id in (
        select invitation_id from auth.invitation where tenant_id = _tenant_id
    );
    delete from auth.invitation where tenant_id = _tenant_id;

    -- MFA policies
    delete from auth.mfa_policy where tenant_id = _tenant_id;

    -- User tenant preferences
    delete from auth.user_tenant_preference where tenant_id = _tenant_id;

    -- Detach journal references (preserve audit history)
    update public.journal set tenant_id = null where tenant_id = _tenant_id;

    -- Stamp the permanent identity ledger as purged. The ledger row stays
    -- forever so the code can never be reused, even after the tenant row is gone.
    update auth.tenant_identity
       set purged_at = now(), purged_by = _deleted_by
     where original_tenant_id = _tenant_id;

    -- Delete the tenant row (all child data was removed above)
    delete from auth.tenant
    where tenant_id = _tenant_id
    returning * into __last_item;

    perform public.create_journal_message_for_entity(_deleted_by, _user_id, _correlation_id
            , 11006  -- tenant_purged
            , 'tenant', __last_item.tenant_id
            , jsonb_build_object('tenant_title', __last_item.title, 'tenant_code', __last_item.code)
            , 1);

    return query
        select __last_item.tenant_id
             , __last_item.uuid
             , __last_item.code;
end;
$$;


drop table auth.tenant_user;


select *
from public.stop_version_update('2.17', _component := 'postgresql_permissionmodel');
