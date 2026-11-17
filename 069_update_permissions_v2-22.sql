/*
 * PostgreSQL Permissions Model — update v2.22
 * ===========================================
 *
 * No privilege escalation (D-19, step 3 of audit/design-d13-tenant-actions.md).
 *
 * Until now a permission like permissions.assign_permission was enough to hand
 * out anything, tenant_admin or full_admin included, to anyone, the caller
 * included. From now on you can't give out or take away what you don't hold:
 * every assignable permission a grant carries (a perm set's permissions, a
 * permission and its descendants, everything a group grants) must be in the
 * caller's own effective permissions in that tenant, groups included. An
 * ancestor covers its descendants. Otherwise 32010 is raised (and journaled).
 *
 * Checked on:
 *  - assign_permission / unassign_permission (users and groups)
 *  - create_perm_set, create_perm_set_permissions, delete_perm_set_permissions,
 *    update_perm_set when it switches is_assignable, ensure_perm_sets
 *  - create_user_group_member / delete_user_group_member (the group's
 *    permissions; the group's owners may add and remove members anyway)
 *  - create_user_group_mapping, create_user_group_rule_mapping,
 *    delete_user_group_mapping, ensure_user_group_mappings (final state)
 *  - update_rule on a tenant rule: the permissions of every group that uses it
 *    (global rules: rules.manage_global_rules in tenant 1 is the authority)
 *  - create_api_key, assign_api_key_permissions, unassign_api_key_permissions
 *  - create_invitation / create_invitation_from_template: the actions
 *    (assign_perm_set, assign_permission, add_group_member, add_tenant_user)
 *    are checked against the inviter when the invitation is created
 *  - create_owner / delete_owner: a tenant owner holds the tenant's
 *    tenant_owner perm set, a group owner adds members to the group, so the
 *    caller must hold those (tenant_admin held tenants.assign_owner and could
 *    make anyone, themselves included, a tenant owner)
 *
 * Exempt: user 1 and active tenant owners of the tenant.
 */

set search_path = public, const, ext, stage, helpers, internal, unsecure, auth, triggers;

select *
from public.start_version_update('2.22', 'No privilege escalation',
                                 _component := 'postgresql_permissionmodel',
                                 _description := 'D-19: you cannot give out or take away permissions, perm sets, group memberships, mappings, rule edits, API key permissions, invitation actions or ownership you do not hold yourself (32010). User 1 and tenant owners are exempt; group owners may add members.');


/***
 *    error codes
 */

insert into const.event_code (event_id, code, category_code, is_system, source)
values (32010, 'err_permission_not_held', 'permission_error', true, 'core')
on conflict do nothing;

insert into const.event_message (event_id, language_code, message_template)
values (32010, 'en', 'User (id: {user_id}) cannot grant or revoke permissions they don''t hold ({permission_codes}) in tenant (id: {tenant_id})')
on conflict do nothing;

-- 32010: the caller would give out or take away permissions they don't hold (D-19)
create or replace function error.raise_32010(_user_id bigint, _permission_codes text[], _tenant_id integer) returns void
    language plpgsql
as
$$
begin
    raise exception 'User (id: %) cannot grant or revoke permissions they don''t hold (%) in tenant (id: %)'
        , _user_id, array_to_string(_permission_codes, '; '), _tenant_id
        using errcode = '32010';
end;
$$;


/***
 *    what a grant carries
 */

-- the assignable permissions the given permissions carry, descendants included
create or replace function unsecure.get_permission_codes(_permission_full_codes text[]) returns text[]
    stable
    language sql
as
$$
select coalesce(array_agg(distinct sp.full_code::text), array []::text[])
from unnest(_permission_full_codes) c
         inner join auth.permission p on p.full_code = c::ext.ltree
         inner join auth.permission sp on sp.node_path operator(ext.<@) p.node_path and sp.is_assignable;
$$;

-- the assignable permissions of the given perm sets, descendants included
create or replace function unsecure.get_perm_set_permission_codes(_perm_set_ids integer[]) returns text[]
    stable
    language sql
as
$$
select coalesce(array_agg(distinct ep.permission_code::text), array []::text[])
from auth.effective_permissions ep
where ep.perm_set_id = any (_perm_set_ids)
  and ep.permission_is_assignable;
$$;

-- what assigning a perm set (by code, in the tenant) and/or permissions carries
create or replace function unsecure.get_grant_permission_codes(_perm_set_code text, _permission_full_codes text[],
                                                               _tenant_id integer) returns text[]
    stable
    language sql
as
$$
select unsecure.get_perm_set_permission_codes(array(select ps.perm_set_id
                                                     from auth.perm_set ps
                                                     where ps.tenant_id = _tenant_id
                                                       and ps.code = _perm_set_code))
           || unsecure.get_permission_codes(_permission_full_codes);
$$;

-- everything a group grants its members
create or replace function unsecure.get_user_group_permission_codes(_user_group_id integer) returns text[]
    stable
    language sql
as
$$
select unsecure.get_perm_set_permission_codes(array(select pa.perm_set_id
                                                     from auth.permission_assignment pa
                                                     where pa.user_group_id = _user_group_id
                                                       and pa.perm_set_id is not null))
           || unsecure.get_permission_codes(array(select p.full_code::text
                                                  from auth.permission_assignment pa
                                                           inner join auth.permission p on p.permission_id = pa.permission_id
                                                  where pa.user_group_id = _user_group_id));
$$;


/***
 *    the check
 */

-- D-19: the caller must hold every given permission in the tenant (user 1 and
-- active tenant owners hold everything); raises and journals 32010 otherwise
create or replace function unsecure.validate_permissions_held(_user_id bigint, _correlation_id text,
                                                              _permission_codes text[], _tenant_id integer) returns void
    language plpgsql
as
$$
declare
    __held    text[];
    __missing text[];
begin
    if _user_id = 1
        or coalesce(cardinality(_permission_codes), 0) = 0
        or unsecure.is_active_tenant_owner(_user_id, _tenant_id) then
        return;
    end if;

    -- the caller passed has_permission in this tenant just before, so the cache is fresh
    select p.__permissions
    from unsecure.recalculate_user_permissions('permission_check', _user_id, _tenant_id) p
    into __held;

    select array_agg(distinct c order by c)
    from unnest(_permission_codes) c
    where c <> all (coalesce(__held, array []::text[]))
    into __missing;

    if __missing is not null then
        perform public.create_journal_message_for_entity('system', _user_id, _correlation_id
            , 32010  -- err_permission_not_held
            , 'perm', _user_id
            , jsonb_build_object('user_id', _user_id, 'tenant_id', _tenant_id
                , 'permission_codes', array_to_string(__missing, '; '))
            , _tenant_id);

        perform error.raise_32010(_user_id, __missing, _tenant_id);
    end if;
end;
$$;

-- D-19 for a group: the caller must hold everything the group grants; with
-- _allows_group_owner the group's owners pass (they may add members anyway)
create or replace function unsecure.validate_user_group_permissions_held(_user_id bigint, _correlation_id text,
                                                                         _user_group_id integer, _tenant_id integer,
                                                                         _allows_group_owner boolean default false) returns void
    language plpgsql
as
$$
begin
    if _allows_group_owner and exists(select
                                      from auth.owner o
                                      where o.user_id = _user_id
                                        and o.tenant_id = _tenant_id
                                        and o.user_group_id = _user_group_id) then
        return;
    end if;

    perform unsecure.validate_permissions_held(_user_id, _correlation_id
        , unsecure.get_user_group_permission_codes(_user_group_id), _tenant_id);
end;
$$;

-- D-19 for invitations: the inviter must hold what the actions will grant
create or replace function unsecure.validate_invitation_permissions_held(_user_id bigint, _correlation_id text,
                                                                         _invitation_id bigint, _tenant_id integer) returns void
    language plpgsql
as
$$
declare
    __action record;
    __codes  text[] := array []::text[];
begin
    for __action in
        select ia.action_type_code, ia.payload
        from auth.invitation_action ia
        where ia.invitation_id = _invitation_id
    loop
        case __action.action_type_code
            when 'assign_perm_set' then
                __codes := __codes || unsecure.get_grant_permission_codes(__action.payload ->> 'perm_set_code', null, _tenant_id);
            when 'assign_permission' then
                __codes := __codes || unsecure.get_permission_codes(array [__action.payload ->> 'permission_code']);
            when 'add_group_member' then
                perform unsecure.validate_user_group_permissions_held(_user_id, _correlation_id
                    , (__action.payload ->> 'user_group_id')::integer, _tenant_id, _allows_group_owner := true);
            when 'add_tenant_user' then
                __codes := __codes || unsecure.get_user_group_permission_codes(
                        (select ug.user_group_id
                         from auth.user_group ug
                         where ug.tenant_id = _tenant_id
                           and ug.code = 'tenant_members'));
            else
                null;
        end case;
    end loop;

    perform unsecure.validate_permissions_held(_user_id, _correlation_id, __codes, _tenant_id);
end;
$$;


/***
 *    the functions that check it
 */

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

create or replace function auth.create_perm_set(_created_by text, _user_id bigint, _correlation_id text, _title text, _is_system boolean DEFAULT false, _is_assignable boolean DEFAULT true, _permissions text[] DEFAULT NULL::text[], _tenant_id integer DEFAULT 1, _source text DEFAULT NULL::text)
    returns table(
        __created_at    timestamptz,
        __created_by    text,
        __updated_at    timestamptz,
        __updated_by    text,
        __perm_set_id   integer,
        __tenant_id     integer,
        __code          text,
        __is_system     boolean,
        __is_assignable boolean,
        __source        text
    )
    rows 1
    language plpgsql
as
$$
begin

	perform
		auth.has_permission(_user_id, _correlation_id, 'permissions.create_permission_set', _tenant_id);

	-- D-19: only permissions the caller holds
	perform unsecure.validate_permissions_held(_user_id, _correlation_id
		, unsecure.get_permission_codes(_permissions), _tenant_id);

	return query
		select created_at, created_by, updated_at, updated_by, perm_set_id, tenant_id, code, is_system, is_assignable, source
		from unsecure.create_perm_set(_created_by, _user_id, _correlation_id, _title, _is_system, _is_assignable,
																	_permissions, _tenant_id, _source);
end;
$$;

create or replace function auth.update_perm_set(_updated_by text, _user_id bigint, _correlation_id text, _perm_set_id integer, _title text, _is_assignable boolean DEFAULT true, _tenant_id integer DEFAULT 1)
    returns table(
        __created_at    timestamptz,
        __created_by    text,
        __updated_at    timestamptz,
        __updated_by    text,
        __perm_set_id   integer,
        __tenant_id     integer,
        __code          text,
        __is_system     boolean,
        __is_assignable boolean,
        __source        text
    )
    rows 1
    language plpgsql
as
$$
begin

	if
		not exists(select from auth.perm_set where perm_set_id = _perm_set_id and tenant_id = _tenant_id) then
		perform error.raise_52177(_perm_set_id, _tenant_id);

	end if;

	perform
		auth.has_permission(_user_id, _correlation_id, 'permissions.update_permission_set', _tenant_id);

	-- D-19: switching assignability grants or revokes the whole set
	if exists(select
					 from auth.perm_set ps
					 where ps.perm_set_id = _perm_set_id
						 and ps.is_assignable is distinct from _is_assignable) then
		perform unsecure.validate_permissions_held(_user_id, _correlation_id
			, unsecure.get_perm_set_permission_codes(array [_perm_set_id]), _tenant_id);
	end if;

	return query
		select created_at, created_by, updated_at, updated_by, perm_set_id, tenant_id, code, is_system, is_assignable, source
		from unsecure.update_perm_set(_updated_by, _user_id, _correlation_id
			, _perm_set_id, _title, _is_assignable, _tenant_id);
end;
$$;

create or replace function auth.create_perm_set_permissions(_created_by text, _user_id bigint, _correlation_id text, _perm_set_id integer, _permissions text[] DEFAULT NULL::text[], _tenant_id integer DEFAULT 1)
    returns TABLE(__perm_set_id integer, __perm_set_code text, __permission_id integer, __permission_full_code text)
    rows 1
    language plpgsql
as
$$
begin

	perform
		auth.has_permission(_user_id, _correlation_id, 'permissions.update_permission_set', _tenant_id);

	-- D-19: only permissions the caller holds
	perform unsecure.validate_permissions_held(_user_id, _correlation_id
		, unsecure.get_permission_codes(_permissions), _tenant_id);

	return query
		select *
		from unsecure.create_perm_set_permissions(_created_by, _user_id, _correlation_id
			, _perm_set_id, _permissions, _tenant_id);
end;
$$;

create or replace function auth.delete_perm_set_permissions(_created_by text, _user_id bigint, _correlation_id text, _perm_set_id integer, _permissions text[] DEFAULT NULL::text[], _tenant_id integer DEFAULT 1)
    returns TABLE(__perm_set_id integer, __perm_set_code text, __permission_id integer, __permission_full_code text)
    rows 1
    language plpgsql
as
$$
begin

	perform
		auth.has_permission(_user_id, _correlation_id, 'permissions.update_permission_set', _tenant_id);

	-- D-19: only permissions the caller holds
	perform unsecure.validate_permissions_held(_user_id, _correlation_id
		, unsecure.get_permission_codes(_permissions), _tenant_id);

	return query
		select *
		from unsecure.delete_perm_set_permissions(_created_by, _user_id, _correlation_id
			, _perm_set_id, _permissions, _tenant_id);
end;
$$;

create or replace function auth.ensure_perm_sets(
    _created_by      text,
    _user_id         bigint,
    _correlation_id  text,
    _perm_sets       jsonb,
    _source          text    default null,
    _tenant_id       integer default 1,
    _is_final_state  boolean default false
)
    returns table(
        __created_at    timestamptz,
        __created_by    text,
        __updated_at    timestamptz,
        __updated_by    text,
        __perm_set_id   integer,
        __tenant_id     integer,
        __code          text,
        __is_system     boolean,
        __is_assignable boolean,
        __source        text
    )
    language plpgsql
as
$$
declare
    __item            jsonb;
    __title           text;
    __is_system       boolean;
    __is_assignable   boolean;
    __item_source     text;
    __permissions     text[];
    __code            text;
    __existing_id     integer;
    __input_codes     text[] := '{}';
    __extra_perms     text[];
    __set_to_delete   record;
begin
    -- Single permission check for the batch
    perform auth.has_permission(_user_id, _correlation_id, 'permissions.create_permission_set', _tenant_id);

    -- D-19: only permissions the caller holds
    perform unsecure.validate_permissions_held(_user_id, _correlation_id
        , unsecure.get_permission_codes(array(select jsonb_array_elements_text(i -> 'permissions')
                                              from jsonb_array_elements(_perm_sets) i)), _tenant_id);
    if _is_final_state then
        perform auth.has_permission(_user_id, _correlation_id, 'permissions.delete_permission_set', _tenant_id);

        if _source is null then
            raise exception '_source is required when _is_final_state is true';
        end if;
    end if;

    for __item in
        select value
        from jsonb_array_elements(_perm_sets)
    loop
        __title         := __item ->> 'title';
        __is_system     := coalesce((__item ->> 'is_system')::boolean, false);
        __is_assignable := coalesce((__item ->> 'is_assignable')::boolean, true);
        __item_source   := coalesce(__item ->> 'source', _source);
        __code          := helpers.get_code(__title, '_');

        __input_codes := array_append(__input_codes, __code);

        -- Convert JSONB array of permission codes to text[]
        select array_agg(elem::text)
        from jsonb_array_elements_text(__item -> 'permissions') as elem
        into __permissions;

        -- Check if perm set already exists for this tenant
        select ps.perm_set_id
        from auth.perm_set ps
        where ps.code = __code
          and ps.tenant_id = _tenant_id
        into __existing_id;

        if __existing_id is not null then
            -- Add any missing permissions to existing perm set
            if __permissions is not null and array_length(__permissions, 1) > 0 then
                perform unsecure.create_perm_set_permissions(
                    _created_by, _user_id, _correlation_id,
                    __existing_id, __permissions, _tenant_id
                );
            end if;

            -- Final state: remove permissions from this set that are not in the input
            if _is_final_state and __permissions is not null then
                select array_agg(p.full_code::text)
                from auth.perm_set_perm psp
                inner join auth.permission p on p.permission_id = psp.permission_id
                where psp.perm_set_id = __existing_id
                  and p.full_code::text != all (__permissions)
                into __extra_perms;

                if __extra_perms is not null and array_length(__extra_perms, 1) > 0 then
                    perform unsecure.validate_permissions_held(_user_id, _correlation_id
                        , unsecure.get_permission_codes(__extra_perms), _tenant_id);
                    perform unsecure.delete_perm_set_permissions(
                        _created_by, _user_id, _correlation_id,
                        __existing_id, __extra_perms, _tenant_id
                    );
                end if;
            end if;
        else
            -- Create new perm set with permissions
            perform unsecure.create_perm_set(
                _created_by, _user_id, _correlation_id,
                __title, __is_system, __is_assignable,
                __permissions, _tenant_id, __item_source
            );
        end if;

        -- Store title as translation
        if helpers.is_not_empty_string(__title) then
            insert into public.translation (created_by, updated_by, language_code, data_group, data_object_code, context, value)
            values (_created_by, _created_by, 'en', 'perm_set', __code, 'title', __title)
            on conflict (language_code, data_group, data_object_code, context)
                where data_object_code is not null
            do update set value = excluded.value, updated_by = excluded.updated_by, updated_at = now();
            perform internal.refresh_translation_cache();
        end if;
    end loop;

    -- Final state: remove perm sets with same source+tenant that are not in the input set
    if _is_final_state then
        for __set_to_delete in
            select ps.perm_set_id, ps.code
            from auth.perm_set ps
            where ps.source = _source
              and ps.tenant_id = _tenant_id
              and ps.code != all (__input_codes)
        loop
            perform unsecure.validate_permissions_held(_user_id, _correlation_id
                , unsecure.get_perm_set_permission_codes(array [__set_to_delete.perm_set_id]), _tenant_id);
            -- Invalidate cache for users affected by this perm set
            perform unsecure.invalidate_perm_set_users_permission_cache(
                _created_by, __set_to_delete.perm_set_id, _tenant_id
            );

            -- Clean up permission_assignment references
            delete from auth.permission_assignment
            where perm_set_id = __set_to_delete.perm_set_id;

            -- Delete the perm set (cascades to perm_set_perm)
            delete from auth.perm_set
            where perm_set_id = __set_to_delete.perm_set_id;

            -- Journal the removal
            perform public.create_journal_message_for_entity(
                _created_by, _user_id, _correlation_id,
                12022,  -- perm_set_deleted
                'perm_set', __set_to_delete.perm_set_id,
                jsonb_build_object('perm_set_code', __set_to_delete.code,
                    'reason', 'final_state_sync', 'source', _source),
                _tenant_id
            );
        end loop;
    end if;

    -- Return all processed perm sets (existing + newly created)
    return query
        select ps.created_at, ps.created_by, ps.updated_at, ps.updated_by, ps.perm_set_id, ps.tenant_id, ps.code, ps.is_system, ps.is_assignable, ps.source
        from auth.perm_set ps
        where ps.tenant_id = _tenant_id
          and ps.code in (
            select helpers.get_code(item ->> 'title', '_')
            from jsonb_array_elements(_perm_sets) as item
        )
        order by ps.code;
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

	perform unsecure.validate_user_group_in_tenant(_user_group_id, _tenant_id);
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

	perform unsecure.validate_user_group_in_tenant(_user_group_id, _tenant_id);
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
    perform unsecure.validate_user_group_in_tenant(_user_group_id, _tenant_id);
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

create or replace function auth.ensure_user_group_mappings(
    _created_by      text,
    _user_id         bigint,
    _correlation_id  text,
    _mappings        jsonb,
    _tenant_id       integer default 1,
    _is_final_state  boolean default false
)
    returns table(
        __created_at            timestamptz,
        __created_by            text,
        __user_group_mapping_id integer,
        __user_group_id         integer,
        __provider_code         text,
        __mapped_object_id      text,
        __mapped_object_name    text,
        __mapped_role           text
    )
    language plpgsql
as
$$
declare
    __item               jsonb;
    __user_group_id      integer;
    __user_group_title   text;
    __provider_code      text;
    __mapped_object_id   text;
    __mapped_object_name text;
    __mapped_role        text;
    __mapping_ids        integer[] := '{}';
    __result_id          integer;
    __input_combos       jsonb[]   := '{}';
    __combo              jsonb;
    __del_mapping        record;
    __affected_user_ids  bigint[];
begin
    -- Single permission check for the batch
    perform auth.has_permission(_user_id, _correlation_id, 'groups.create_mapping', _tenant_id);

    if _is_final_state then
        perform auth.has_permission(_user_id, _correlation_id, 'groups.delete_mapping', _tenant_id);
    end if;

    for __item in
        select value
        from jsonb_array_elements(_mappings)
    loop
        __user_group_id      := (__item ->> 'user_group_id')::integer;
        __user_group_title   := __item ->> 'user_group_title';
        __provider_code      := __item ->> 'provider_code';
        __mapped_object_id   := __item ->> 'mapped_object_id';
        __mapped_object_name := __item ->> 'mapped_object_name';
        __mapped_role        := __item ->> 'mapped_role';

        -- Resolve user_group_title to user_group_id if needed
        if __user_group_id is null and __user_group_title is not null then
            select ug.user_group_id
            from auth.user_group ug
            where ug.code = helpers.get_code(__user_group_title, '_')
              and ug.tenant_id = _tenant_id
            into __user_group_id;

            if __user_group_id is null then
                perform error.raise_52171(0);
            end if;
        end if;

        -- Track input (group, provider) combos and their specific mappings for final state
        if _is_final_state then
            __input_combos := array_append(__input_combos,
                jsonb_build_object(
                    'group_id', __user_group_id,
                    'provider_code', __provider_code,
                    'mapped_object_id', coalesce(lower(__mapped_object_id), ''),
                    'mapped_role', coalesce(lower(__mapped_role), '')
                )
            );
        end if;

        -- Delegate to existing ensure function (handles existence check + creation)
        select m.__user_group_mapping_id
        from auth.ensure_user_group_mapping(
            _created_by, _user_id, _correlation_id,
            __user_group_id, __provider_code,
            __mapped_object_id, __mapped_object_name, __mapped_role,
            _tenant_id
        ) m
        into __result_id;

        __mapping_ids := array_append(__mapping_ids, __result_id);
    end loop;

    -- Final state: for each unique (group, provider) pair in input, remove mappings not in the input
    if _is_final_state then
        -- Get distinct (group_id, provider_code) pairs from input
        for __combo in
            select distinct jsonb_build_object('group_id', c ->> 'group_id', 'provider_code', c ->> 'provider_code')
            from unnest(__input_combos) as c
        loop
            for __del_mapping in
                select ugm.user_group_mapping_id, ugm.user_group_id,
                       ugm.mapped_object_id, ugm.mapped_role, ugm.provider_code
                from auth.user_group_mapping ugm
                where ugm.user_group_id = (__combo ->> 'group_id')::integer
                  and ugm.provider_code = __combo ->> 'provider_code'
                  and ugm.user_group_mapping_id != all (__mapping_ids)
            loop
                -- D-19: removing a mapping takes away what the group grants
                perform unsecure.validate_user_group_permissions_held(_user_id, _correlation_id
                    , __del_mapping.user_group_id, _tenant_id);
                -- Collect affected user_ids for cache invalidation
                select array_agg(distinct ugm.user_id)
                from auth.user_group_member ugm
                where ugm.user_group_id = __del_mapping.user_group_id
                into __affected_user_ids;

                -- Delete the mapping
                delete from auth.user_group_mapping
                where user_group_mapping_id = __del_mapping.user_group_mapping_id;

                -- Invalidate permission cache for affected users
                if __affected_user_ids is not null and array_length(__affected_user_ids, 1) > 0 then
                    update auth.user_permission_cache
                    set expiration_date = now(),
                        updated_by = _created_by,
                        updated_at = now()
                    where tenant_id = _tenant_id
                      and user_id = any (__affected_user_ids);
                end if;

                -- Journal the removal
                perform public.create_journal_message_for_entity(
                    _created_by, _user_id, _correlation_id,
                    13021,  -- group_mapping_deleted
                    'user_group_mapping', __del_mapping.user_group_mapping_id,
                    jsonb_build_object(
                        'user_group_id', __del_mapping.user_group_id,
                        'provider_code', __del_mapping.provider_code,
                        'mapped_object_id', __del_mapping.mapped_object_id,
                        'mapped_role', __del_mapping.mapped_role,
                        'reason', 'final_state_sync'),
                    _tenant_id
                );
            end loop;
        end loop;
    end if;

    -- Return all processed mappings
    return query
        select ugm.created_at, ugm.created_by, ugm.user_group_mapping_id, ugm.user_group_id, ugm.provider_code, ugm.mapped_object_id, ugm.mapped_object_name, ugm.mapped_role
        from auth.user_group_mapping ugm
        where ugm.user_group_mapping_id = any (__mapping_ids)
        order by ugm.user_group_mapping_id;
end;
$$;

create or replace function auth.update_rule(_updated_by text, _user_id bigint, _correlation_id text, _rule_id integer,
                                            _title text, _rule jsonb, _description text default null,
                                            _tenant_id integer default 1)
    returns table(__rule_id integer)
    rows 1
    language plpgsql
as
$$
declare
    __is_global boolean;
    __tenant_id integer;
    __old_rule  jsonb;
begin
    select r.is_global, r.tenant_id, r.rule
    from auth.rule r
    where r.rule_id = _rule_id
    into __is_global, __tenant_id, __old_rule;

    if __is_global then
        perform auth.has_permission(_user_id, _correlation_id, 'rules.manage_global_rules', 1);
    else
        perform auth.has_permission(_user_id, _correlation_id, 'rules.update_rule', _tenant_id);
        perform unsecure.validate_rule_in_tenant(_rule_id, _tenant_id);
        -- D-19: an edit changes who joins every group that uses the rule
        perform unsecure.validate_permissions_held(_user_id, _correlation_id
            , (select coalesce(array_agg(distinct c), array []::text[])
               from auth.user_group_mapping ugm
                  , unnest(unsecure.get_user_group_permission_codes(ugm.user_group_id)) c
               where ugm.rule_id = _rule_id)
            , _tenant_id);
    end if;

    perform unsecure.validate_rule(_rule);

    update auth.rule
    set updated_by  = _updated_by
      , updated_at  = now()
      , title       = _title
      , description = _description
      , rule        = _rule
    where rule_id = _rule_id;

    -- current members re-evaluate at their next rebuild; new matches join at their next login or cache expiry
    update auth.user_permission_cache upc
    set expiration_date = now()
      , updated_by      = _updated_by
      , updated_at      = now()
    where upc.user_id in (select m.user_id
                          from auth.user_group_member m
                                   inner join auth.user_group_mapping ugm on ugm.user_group_mapping_id = m.mapping_id
                          where ugm.rule_id = _rule_id);

    perform public.create_journal_message_for_entity(_updated_by, _user_id, _correlation_id
        , 23002  -- rule_updated
        , 'rule', _rule_id
        , jsonb_build_object('rule_title', _title, 'old_rule', __old_rule, 'new_rule', _rule)
        , __tenant_id);

    return query select _rule_id;
end;
$$;

create or replace function auth.create_api_key(_created_by text, _user_id bigint, _correlation_id text, _title text, _description text, _perm_set_code text, _permission_full_codes text[], _api_key text DEFAULT NULL::text, _api_secret text DEFAULT NULL::text, _expire_at timestamp with time zone DEFAULT NULL::timestamp with time zone, _notification_email text DEFAULT NULL::text, _tenant_id integer DEFAULT 1)
    returns TABLE(__api_key_id integer, __api_key text, __api_secret text)
    rows 1
    language plpgsql
as
$$
declare
	__permission_full_code text;
	__api_secret      text;
	__api_secret_hash bytea;
	__api_key         text;
	__last_id         int;
	__api_user_id     bigint;
	__tenant_id       int;
begin

	perform auth.has_permission(_user_id, _correlation_id, 'api_keys.create_api_key', _tenant_id);

	__tenant_id := coalesce(_tenant_id, 1);
	-- D-19: only what the caller holds
	perform unsecure.validate_permissions_held(_user_id, _correlation_id
		, unsecure.get_grant_permission_codes(_perm_set_code, _permission_full_codes, __tenant_id), __tenant_id);

	__api_key := coalesce(_api_key, auth.generate_api_key());
	__api_secret := coalesce(_api_secret, auth.generate_api_secret());
	__api_secret_hash := auth.generate_api_secret_hash(__api_secret);

	insert into auth.api_key( created_by, updated_by, tenant_id, title, description, api_key, secret_hash, expire_at
													, notification_email)
	values ( _created_by, _created_by, _tenant_id, _title, _description, __api_key, __api_secret_hash, _expire_at
				 , _notification_email)
	returning api_key_id
		into __last_id;

	select user_id
	from unsecure.create_api_user(_created_by, _user_id, _correlation_id, __api_key, __tenant_id)
	into __api_user_id;

	if _perm_set_code is not null and _perm_set_code <> '' then
		perform unsecure.assign_permission(_created_by, _user_id, _correlation_id, _target_user_id := __api_user_id,
																			 _perm_set_code := _perm_set_code, _tenant_id := __tenant_id);
	end if;

	if _permission_full_codes is not null and _permission_full_codes <> (array [])::text[] then
		foreach __permission_full_code in array _permission_full_codes
			loop
				perform unsecure.assign_permission(_created_by, _user_id, _correlation_id, _target_user_id := __api_user_id,
																					 _permission_full_code := __permission_full_code, _tenant_id := __tenant_id);
			end loop;
	end if;

	return query
		select __last_id, __api_key, __api_secret;

	perform public.create_journal_message_for_entity(_created_by, _user_id, _correlation_id
			, 14001  -- apikey_created
			, 'api_key', __last_id
			, jsonb_strip_nulls(jsonb_build_object('api_key_title', coalesce(_title, __api_key)
				, 'api_key', __api_key, 'description', _description
				, 'expire_at', _expire_at, 'notification_email', _notification_email
				, 'perm_set_code', _perm_set_code, 'permission_codes', _permission_full_codes))
			, __tenant_id);

end;
$$;

create or replace function auth.assign_api_key_permissions(_created_by text, _user_id bigint, _correlation_id text, _api_key_id integer, _perm_set_code text, _permission_full_codes text[], _tenant_id integer DEFAULT 1)
    returns TABLE(__assignment_id bigint, __tenant_id integer, __perm_set_id integer, __perm_set_code text, __perm_set_title text, __permission_full_code text, __permission_full_title text, __permission_title text)
    rows 1
    language plpgsql
as
$$
declare
	__permission_full_code text;
	__api_user_id     bigint;
begin

	perform auth.has_permission(_user_id, _correlation_id, 'api_keys.update_permissions', _tenant_id);

	perform unsecure.validate_api_key_in_tenant(_api_key_id, _tenant_id);
	-- D-19: only what the caller holds (removals included)
	perform unsecure.validate_permissions_held(_user_id, _correlation_id
		, unsecure.get_grant_permission_codes(_perm_set_code, _permission_full_codes, _tenant_id), _tenant_id);

	select user_id
	from auth.api_key ak
				 inner join auth.user_info ui on ui.code = auth.generate_api_key_username(ak.api_key)
	where api_key_id = _api_key_id
	into __api_user_id;

	if _perm_set_code is not null then
		perform unsecure.assign_permission(_created_by, _user_id, _correlation_id, _target_user_id := __api_user_id,
																			 _perm_set_code := _perm_set_code,
																			 _tenant_id := _tenant_id);
	end if;

	if _permission_full_codes is not null then
		foreach __permission_full_code in array _permission_full_codes
			loop
				perform unsecure.assign_permission(_created_by, _user_id, _correlation_id, _target_user_id := __api_user_id,
																					 _permission_full_code := __permission_full_code,
																					 _tenant_id := _tenant_id);
			end loop;
	end if;

	return query
		select pa.assignment_id
				 , pa.tenant_id
				 , pa.perm_set_id
				 , ps.code
				 , coalesce((select mv.values->>'title' from public.mv_translation mv where mv.data_group = 'perm_set' and mv.data_object_code = ps.code and mv.language_code = 'en'), ps.code)
				 , p.full_code::text
				 , coalesce((select mv.values->>'full_title' from public.mv_translation mv where mv.data_group = 'permission' and mv.data_object_code = p.full_code::text and mv.language_code = 'en'), p.full_code::text)
				 , coalesce((select mv.values->>'title' from public.mv_translation mv where mv.data_group = 'permission' and mv.data_object_code = p.full_code::text and mv.language_code = 'en'), p.code)
		from auth.permission_assignment pa
					 left join auth.perm_set ps on pa.perm_set_id = ps.perm_set_id
					 left join auth.permission p on pa.permission_id = p.permission_id
		where pa.user_id = __api_user_id
		order by ps.code nulls last, p.full_code;

	perform public.create_journal_message_for_entity(_created_by, _user_id, _correlation_id
			, 14002  -- apikey_updated (permissions assigned)
			, 'api_key', _api_key_id
			, jsonb_build_object('api_key_title', _api_key_id::text
				, 'action', 'permissions_assigned', 'perm_set_code', _perm_set_code
				, 'permission_codes', array_to_string(_permission_full_codes, ';'))
			, _tenant_id);
end;
$$;

create or replace function auth.unassign_api_key_permissions(_deleted_by text, _user_id bigint, _correlation_id text, _api_key_id integer, _perm_set_code text, _permission_full_codes text[], _tenant_id integer DEFAULT 1)
    returns TABLE(__assignment_id bigint, __perm_set_id integer, __perm_set_code text, __perm_set_title text, __permission_full_code text, __permission_full_title text, __permission_title text)
    rows 1
    language plpgsql
as
$$
declare
	__permission_full_code text;
	__assignment_id   bigint;
	__null_bigint     bigint;
	__api_user_id     bigint;
begin

	perform auth.has_permission(_user_id, _correlation_id, 'api_keys.update_permissions', _tenant_id);

	perform unsecure.validate_api_key_in_tenant(_api_key_id, _tenant_id);
	-- D-19: only what the caller holds (removals included)
	perform unsecure.validate_permissions_held(_user_id, _correlation_id
		, unsecure.get_grant_permission_codes(_perm_set_code, _permission_full_codes, _tenant_id), _tenant_id);

	select user_id
	from auth.api_key ak
				 inner join auth.user_info ui on ui.code = auth.generate_api_key_username(ak.api_key)
	where api_key_id = _api_key_id
	into __api_user_id;

	if _perm_set_code is not null then
		select up.assignment_id
		from auth.perm_set ps
					 inner join auth.permission_assignment pa
											on pa.user_id = __api_user_id and ps.perm_set_id = pa.perm_set_id and
												 pa.tenant_id = _tenant_id
			 , lateral unsecure.unassign_permission(_deleted_by, _user_id, _correlation_id, pa.assignment_id, _tenant_id) as up
		where ps.code = _perm_set_code
		into __null_bigint;
	end if;

	if _permission_full_codes is not null then
		foreach __permission_full_code in array _permission_full_codes
			loop
				for __assignment_id in
					select pa.assignment_id
					from auth.permission p
								 inner join auth.permission_assignment pa
														on pa.user_id = __api_user_id and p.permission_id = pa.permission_id and
															 pa.tenant_id = _tenant_id
					where p.full_code = __permission_full_code::ext.ltree
					loop
						perform unsecure.unassign_permission(_deleted_by, _user_id, _correlation_id, __assignment_id, _tenant_id);
					end loop;
			end loop;
	end if;

	return query
		select pa.assignment_id
			 , pa.perm_set_id
			 , ps.code
			 , coalesce((select mv.values->>'title' from public.mv_translation mv where mv.data_group = 'perm_set' and mv.data_object_code = ps.code and mv.language_code = 'en'), ps.code)
			 , p.full_code::text
			 , coalesce((select mv.values->>'full_title' from public.mv_translation mv where mv.data_group = 'permission' and mv.data_object_code = p.full_code::text and mv.language_code = 'en'), p.full_code::text)
			 , coalesce((select mv.values->>'title' from public.mv_translation mv where mv.data_group = 'permission' and mv.data_object_code = p.full_code::text and mv.language_code = 'en'), p.code)
		from auth.permission_assignment pa
					 inner join auth.perm_set ps on pa.perm_set_id = ps.perm_set_id
					 inner join auth.permission p on pa.permission_id = p.permission_id
		where pa.user_id = __api_user_id
		order by ps.code nulls last, p.full_code;

	perform public.create_journal_message_for_entity(_deleted_by, _user_id, _correlation_id
			, 14002  -- apikey_updated (permissions unassigned)
			, 'api_key', _api_key_id
			, jsonb_build_object('api_key_title', _api_key_id::text
				, 'action', 'permissions_unassigned', 'perm_set_code', _perm_set_code
				, 'permission_codes', array_to_string(_permission_full_codes, ';'))
			, _tenant_id);

end;
$$;

create or replace function auth.create_invitation(
    _created_by      text,
    _user_id         bigint,
    _correlation_id  text,
    _tenant_id       integer,
    _target_email    text,
    _actions         jsonb default '[]'::jsonb,
    _message         text default null,
    _expires_at      timestamptz default null,
    _extra_data      jsonb default null,
    _request_context jsonb default null
) returns table(__invitation_id bigint, __uuid uuid, __on_create_actions jsonb)
    language plpgsql
as
$$
declare
    ___invitation_id bigint;
    ___uuid uuid;
    ___action jsonb;
    ___pending_actions jsonb;
begin
    perform auth.has_permission(_user_id, _correlation_id, 'invitations.create_invitation', _tenant_id);

    select * from unsecure.create_invitation(
        _created_by, _user_id, _correlation_id, _tenant_id, _target_email,
        _message, _expires_at, _extra_data
    ) into ___invitation_id, ___uuid;

    -- Create actions from the provided JSON array
    for ___action in select * from jsonb_array_elements(_actions)
    loop
        insert into auth.invitation_action (
            created_by, updated_by, invitation_id, action_type_code, executor_code,
            phase_code, condition_code, sequence, is_required, payload
        ) values (
            _created_by, _created_by, ___invitation_id,
            ___action->>'action_type_code',
            coalesce(___action->>'executor_code',
                     (select executor_code from const.invitation_action_type where code = ___action->>'action_type_code')),
            coalesce(___action->>'phase_code', 'on_accept'),
            coalesce(___action->>'condition_code', 'always'),
            coalesce((___action->>'sequence')::integer, 0),
            coalesce((___action->>'is_required')::boolean, true),
            coalesce(___action->'payload', '{}'::jsonb)
        );
    end loop;

    -- D-19: the inviter must hold what the actions will grant
    perform unsecure.validate_invitation_permissions_held(_user_id, _correlation_id, ___invitation_id, _tenant_id);

    perform unsecure.create_user_event(_created_by, _user_id, _correlation_id,
        'invitation_created', null, _request_context := _request_context,
        _event_data := jsonb_build_object('invitation_id', ___invitation_id, 'target_email', _target_email, 'tenant_id', _tenant_id));

    -- Process on_create phase actions immediately
    select coalesce(jsonb_agg(jsonb_build_object(
        'invitation_action_id', p.__invitation_action_id,
        'action_type_code', p.__action_type_code,
        'executor_code', p.__executor_code,
        'sequence', p.__sequence,
        'payload', p.__payload
    )), '[]'::jsonb)
    from unsecure.process_invitation_actions(
        _created_by, _user_id, _correlation_id, ___invitation_id, 'on_create'
    ) p
    into ___pending_actions;

    return query select ___invitation_id, ___uuid, ___pending_actions;
end;
$$;

create or replace function auth.create_invitation_from_template(
    _created_by        text,
    _user_id           bigint,
    _correlation_id    text,
    _tenant_id         integer,
    _template_code     text,
    _target_email      text,
    _message           text default null,
    _expires_at        timestamptz default null,
    _payload_overrides jsonb default null,
    _extra_data        jsonb default null,
    _request_context   jsonb default null
) returns table(__invitation_id bigint, __uuid uuid, __on_create_actions jsonb)
    language plpgsql
as
$$
declare
    ___invitation_id bigint;
    ___uuid uuid;
    ___pending_actions jsonb;
begin
    perform auth.has_permission(_user_id, _correlation_id, 'invitations.create_invitation', _tenant_id);

    select * from unsecure.create_invitation_from_template(
        _created_by, _user_id, _correlation_id, _tenant_id, _template_code,
        _target_email, _message, _expires_at, _payload_overrides, _extra_data
    ) into ___invitation_id, ___uuid;

    -- D-19: the inviter must hold what the actions will grant
    perform unsecure.validate_invitation_permissions_held(_user_id, _correlation_id, ___invitation_id, _tenant_id);

    perform unsecure.create_user_event(_created_by, _user_id, _correlation_id,
        'invitation_created', null, _request_context := _request_context,
        _event_data := jsonb_build_object('invitation_id', ___invitation_id, 'target_email', _target_email,
                                          'tenant_id', _tenant_id, 'template_code', _template_code));

    -- Process on_create phase actions immediately
    select coalesce(jsonb_agg(jsonb_build_object(
        'invitation_action_id', p.__invitation_action_id,
        'action_type_code', p.__action_type_code,
        'executor_code', p.__executor_code,
        'sequence', p.__sequence,
        'payload', p.__payload
    )), '[]'::jsonb)
    from unsecure.process_invitation_actions(
        _created_by, _user_id, _correlation_id, ___invitation_id, 'on_create'
    ) p
    into ___pending_actions;

    return query select ___invitation_id, ___uuid, ___pending_actions;
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
        perform unsecure.validate_user_group_in_tenant(_user_group_id, _tenant_id);
        -- D-19: a group owner adds members, so the caller must hold what the group grants
        perform unsecure.validate_user_group_permissions_held(_user_id, _correlation_id, _user_group_id, _tenant_id);
    else
        perform auth.has_permission(_user_id, _correlation_id
            , 'tenants.assign_owner', _tenant_id);
        -- D-19: a tenant owner holds the tenant's tenant_owner perm set
        perform unsecure.validate_permissions_held(_user_id, _correlation_id
            , unsecure.get_grant_permission_codes('tenant_owner', null, _tenant_id), _tenant_id);
    end if;
end;
$$;


select *
from public.stop_version_update('2.22', _component := 'postgresql_permissionmodel');
