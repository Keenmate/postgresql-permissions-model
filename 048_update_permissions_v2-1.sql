/*
 * PostgreSQL Permissions Model — update v2.1
 * ==========================================
 *
 * Security and correctness fixes ported from the v1 line (fixed downstream in
 * gcp-documenthub-database 110/v56, 2026-10-22 .. 2026-10-26):
 *
 *  - auth.is_owner: a null group matched ANY owner row, so the owner of one group
 *    was treated as a tenant-wide owner (and auth.has_permissions lets tenant-wide
 *    owners through every check).
 *  - unsecure.assign_permission: accepted a group from another tenant.
 *  - unsecure.unassign_permission: deleted an assignment by id in any tenant.
 *  - auth.create_user_group_mapping: no tenant scoping, inactive-group check never
 *    fired, duplicate raised a raw unique violation.
 *  - auth.delete_user_group_mapping: deleted by id in any tenant, silently did
 *    nothing for an unknown id.
 *  - auth.validate_api_key: never checked api_key.expire_at.
 *  - auth.get_tenant_groups: __group_code / __group_title were swapped.
 *  - unsecure.create_user_group_as_system / create_user_group_member_as_system:
 *    returned no rows; the member helper looked the group up in every tenant.
 *
 * New error codes: 32009 (assignment not found in tenant), 33022 (group mapping
 * not found in tenant), 33023 (group mapping already exists).
 */

set search_path = public, const, ext, stage, helpers, internal, unsecure, auth, triggers;

select *
from public.start_version_update('2.1', 'Tenant-scoping and ownership security fixes',
                                 _component := 'postgresql_permissionmodel',
                                 _description := 'is_owner null-group fix; tenant-scoped assign/unassign_permission and group mapping writers; api key expiry; get_tenant_groups column swap; *_as_system group helpers return their rows.');


/***
 *    ███████╗██████╗ ██████╗  ██████╗ ██████╗ ███████╗
 *    ██╔════╝██╔══██╗██╔══██╗██╔═══██╗██╔══██╗██╔════╝
 *    █████╗  ██████╔╝██████╔╝██║   ██║██████╔╝███████╗
 *    ██╔══╝  ██╔══██╗██╔══██╗██║   ██║██╔══██╗╚════██║
 *    ███████╗██║  ██║██║  ██║╚██████╔╝██║  ██║███████║
 *    ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝
 *
 */

insert into const.event_code (event_id, code, category_code, is_system, source)
values (32009, 'err_permission_assignment_not_found', 'permission_error', true, 'core')
     , (33022, 'err_group_mapping_not_found', 'user_error', true, 'core')
     , (33023, 'err_group_mapping_already_exists', 'user_error', true, 'core')
on conflict do nothing;

insert into const.event_message (event_id, language_code, message_template)
values (32009, 'en', 'Permission assignment (assignment id: {assignment_id}) does not exist in tenant (tenant id: {tenant_id})')
     , (33022, 'en', 'User group mapping (mapping id: {user_group_mapping_id}) does not exist in tenant (tenant id: {tenant_id})')
     , (33023, 'en', 'User group (group id: {user_group_id}) already has this mapping (provider: {provider_code}, object: {mapped_object_id}, role: {mapped_role})')
on conflict do nothing;

-- 32009: Permission assignment not found in tenant
create or replace function error.raise_32009(_assignment_id bigint, _tenant_id integer) returns void
    language plpgsql
as
$$
begin
    raise exception 'Permission assignment (assignment id: %) does not exist in tenant (tenant id: %)', _assignment_id, _tenant_id
        using errcode = '32009';
end;
$$;

-- 33022: Group mapping not found in tenant
create or replace function error.raise_33022(_user_group_mapping_id integer, _tenant_id integer) returns void
    language plpgsql
as
$$
begin
    raise exception 'User group mapping (mapping id: %) does not exist in tenant (tenant id: %)', _user_group_mapping_id, _tenant_id
        using errcode = '33022';
end;
$$;

-- 33023: Group mapping already exists
create or replace function error.raise_33023(_user_group_id integer, _provider_code text, _mapped_object_id text, _mapped_role text) returns void
    language plpgsql
as
$$
begin
    raise exception 'User group (group id: %) already has this mapping (provider: %, object: %, role: %)', _user_group_id, _provider_code, _mapped_object_id, _mapped_role
        using errcode = '33023';
end;
$$;


/***
 *     ██████╗ ██╗    ██╗███╗   ██╗███████╗██████╗
 *    ██╔═══██╗██║    ██║████╗  ██║██╔════╝██╔══██╗
 *    ██║   ██║██║ █╗ ██║██╔██╗ ██║█████╗  ██████╔╝
 *    ██║   ██║██║███╗██║██║╚██╗██║██╔══╝  ██╔══██╗
 *    ╚██████╔╝╚███╔███╔╝██║ ╚████║███████╗██║  ██║
 *     ╚═════╝  ╚══╝╚══╝ ╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝
 *
 */

-- A null _user_group_id asks "is this user a tenant-wide owner?" and must match
-- only tenant-wide owner rows (user_group_id is null), not the owner of any group.
create or replace function auth.is_owner(_user_id bigint, _correlation_id text, _user_group_id integer DEFAULT NULL::integer, _tenant_id integer DEFAULT 1) returns boolean
    stable
    language plpgsql
as
$$
begin
	if exists(select
						from auth.owner
						where user_id = _user_id
							and tenant_id = _tenant_id
							and user_group_id is not distinct from _user_group_id) then
		return true;
	end if;

	return false;
end;
$$;


/***
 *    ██████╗ ███████╗██████╗ ███╗   ███╗██╗███████╗███████╗██╗ ██████╗ ███╗   ██╗███████╗
 *    ██╔══██╗██╔════╝██╔══██╗████╗ ████║██║██╔════╝██╔════╝██║██╔═══██╗████╗  ██║██╔════╝
 *    ██████╔╝█████╗  ██████╔╝██╔████╔██║██║███████╗███████╗██║██║   ██║██╔██╗ ██║███████╗
 *    ██╔═══╝ ██╔══╝  ██╔══██╗██║╚██╔╝██║██║╚════██║╚════██║██║██║   ██║██║╚██╗██║╚════██║
 *    ██║     ███████╗██║  ██║██║ ╚═╝ ██║██║███████║███████║██║╚██████╔╝██║ ╚████║███████║
 *    ╚═╝     ╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝╚═╝╚══════╝╚══════╝╚═╝ ╚═════╝ ╚═╝  ╚═══╝╚══════╝
 *
 */

create or replace function unsecure.assign_permission(_created_by text, _user_id bigint, _correlation_id text, _user_group_id integer DEFAULT NULL::integer, _target_user_id bigint DEFAULT NULL::bigint, _perm_set_code text DEFAULT NULL::text, _permission_full_code text DEFAULT NULL::text, _tenant_id integer DEFAULT 1) returns SETOF auth.permission_assignment
    language plpgsql
as
$$
declare
	__last_id               bigint;
	__perm_set_id           int;
	__perm_set_assignable   bool;
	__permission_id         int;
	__permission_assignable bool;
begin

	if _user_group_id is null and _target_user_id is null then
		perform error.raise_52272();
	end if;

	-- Enforce mutual exclusivity: cannot specify both group and user
	if _user_group_id is not null and _target_user_id is not null then
		raise exception 'Cannot specify both group and user for permission assignment'
			using errcode = '22023';  -- invalid_parameter_value
	end if;

	if
		_perm_set_code is null and _permission_full_code is null then
		perform error.raise_52273();
	end if;

	-- The group must live in the tenant the assignment is created in
	if _user_group_id is not null and not exists(select
																							 from auth.user_group ug
																							 where ug.user_group_id = _user_group_id
																								 and ug.tenant_id = _tenant_id) then
		perform error.raise_52171(_user_group_id);
	end if;

	if _target_user_id is not null and not exists(select
																								from auth.user_info ui
																								where ui.user_id = _target_user_id) then
		perform error.raise_52103(_target_user_id);
	end if;

	if _perm_set_code is not null then
		select ps.perm_set_id, ps.is_assignable
		from auth.perm_set ps
		where ps.tenant_id = _tenant_id
		and ps.code = _perm_set_code
		into __perm_set_id, __perm_set_assignable;

		if __perm_set_id is null then
			perform error.raise_52282(_perm_set_code);
		else
			if not __perm_set_assignable then
				perform error.raise_52283(_permission_full_code);
			end if;
		end if;
	end if;

	if _permission_full_code is not null then
		select p.permission_id, p.is_assignable
		from auth.permission p
		where p.full_code = _permission_full_code::ext.ltree
		into __permission_id, __permission_assignable;

		if __permission_id is null then
			perform error.raise_52180(_permission_full_code);
		else
			if not __permission_assignable then
				perform error.raise_52181(_permission_full_code);
			end if;
		end if;
	end if;

	insert into auth.permission_assignment (created_by, tenant_id, user_group_id, user_id, perm_set_id, permission_id)
	values (_created_by, _tenant_id, _user_group_id, _target_user_id, __perm_set_id, __permission_id)
	returning assignment_id
		into __last_id;

	return query
		select *
		from auth.permission_assignment
		where assignment_id = __last_id;

	if _user_group_id is not null then
		perform public.create_journal_message_for_entity(_created_by, _user_id, _correlation_id
			, 12010  -- permission_assigned
			, 'group', _user_group_id
			, jsonb_build_object('permission_code', coalesce(_perm_set_code, _permission_full_code)
				, 'target_type', 'group', 'target_name', _user_group_id::text
				, 'assignment_id', __last_id, 'perm_set_code', _perm_set_code)
			, _tenant_id);

		-- Invalidate permission cache for all members of the group
		perform unsecure.invalidate_group_members_permission_cache(_created_by, _user_group_id, _tenant_id);
	else
		perform public.create_journal_message_for_entity(_created_by, _user_id, _correlation_id
			, 12010  -- permission_assigned
			, 'user', _target_user_id
			, jsonb_build_object('permission_code', coalesce(_perm_set_code, _permission_full_code)
				, 'target_type', 'user', 'target_name', _target_user_id::text
				, 'assignment_id', __last_id, 'perm_set_code', _perm_set_code)
			, _tenant_id);

		-- Invalidate permission cache for the target user
		perform unsecure.clear_permission_cache(_created_by, _target_user_id, _tenant_id);
	end if;
end;
$$;

-- Only an assignment of _tenant_id can be removed; anything else raises 32009
create or replace function unsecure.unassign_permission(_deleted_by text, _user_id bigint, _correlation_id text, _assignment_id bigint, _tenant_id integer DEFAULT 1) returns SETOF auth.permission_assignment
    language plpgsql
as
$$
declare
	__user_group_id  int;
	__target_user_id bigint;
begin

	select user_group_id, user_id
	from auth.permission_assignment pa
	where pa.assignment_id = _assignment_id
		and pa.tenant_id = _tenant_id
	into __user_group_id, __target_user_id;

	if not found then
		perform error.raise_32009(_assignment_id, _tenant_id);
	end if;

	return query
		delete
			from auth.permission_assignment
				where assignment_id = _assignment_id
					and tenant_id = _tenant_id
				returning *;

	if __user_group_id is not null then
		perform public.create_journal_message_for_entity(_deleted_by, _user_id, _correlation_id
			, 12011  -- permission_revoked
			, 'group', __user_group_id
			, jsonb_build_object('target_type', 'group', 'target_name', __user_group_id::text
				, 'assignment_id', _assignment_id)
			, _tenant_id);

		-- Invalidate permission cache for all members of the group
		perform unsecure.invalidate_group_members_permission_cache(_deleted_by, __user_group_id, _tenant_id);
	else
		perform public.create_journal_message_for_entity(_deleted_by, _user_id, _correlation_id
			, 12011  -- permission_revoked
			, 'user', __target_user_id
			, jsonb_build_object('target_type', 'user', 'target_name', __target_user_id::text
				, 'assignment_id', _assignment_id)
			, _tenant_id);

		-- Invalidate permission cache for the target user
		perform unsecure.clear_permission_cache(_deleted_by, __target_user_id, _tenant_id);
	end if;
end;

$$;


/***
 *     ██████╗ ██████╗  ██████╗ ██╗   ██╗██████╗ ███████╗
 *    ██╔════╝ ██╔══██╗██╔═══██╗██║   ██║██╔══██╗██╔════╝
 *    ██║  ███╗██████╔╝██║   ██║██║   ██║██████╔╝███████╗
 *    ██║   ██║██╔══██╗██║   ██║██║   ██║██╔═══╝ ╚════██║
 *    ╚██████╔╝██║  ██║╚██████╔╝╚██████╔╝██║     ███████║
 *     ╚═════╝ ╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚═╝     ╚══════╝
 *
 */

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

-- Only a mapping of a group in _tenant_id can be deleted; anything else raises 33022
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

-- Was returning group_title as __group_code and group_code as __group_title
create or replace function auth.get_tenant_groups(_requested_by text, _user_id bigint, _correlation_id text, _tenant_id integer DEFAULT 1, _target_tenant_id integer default null)
    returns TABLE(__user_group_id integer, __group_code text, __group_title text, __is_external boolean, __is_assignable boolean, __is_active boolean, __members_count bigint)
    language plpgsql
as
$$
declare
	__effective_tenant_id int;
begin
	__effective_tenant_id := internal.resolve_cross_tenant_access(
		_user_id, _correlation_id, 'tenants.get_all_groups', 'tenants.get_groups', _tenant_id, _target_tenant_id);

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
		group by ugs.user_group_id, ugs.group_title, ugs.group_code, ugs.is_external, ugs.is_assignable, ugs.is_active
		order by ugs.group_title;

	-- Read operation - journal message omitted (use journal level 'all' to log reads)
end;
$$;

-- Joining the new id back to auth.user_group in the same statement can't see the
-- row the call just inserted, so these returned nothing. Read it in a second statement.
create or replace function unsecure.create_user_group_as_system(_title text, _is_system boolean DEFAULT false, _is_assignable boolean DEFAULT true, _is_default boolean DEFAULT false, _tenant_id integer DEFAULT 1) returns SETOF auth.user_group
    rows 1
    language plpgsql
as
$$
declare
	__user_group_id int;
begin
	select g.__user_group_id
	from unsecure.create_user_group('system', 1, null, _title, _is_assignable, true, false, _is_system, _is_default, _tenant_id) g
	into __user_group_id;

	return query
		select ug.*
		from auth.user_group ug
		where ug.user_group_id = __user_group_id;
end;
$$;

-- Also looks the group up only in _tenant_id (every tenant has e.g. "Tenant Admins")
create or replace function unsecure.create_user_group_member_as_system(_user_name text, _group_title text, _tenant_id integer DEFAULT 1) returns SETOF auth.user_group_member
    language plpgsql
as
$$
declare
	__user_id       bigint;
	__user_group_id int;
	__member_id     bigint;
begin
	select ui.user_id
	from auth.user_info ui
	where ui.username = _user_name
	into __user_id;

	select ug.user_group_id
	from auth.user_group ug
	where lower(ug.title) = lower(_group_title)
		and ug.tenant_id = _tenant_id
	into __user_group_id;

	select r.__user_group_member_id
	from unsecure.create_user_group_member('system', 1, null, __user_group_id, __user_id, _tenant_id) r
	into __member_id;

	return query
		select ugm.*
		from auth.user_group_member ugm
		where ugm.member_id = __member_id;
end;
$$;


/***
 *     █████╗ ██████╗ ██╗    ██╗  ██╗███████╗██╗   ██╗███████╗
 *    ██╔══██╗██╔══██╗██║    ██║ ██╔╝██╔════╝╚██╗ ██╔╝██╔════╝
 *    ███████║██████╔╝██║    █████╔╝ █████╗   ╚████╔╝ ███████╗
 *    ██╔══██║██╔═══╝ ██║    ██╔═██╗ ██╔══╝    ╚██╔╝  ╚════██║
 *    ██║  ██║██║     ██║    ██║  ██╗███████╗   ██║   ███████║
 *    ╚═╝  ╚═╝╚═╝     ╚═╝    ╚═╝  ╚═╝╚══════╝   ╚═╝   ╚══════╝
 *
 */

-- An expired key is refused with the same 52301 as a wrong key/secret
create or replace function auth.validate_api_key(_requested_by text, _user_id bigint, _correlation_id text, _api_key text, _api_secret text, _request_context jsonb DEFAULT NULL::jsonb, _tenant_id integer DEFAULT 1)
    returns TABLE(__user_id bigint, __username text, __user_display_name text, __permission_full_codes text[])
    rows 1
    language plpgsql
as
$$
declare
	__api_user_id bigint;
begin

	perform auth.has_permission(_user_id, _correlation_id, 'api_keys.validate_api_key', _tenant_id);

	select user_id
	from auth.api_key ak
				 inner join auth.user_info ui on ui.code = auth.generate_api_key_username(ak.api_key)
	where ak.api_key = _api_key
		and ak.secret_hash = auth.generate_api_secret_hash(_api_secret)
		and ak.tenant_id = _tenant_id
		and (ak.expire_at is null or ak.expire_at > now())
	into __api_user_id;

	if __api_user_id is null then

		perform auth.create_user_event(_requested_by, _user_id, _correlation_id,
			'api_key_validating', __api_user_id,
			_request_context := _request_context,
			_event_data := jsonb_build_object('is_successful', false));

		perform error.raise_52301(_api_key);
	end if;

	return query
		with pa as (select u.display_name, u.username, pa.perm_set_id, pa.permission_id
								from auth.permission_assignment pa
											 inner join auth.user_info u on u.user_id = pa.user_id
								where pa.user_id = __api_user_id
									and pa.tenant_id = _tenant_id)
			 , permissions as (select ep.permission_code::text
												 from pa
																inner join auth.effective_permissions ep on pa.perm_set_id = ep.perm_set_id
												 union
												 distinct
												 select p.full_code::text
												 from pa
																inner join auth.permission p on pa.permission_id = p.permission_id)
		select ui.user_id, ui.username, ui.display_name, array_agg(permission_code)
		from auth.user_info ui
					 left join permissions p on true
		where ui.user_id = __api_user_id
		group by ui.user_id, ui.username, ui.display_name;

	perform auth.create_user_event(_requested_by, _user_id, _correlation_id,
		'api_key_validating', __api_user_id,
		_request_context := _request_context,
		_event_data := jsonb_build_object('is_successful', true));

end;
$$;


select *
from public.stop_version_update('2.1', _component := 'postgresql_permissionmodel');
