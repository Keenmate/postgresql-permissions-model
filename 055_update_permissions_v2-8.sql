/*
 * PostgreSQL Permissions Model — update v2.8
 * ==========================================
 *
 * Entities passed by id must belong to _tenant_id (audit decision D-02, option a).
 * Functions took a group, API key, invitation, invitation template or MFA policy
 * by id, checked the caller's permission in _tenant_id and never checked that the
 * entity lives in _tenant_id. An admin - or a plain tenant owner, who skips the
 * group-management check - of tenant B could pass tenant A's ids with
 * _tenant_id = B and:
 *
 *  - join tenant A's groups (create_user_group_member), so gain A's permissions,
 *    or remove A's members, or make themselves A's group owner (create_owner);
 *  - turn A's groups external / hybrid / internal (dropping A's members);
 *  - delete A's API keys, give them B's permissions;
 *  - accept, reject or revoke A's invitations, update or delete A's and global
 *    invitation templates, delete A's MFA policies;
 *  - read A's groups and their assigned permissions by id.
 *
 * Every such function now validates the entity's tenant right after the
 * permission check and raises the same not-found error as for a missing id
 * (33011 group, 30007 API key (new), 39001 invitation, 39006 template, 38007 MFA
 * policy), so the entity's existence is not revealed. Functions that already
 * filtered on the tenant and silently did nothing (update/enable/disable/lock/
 * unlock/delete group, update API key / secret - which returned a secret that
 * was never stored) now raise too.
 *
 * Global rows (invitation templates and MFA policies with tenant_id null) can
 * only be managed from tenant 1.
 *
 * auth.has_permissions with _tenant_id null granted whatever the user held in
 * any tenant. A null tenant now holds nothing. create_mfa_policy,
 * get_mfa_policies and create_invitation_template, where null means "global",
 * check the permission in tenant 1.
 *
 * New error code: 30007.
 */

set search_path = public, const, ext, stage, helpers, internal, unsecure, auth, triggers;

select *
from public.start_version_update('2.8', 'Entities passed by id must belong to _tenant_id',
                                 _component := 'postgresql_permissionmodel',
                                 _description := 'Groups, members, group owners, API keys, invitations, invitation templates and MFA policies passed by id are validated against _tenant_id (mismatch = not found); global templates and policies are managed from tenant 1; has_permissions grants nothing for a null tenant.');


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
values (30007, 'err_api_key_not_found', 'security_error', true, 'core')
on conflict do nothing;

insert into const.event_message (event_id, language_code, message_template)
values (30007, 'en', 'API key (id: {api_key_id}) does not exist')
on conflict do nothing;

-- 30007: API key not found
create or replace function error.raise_30007(_api_key_id integer) returns void
    language plpgsql
as
$$
begin
    raise exception 'API key (id: %) does not exist', _api_key_id
        using errcode = '30007';
end;
$$;


/***
 *    ██╗   ██╗ █████╗ ██╗     ██╗██████╗  █████╗ ████████╗ ██████╗ ██████╗ ███████╗
 *    ██║   ██║██╔══██╗██║     ██║██╔══██╗██╔══██╗╚══██╔══╝██╔═══██╗██╔══██╗██╔════╝
 *    ██║   ██║███████║██║     ██║██║  ██║███████║   ██║   ██║   ██║██████╔╝███████╗
 *    ╚██╗ ██╔╝██╔══██║██║     ██║██║  ██║██╔══██║   ██║   ██║   ██║██╔══██╗╚════██║
 *     ╚████╔╝ ██║  ██║███████╗██║██████╔╝██║  ██║   ██║   ╚██████╔╝██║  ██║███████║
 *      ╚═══╝  ╚═╝  ╚═╝╚══════╝╚═╝╚═════╝ ╚═╝  ╚═╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝╚══════╝
 *
 * Called right after the permission check, so a caller without the permission
 * cannot use them to probe which ids exist. A row of another tenant raises the
 * same error as a missing row.
 */

create or replace function unsecure.validate_user_group_in_tenant(_user_group_id integer, _tenant_id integer) returns void
    stable
    language plpgsql
as
$$
begin
    if not exists(select
                  from auth.user_group ug
                  where ug.user_group_id = _user_group_id
                    and ug.tenant_id = _tenant_id) then
        perform error.raise_33011(_user_group_id);
    end if;
end;
$$;

create or replace function unsecure.validate_api_key_in_tenant(_api_key_id integer, _tenant_id integer) returns void
    stable
    language plpgsql
as
$$
begin
    if not exists(select
                  from auth.api_key ak
                  where ak.api_key_id = _api_key_id
                    and ak.tenant_id = _tenant_id) then
        perform error.raise_30007(_api_key_id);
    end if;
end;
$$;

create or replace function unsecure.validate_invitation_in_tenant(_invitation_id bigint, _tenant_id integer) returns void
    stable
    language plpgsql
as
$$
begin
    if not exists(select
                  from auth.invitation i
                  where i.invitation_id = _invitation_id
                    and i.tenant_id = _tenant_id) then
        perform error.raise_39001(_invitation_id);
    end if;
end;
$$;

-- A global template (tenant_id null) belongs to tenant 1
create or replace function unsecure.validate_invitation_template_in_tenant(_template_id integer, _tenant_id integer) returns void
    stable
    language plpgsql
as
$$
begin
    if not exists(select
                  from auth.invitation_template it
                  where it.template_id = _template_id
                    and coalesce(it.tenant_id, 1) = _tenant_id) then
        perform error.raise_39006(_template_id::text);
    end if;
end;
$$;

-- A global policy (tenant_id null) belongs to tenant 1
create or replace function unsecure.validate_mfa_policy_in_tenant(_mfa_policy_id bigint, _tenant_id integer) returns void
    stable
    language plpgsql
as
$$
begin
    if not exists(select
                  from auth.mfa_policy mp
                  where mp.mfa_policy_id = _mfa_policy_id
                    and coalesce(mp.tenant_id, 1) = _tenant_id) then
        perform error.raise_38007(_mfa_policy_id);
    end if;
end;
$$;


/***
 *    ███████╗██╗   ██╗███╗   ██╗ ██████╗████████╗██╗ ██████╗ ███╗   ██╗███████╗
 *    ██╔════╝██║   ██║████╗  ██║██╔════╝╚══██╔══╝██║██╔═══██╗████╗  ██║██╔════╝
 *    █████╗  ██║   ██║██╔██╗ ██║██║        ██║   ██║██║   ██║██╔██╗ ██║███████╗
 *    ██╔══╝  ██║   ██║██║╚██╗██║██║        ██║   ██║██║   ██║██║╚██╗██║╚════██║
 *    ██║     ╚██████╔╝██║ ╚████║╚██████╗   ██║   ██║╚██████╔╝██║  ██║███████║
 *    ╚═╝      ╚═════╝ ╚═╝  ╚═══╝ ╚═════╝   ╚═╝   ╚═╝ ╚═════╝ ╚═╝  ╚═══╝╚══════╝
 *
 */

-- ----------------------------------------------------------------------------
-- Permission check: a null tenant holds nothing
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

-- ----------------------------------------------------------------------------
-- Groups, group members and group owners
-- ----------------------------------------------------------------------------

create or replace function auth.update_user_group(_updated_by text, _user_id bigint, _correlation_id text, _user_group_id integer, _title text, _is_assignable boolean, _is_active boolean, _is_external boolean, _is_default boolean, _tenant_id integer DEFAULT 1)
    returns TABLE(__user_group_id integer)
    rows 1
    language plpgsql
as
$$
begin
	perform
		auth.has_permission(_user_id, _correlation_id, 'groups.update_group', _tenant_id);

	perform unsecure.validate_user_group_in_tenant(_user_group_id, _tenant_id);

	return query
		update auth.user_group
			set updated_by = _updated_by
				, updated_at = now()
				, title = _title
				, is_assignable = _is_assignable
				, is_active = _is_active
				, is_external = _is_external
				, is_default = _is_default
			where tenant_id = _tenant_id
				and user_group_id = _user_group_id
			returning user_group_id;

	perform public.create_journal_message_for_entity(_updated_by, _user_id, _correlation_id
			, 13002  -- group_updated
			, 'group', _user_group_id
			, jsonb_build_object('group_title', _title, 'is_default', _is_default
				, 'is_assignable', _is_assignable, 'is_active', _is_active, 'is_external', _is_external)
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

	perform unsecure.validate_user_group_in_tenant(_user_group_id, _tenant_id);

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

	perform unsecure.validate_user_group_in_tenant(_user_group_id, _tenant_id);

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

	perform unsecure.validate_user_group_in_tenant(_user_group_id, _tenant_id);

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

	perform unsecure.validate_user_group_in_tenant(_user_group_id, _tenant_id);

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

	perform unsecure.validate_user_group_in_tenant(_user_group_id, _tenant_id);

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

create or replace function auth.set_user_group_as_external(_updated_by text, _user_id bigint, _correlation_id text, _user_group_id integer, _tenant_id integer DEFAULT 1) returns void
    language plpgsql
as
$$
declare
	__user_group_code text;
begin
	perform
		auth.has_permission(_user_id, _correlation_id, 'groups.update_group', _tenant_id);

	perform unsecure.validate_user_group_in_tenant(_user_group_id, _tenant_id);

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

	perform unsecure.validate_user_group_in_tenant(_user_group_id, _tenant_id);

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

	perform unsecure.validate_user_group_in_tenant(_user_group_id, _tenant_id);

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

create or replace function auth.get_user_group_by_id(_requested_by text, _user_id bigint, _correlation_id text, _user_group_id integer, _tenant_id integer DEFAULT 1)
    returns TABLE(__user_group_id integer, __tenant_id integer, __title text, __code text, __is_system boolean, __is_external boolean, __is_assignable boolean, __is_active boolean, __is_default boolean)
    language plpgsql
as
$$
begin
	perform
		auth.has_permission(_user_id, _correlation_id, 'groups.get_group', _tenant_id);

	perform unsecure.validate_user_group_in_tenant(_user_group_id, _tenant_id);

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

	perform unsecure.validate_user_group_in_tenant(_user_group_id, _tenant_id);

	return query select *
							 from unsecure.get_assigned_group_permissions(_requested_by, _user_id, _user_group_id, _tenant_id);
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
    perform unsecure.validate_user_group_in_tenant(_user_group_id, _tenant_id);

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
		perform unsecure.validate_user_group_in_tenant(_user_group_id, _tenant_id);
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
		perform unsecure.validate_user_group_in_tenant(_user_group_id, _tenant_id);
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

-- ----------------------------------------------------------------------------
-- API keys
-- ----------------------------------------------------------------------------

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

create or replace function auth.update_api_key(_updated_by text, _user_id bigint, _correlation_id text, _api_key_id integer, _title text, _description text, _expire_at timestamp with time zone, _notification_email text, _tenant_id integer DEFAULT 1)
    returns TABLE(__api_key_id integer, __title text, __description text, __expire_at timestamp with time zone, __notification_email text)
    rows 1
    language plpgsql
as
$$
begin

	perform auth.has_permission(_user_id, _correlation_id, 'api_keys.update_api_key', _tenant_id);

	perform unsecure.validate_api_key_in_tenant(_api_key_id, _tenant_id);

	update auth.api_key
	set updated_by         = _updated_by
		, updated_at         = now()
		, title              = _title
		, description        = _description
		, expire_at          = _expire_at
		, notification_email = _notification_email
	where api_key_id = _api_key_id
		and tenant_id = _tenant_id;

	return query
		select api_key_id, title, description, expire_at, notification_email
		from auth.api_key
		where api_key_id = _api_key_id
			and tenant_id = _tenant_id;

	perform public.create_journal_message_for_entity(_updated_by, _user_id, _correlation_id
			, 14002  -- apikey_updated
			, 'api_key', _api_key_id
			, jsonb_build_object('api_key_title', _title, 'description', _description
				, 'expire_at', _expire_at, 'notification_email', _notification_email)
			, _tenant_id);
end;
$$;

create or replace function auth.update_api_key_secret(_updated_by text, _user_id bigint, _correlation_id text, _api_key_id integer, _api_secret text DEFAULT NULL::text, _tenant_id integer DEFAULT 1)
    returns TABLE(__api_key_id integer, __api_secret text)
    rows 1
    language plpgsql
as
$$
declare
	__api_secret      text;
	__api_secret_hash bytea;
begin

	perform auth.has_permission(_user_id, _correlation_id, 'api_keys.update_api_secret', _tenant_id);

	perform unsecure.validate_api_key_in_tenant(_api_key_id, _tenant_id);

	__api_secret := coalesce(_api_secret, auth.generate_api_secret());
	__api_secret_hash := auth.generate_api_secret_hash(__api_secret);

	update auth.api_key
	set updated_by  = _updated_by
		, updated_at  = now()
		, secret_hash = __api_secret_hash
	where api_key_id = _api_key_id
		and tenant_id = _tenant_id;

	return query
		select _api_key_id, __api_secret;

	perform public.create_journal_message_for_entity(_updated_by, _user_id, _correlation_id
			, 14002  -- apikey_updated (secret rotated)
			, 'api_key', _api_key_id
			, jsonb_build_object('api_key_title', _api_key_id::text, 'action', 'secret_rotated')
			, _tenant_id);

end;
$$;

create or replace function auth.delete_api_key(_deleted_by text, _user_id bigint, _correlation_id text, _api_key_id integer, _tenant_id integer DEFAULT 1)
    returns TABLE(__api_key_id integer)
    rows 1
    language plpgsql
as
$$
declare
	__api_user_id bigint;
begin

	perform auth.has_permission(_user_id, _correlation_id, 'api_keys.delete_api_key', _tenant_id);

	perform unsecure.validate_api_key_in_tenant(_api_key_id, _tenant_id);

	select user_id
	from auth.api_key ak
				 inner join auth.user_info ui on ui.code = auth.generate_api_key_username(ak.api_key)
	where api_key_id = _api_key_id
	into __api_user_id;

	delete from auth.permission_assignment where user_id = __api_user_id;

	perform unsecure.delete_user_by_id(_deleted_by, _user_id, _correlation_id, __api_user_id) du;

	return query
		delete from auth.api_key where api_key_id = _api_key_id
			returning api_key_id;

	perform public.create_journal_message_for_entity(_deleted_by, _user_id, _correlation_id
			, 14003  -- apikey_deleted
			, 'api_key', _api_key_id
			, jsonb_build_object('api_key_title', _api_key_id::text)
			, _tenant_id);

end;
$$;

-- ----------------------------------------------------------------------------
-- Invitations and invitation templates
-- ----------------------------------------------------------------------------

create or replace function auth.accept_invitation(
    _updated_by      text,
    _user_id         bigint,
    _correlation_id  text,
    _invitation_id   bigint,
    _target_user_id  bigint,
    _request_context jsonb default null,
    _tenant_id       integer default 1
) returns table(
    __invitation_action_id bigint,
    __action_type_code     text,
    __executor_code        text,
    __sequence             integer,
    __payload              jsonb
)
    language plpgsql
as
$$
begin
    perform auth.has_permission(_user_id, _correlation_id, 'invitations.accept_invitation', _tenant_id);

    perform unsecure.validate_invitation_in_tenant(_invitation_id, _tenant_id);

    perform unsecure.accept_invitation(
        _updated_by, _user_id, _correlation_id, _invitation_id, _target_user_id
    );

    perform unsecure.create_user_event(_updated_by, _user_id, _correlation_id,
        'invitation_accepted', _target_user_id, _request_context := _request_context,
        _event_data := jsonb_build_object('invitation_id', _invitation_id));

    -- Process on_accept phase actions
    return query select * from unsecure.process_invitation_actions(
        _updated_by, _user_id, _correlation_id, _invitation_id, 'on_accept'
    );
end;
$$;

create or replace function auth.reject_invitation(
    _updated_by      text,
    _user_id         bigint,
    _correlation_id  text,
    _invitation_id   bigint,
    _request_context jsonb default null,
    _tenant_id       integer default 1
) returns table(
    __invitation_action_id bigint,
    __action_type_code     text,
    __executor_code        text,
    __sequence             integer,
    __payload              jsonb
)
    language plpgsql
as
$$
begin
    perform auth.has_permission(_user_id, _correlation_id, 'invitations.reject_invitation', _tenant_id);

    perform unsecure.validate_invitation_in_tenant(_invitation_id, _tenant_id);

    perform unsecure.reject_invitation(
        _updated_by, _user_id, _correlation_id, _invitation_id
    );

    perform unsecure.create_user_event(_updated_by, _user_id, _correlation_id,
        'invitation_rejected', null, _request_context := _request_context,
        _event_data := jsonb_build_object('invitation_id', _invitation_id));

    -- Process on_reject phase actions (e.g. notify inviter of rejection)
    return query select * from unsecure.process_invitation_actions(
        _updated_by, _user_id, _correlation_id, _invitation_id, 'on_reject'
    );
end;
$$;

create or replace function auth.revoke_invitation(
    _updated_by      text,
    _user_id         bigint,
    _correlation_id  text,
    _invitation_id   bigint,
    _request_context jsonb default null,
    _tenant_id       integer default 1
) returns void
    language plpgsql
as
$$
begin
    perform auth.has_permission(_user_id, _correlation_id, 'invitations.revoke_invitation', _tenant_id);

    perform unsecure.validate_invitation_in_tenant(_invitation_id, _tenant_id);

    perform unsecure.revoke_invitation(
        _updated_by, _user_id, _correlation_id, _invitation_id
    );

    perform unsecure.create_user_event(_updated_by, _user_id, _correlation_id,
        'invitation_revoked', null, _request_context := _request_context,
        _event_data := jsonb_build_object('invitation_id', _invitation_id));
end;
$$;

create or replace function auth.get_invitation_actions(
    _requested_by    text,
    _user_id         bigint,
    _correlation_id  text,
    _invitation_id   bigint,
    _tenant_id       integer default 1
) returns table(
    __invitation_action_id bigint,
    __action_type_code     text,
    __executor_code        text,
    __phase_code           text,
    __condition_code       text,
    __sequence             integer,
    __is_required          boolean,
    __status_code          text,
    __payload              jsonb,
    __result_data          jsonb,
    __error_message        text,
    __completed_at         timestamptz,
    __created_at           timestamptz
)
    language plpgsql
as
$$
begin
    perform auth.has_permission(_user_id, _correlation_id, 'invitations.get_invitations', _tenant_id);

    perform unsecure.validate_invitation_in_tenant(_invitation_id, _tenant_id);

    return query select * from unsecure.get_invitation_actions(
        _requested_by, _user_id, _correlation_id, _invitation_id
    );
end;
$$;

create or replace function auth.update_invitation_template(
    _updated_by      text,
    _user_id         bigint,
    _correlation_id  text,
    _template_id     integer,
    _title           text default null,
    _description     text default null,
    _default_message text default null,
    _is_active       boolean default null,
    _request_context jsonb default null,
    _tenant_id       integer default 1
) returns void
    language plpgsql
as
$$
begin
    perform auth.has_permission(_user_id, _correlation_id, 'invitations.manage_templates', _tenant_id);

    perform unsecure.validate_invitation_template_in_tenant(_template_id, _tenant_id);

    perform unsecure.update_invitation_template(
        _updated_by, _user_id, _correlation_id, _template_id,
        _title, _description, _default_message, _is_active
    );
end;
$$;

create or replace function auth.delete_invitation_template(
    _deleted_by      text,
    _user_id         bigint,
    _correlation_id  text,
    _template_id     integer,
    _request_context jsonb default null,
    _tenant_id       integer default 1
) returns void
    language plpgsql
as
$$
begin
    perform auth.has_permission(_user_id, _correlation_id, 'invitations.manage_templates', _tenant_id);

    perform unsecure.validate_invitation_template_in_tenant(_template_id, _tenant_id);

    perform unsecure.delete_invitation_template(
        _deleted_by, _user_id, _correlation_id, _template_id
    );
end;
$$;

create or replace function auth.create_invitation_template(
    _created_by      text,
    _user_id         bigint,
    _correlation_id  text,
    _tenant_id       integer,
    _code            text,
    _title           text,
    _description     text default null,
    _default_message text default null,
    _actions         jsonb default '[]'::jsonb,
    _request_context jsonb default null
) returns table(__template_id integer)
    language plpgsql
as
$$
begin
    -- a global template (_tenant_id null) is managed from tenant 1
    perform auth.has_permission(_user_id, _correlation_id, 'invitations.manage_templates', coalesce(_tenant_id, 1));

    return query select * from unsecure.create_invitation_template(
        _created_by, _user_id, _correlation_id, _tenant_id, _code, _title,
        _description, _default_message, _actions
    );
end;
$$;

-- ----------------------------------------------------------------------------
-- MFA policies
-- ----------------------------------------------------------------------------

create or replace function auth.delete_mfa_policy(
    _deleted_by      text,
    _user_id         bigint,
    _correlation_id  text,
    _mfa_policy_id   bigint,
    _request_context jsonb default null,
    _tenant_id       integer default 1
) returns void
    language plpgsql
as
$$
declare
    __existing auth.mfa_policy;
begin
    perform
        auth.has_permission(_user_id, _correlation_id, 'mfa.mfa_policy.delete_mfa_policy', _tenant_id);

    perform unsecure.validate_mfa_policy_in_tenant(_mfa_policy_id, _tenant_id);

    -- Validate policy exists
    select mp.*
    from auth.mfa_policy mp
    where mp.mfa_policy_id = _mfa_policy_id
    into __existing;

    if __existing.mfa_policy_id is null then
        perform error.raise_38007(_mfa_policy_id);
    end if;

    -- Delete
    delete from auth.mfa_policy
    where mfa_policy_id = _mfa_policy_id;

    -- Log event
    perform unsecure.create_user_event(
        _deleted_by, _user_id, _correlation_id, 'mfa_policy_deleted',
        __existing.user_id,
        _request_context := _request_context,
        _event_data := jsonb_build_object(
            'mfa_policy_id', _mfa_policy_id,
            'tenant_id', __existing.tenant_id,
            'user_group_id', __existing.user_group_id,
            'user_id', __existing.user_id,
            'mfa_required', __existing.mfa_required
        )
    );
end;
$$;

create or replace function auth.create_mfa_policy(
    _created_by      text,
    _user_id         bigint,
    _correlation_id  text,
    _tenant_id       integer      default null,
    _user_group_id   integer      default null,
    _target_user_id  bigint       default null,
    _mfa_required    boolean      default true,
    _request_context jsonb        default null
) returns table (
    __mfa_policy_id bigint
)
    language plpgsql
as
$$
declare
    __last_item auth.mfa_policy;
begin
    -- a global policy (_tenant_id null) is managed from tenant 1
    perform
        auth.has_permission(_user_id, _correlation_id, 'mfa.mfa_policy.create_mfa_policy', coalesce(_tenant_id, 1));

    if _user_group_id is not null then
        perform unsecure.validate_user_group_in_tenant(_user_group_id, coalesce(_tenant_id, 1));
    end if;

    insert into auth.mfa_policy (created_by, updated_by, tenant_id, user_group_id, user_id, mfa_required)
    values (_created_by, _created_by, _tenant_id, _user_group_id, _target_user_id, _mfa_required)
    returning *
        into __last_item;

    -- Log event
    perform unsecure.create_user_event(
        _created_by, _user_id, _correlation_id, 'mfa_policy_created',
        _target_user_id,
        _request_context := _request_context,
        _event_data := jsonb_build_object(
            'mfa_policy_id', __last_item.mfa_policy_id,
            'tenant_id', _tenant_id,
            'user_group_id', _user_group_id,
            'target_user_id', _target_user_id,
            'mfa_required', _mfa_required
        )
    );

    return query
        select __last_item.mfa_policy_id;
end;
$$;

create or replace function auth.get_mfa_policies(
    _user_id         bigint,
    _correlation_id  text,
    _tenant_id       integer default null,
    _user_group_id   integer default null,
    _target_user_id  bigint  default null
) returns table (
    __mfa_policy_id  bigint,
    __tenant_id      integer,
    __user_group_id  integer,
    __user_id        bigint,
    __mfa_required   boolean,
    __created_at     timestamp with time zone,
    __created_by     text
)
    language plpgsql
as
$$
begin
    -- _tenant_id null lists every tenant's policies, so it is allowed from tenant 1 only
    perform
        auth.has_permission(_user_id, _correlation_id, 'mfa.mfa_policy.get_mfa_policies', coalesce(_tenant_id, 1));

    return query
        select mp.mfa_policy_id,
               mp.tenant_id,
               mp.user_group_id,
               mp.user_id,
               mp.mfa_required,
               mp.created_at,
               mp.created_by
        from auth.mfa_policy mp
        where (_tenant_id is null or mp.tenant_id = _tenant_id)
          and (_user_group_id is null or mp.user_group_id = _user_group_id)
          and (_target_user_id is null or mp.user_id = _target_user_id)
        order by mp.mfa_policy_id;
end;
$$;


select *
from public.stop_version_update('2.8', _component := 'postgresql_permissionmodel');
