/*
 * PostgreSQL Permissions Model — update v2.5
 * ==========================================
 *
 * Tenant lifecycle scoping (audit finding, domain 05):
 *
 *  - auth.delete_tenant / restore_tenant / purge_tenant checked the permission
 *    in the caller-supplied _tenant_id and then acted on any _tenant_uuid. The
 *    tenant_admin perm set (copied into every new tenant) holds the whole
 *    `tenants` node, and tenant-wide owners pass every check, so the admin or
 *    owner of any tenant could soft-delete and then purge every other tenant.
 *    Now:
 *      - delete_tenant: a tenant's own admin may soft-delete that tenant; any
 *        other tenant needs tenants.delete_tenant in tenant 1
 *      - restore_tenant, purge_tenant, create_tenant: permission in tenant 1 only
 *        (_tenant_id is kept for signature compatibility and no longer widens access)
 *      - update_tenant: changing is_removable or code also needs
 *        tenants.update_tenant in tenant 1
 *  - tenant_admin is rewritten from the whole `tenants` node to an explicit list
 *    without create/purge and the cross-tenant get_all_* / read_all_* permissions,
 *    in tenant 1 (the template create_tenant copies) and in every existing copy.
 */

set search_path = public, const, ext, stage, helpers, internal, unsecure, auth, triggers;

select *
from public.start_version_update('2.5', 'Tenant lifecycle scoping',
                                 _component := 'postgresql_permissionmodel',
                                 _description := 'delete/restore/purge/create_tenant authorize against tenant 1 (own-tenant soft delete allowed); update_tenant guards is_removable/code; tenant_admin perm set without lifecycle and cross-tenant permissions.');


/***
 *    ███████╗██╗   ██╗███╗   ██╗ ██████╗████████╗██╗ ██████╗ ███╗   ██╗███████╗
 *    ██╔════╝██║   ██║████╗  ██║██╔════╝╚══██╔══╝██║██╔═══██╗████╗  ██║██╔════╝
 *    █████╗  ██║   ██║██╔██╗ ██║██║        ██║   ██║██║   ██║██╔██╗ ██║███████╗
 *    ██╔══╝  ██║   ██║██║╚██╗██║██║        ██║   ██║██║   ██║██║╚██╗██║╚════██║
 *    ██║     ╚██████╔╝██║ ╚████║╚██████╗   ██║   ██║╚██████╔╝██║ ╚████║███████║
 *    ╚═╝      ╚═════╝ ╚═╝  ╚═══╝ ╚═════╝   ╚═╝   ╚═╝ ╚═════╝ ╚═╝  ╚═══╝╚══════╝
 *
 */

create or replace function auth.delete_tenant(_deleted_by text, _user_id bigint, _correlation_id text, _tenant_uuid uuid, _tenant_id integer DEFAULT 1)
    returns TABLE(__tenant_id integer, __uuid uuid, __code text)
    rows 1
    language plpgsql
as
$$
declare
    __t auth.tenant;
begin
    select * into __t from auth.tenant t where t.uuid = _tenant_uuid;
    if not found then
        perform error.raise_34003(_tenant_uuid::text);
    end if;

    -- A tenant's own admin may soft-delete that tenant; any other tenant needs the
    -- permission in tenant 1. The caller's _tenant_id never authorizes another tenant.
    if __t.tenant_id = _tenant_id then
        perform
            auth.has_permission(_user_id, _correlation_id, 'tenants.delete_tenant', _tenant_id);
    else
        perform
            auth.has_permission(_user_id, _correlation_id, 'tenants.delete_tenant', 1);
    end if;

    if __t.tenant_id = 1 or not __t.is_removable then
        perform error.raise_34007(__t.tenant_id);
    end if;

    if __t.deleted_at is not null then
        perform error.raise_34005(_tenant_uuid);
    end if;

    return query
        select dt.__tenant_id, dt.__uuid, dt.__code
        from unsecure.soft_delete_tenant(_deleted_by, _user_id, _correlation_id, __t.tenant_id) dt;
end;
$$;

create or replace function auth.restore_tenant(_restored_by text, _user_id bigint, _correlation_id text, _tenant_uuid uuid, _tenant_id integer DEFAULT 1)
    returns TABLE(__tenant_id integer, __uuid uuid, __code text)
    rows 1
    language plpgsql
as
$$
declare
    __t auth.tenant;
begin
    perform
        auth.has_permission(_user_id, _correlation_id, 'tenants.delete_tenant', 1);  -- tenant 1 only

    select * into __t from auth.tenant t where t.uuid = _tenant_uuid;
    if not found then
        perform error.raise_34003(_tenant_uuid::text);
    end if;

    if __t.deleted_at is null then
        perform error.raise_34006(_tenant_uuid);
    end if;

    return query
        select dt.__tenant_id, dt.__uuid, dt.__code
        from unsecure.restore_tenant(_restored_by, _user_id, _correlation_id, __t.tenant_id) dt;
end;
$$;

create or replace function auth.purge_tenant(_deleted_by text, _user_id bigint, _correlation_id text, _tenant_uuid uuid, _tenant_id integer DEFAULT 1)
    returns TABLE(__tenant_id integer, __uuid uuid, __code text)
    rows 1
    language plpgsql
as
$$
declare
    __t auth.tenant;
begin
    perform
        auth.has_permission(_user_id, _correlation_id, 'tenants.purge_tenant', 1);  -- tenant 1 only

    select * into __t from auth.tenant t where t.uuid = _tenant_uuid;
    if not found then
        perform error.raise_34003(_tenant_uuid::text);
    end if;

    if __t.tenant_id = 1 or not __t.is_removable then
        perform error.raise_34007(__t.tenant_id);
    end if;

    -- Two-step safety: a tenant must be soft-deleted before it can be purged
    if __t.deleted_at is null then
        perform error.raise_34006(_tenant_uuid);
    end if;

    return query
        select dt.__tenant_id, dt.__uuid, dt.__code
        from unsecure.delete_tenant(_deleted_by, _user_id, _correlation_id, __t.tenant_id) dt;
end;
$$;

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

	if
		(_tenant_owner_id is not null)
	then
		perform auth.create_owner(_created_by, _user_id, _correlation_id, _tenant_owner_id, null, _tenant_id := __last_item.tenant_id);
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

create or replace function auth.update_tenant(_created_by text, _user_id bigint, _correlation_id text, _tenant_id integer, _title text, _code text DEFAULT NULL::text, _is_removable boolean DEFAULT NULL::boolean, _is_assignable boolean DEFAULT NULL::boolean, _tenant_owner_id bigint DEFAULT NULL::bigint)
    returns TABLE(__tenant_id integer, __uuid uuid, __title text, __code text, __is_removable boolean, __is_assignable boolean, __access_type_code text, __is_default boolean)
    rows 1
    language plpgsql
as
$$
begin
	perform
		auth.has_permission(_user_id, _correlation_id, 'tenants.update_tenant', _tenant_id);

	-- is_removable and code are guarded by tenant 1: a tenant must not make itself
	-- undeletable or change its code past the identity ledger
	if exists(select
						from auth.tenant t
						where t.tenant_id = _tenant_id
							and ((_is_removable is not null and _is_removable is distinct from t.is_removable)
								or (_code is not null and _code is distinct from t.code))) then
		perform
			auth.has_permission(_user_id, _correlation_id, 'tenants.update_tenant', 1);
	end if;

	update auth.tenant
	set title         = _title
		, code          = coalesce(_code, code)
		, is_removable  = coalesce(_is_removable, is_removable)
		, is_assignable = coalesce(_is_assignable, is_assignable)
		, updated_by    = _created_by
		, updated_at    = now()
	where tenant_id = _tenant_id;

	perform public.create_journal_message_for_entity(_created_by, _user_id, _correlation_id
			, 11002  -- tenant_updated
			, 'tenant', _tenant_id
			, jsonb_build_object('tenant_title', _title, 'tenant_code', _code
				, 'is_assignable', _is_assignable, 'is_removable', _is_removable)
			, 1);

	if
		(_tenant_owner_id is not null)
	then
		perform auth.create_owner(_created_by, _user_id, _correlation_id, _tenant_owner_id, null, _tenant_id := _tenant_id);
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
		where tenant_id = _tenant_id;
end;
$$;

/***
 *    ██████╗ ███████╗██████╗ ███╗   ███╗    ███████╗███████╗████████╗███████╗
 *    ██╔══██╗██╔════╝██╔══██╗████╗ ████║    ██╔════╝██╔════╝╚══██╔══╝██╔════╝
 *    ██████╔╝█████╗  ██████╔╝██╔████╔██║    ███████╗█████╗     ██║   ███████╗
 *    ██╔═══╝ ██╔══╝  ██╔══██╗██║╚██╔╝██║    ╚════██║██╔══╝     ██║   ╚════██║
 *    ██║     ███████╗██║  ██║██║ ╚═╝ ██║    ███████║███████╗   ██║   ███████║
 *    ╚═╝     ╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝    ╚══════╝╚══════╝   ╚═╝   ╚══════╝
 *
 */

-- tenant_admin: replace the whole `tenants` node with an explicit list, in every
-- tenant. Both helpers invalidate the cache of users holding the set.
do $$
declare
    __ps record;
begin
    for __ps in
        select perm_set_id, tenant_id
        from auth.perm_set
        where code = 'tenant_admin'
    loop
        perform unsecure.delete_perm_set_permissions('update_v2.5', 1, null, __ps.perm_set_id
            , array ['tenants'], __ps.tenant_id);

        perform unsecure.create_perm_set_permissions('update_v2.5', 1, null, __ps.perm_set_id
            , array ['tenants.update_tenant', 'tenants.delete_tenant', 'tenants.get_tenants', 'tenants.read_tenants'
                , 'tenants.get_users', 'tenants.get_groups', 'tenants.assign_owner', 'tenants.assign_group_owner']
            , __ps.tenant_id);
    end loop;
end;
$$;


select *
from public.stop_version_update('2.5', _component := 'postgresql_permissionmodel');
