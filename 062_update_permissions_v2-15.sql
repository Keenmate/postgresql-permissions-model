/*
 * PostgreSQL Permissions Model — update v2.15
 * ===========================================
 *
 * Global operations need the permission in tenant 1 (audit decision D-07).
 *
 * Global objects were changed by checking the permission in whatever
 * _tenant_id the caller passed. A tenant admin or owner - who can build perm
 * sets in their own tenant and assign them to themselves - could therefore
 * create permissions, providers, resource types, token types and languages,
 * or disable the login provider for everyone. The permission is now checked
 * in tenant 1 for:
 *
 *  - the permission tree: create_permission, set_permission_as_assignable,
 *    ensure_permissions
 *  - providers: create/update/delete/enable/disable_provider, ensure_provider
 *    (which returned existing providers without any check)
 *  - resource types, roles and flags: create/update_resource_type,
 *    create/update/delete_resource_role, ensure_access_flags,
 *    ensure_resource_role_flags, ensure_resource_roles,
 *    ensure_resource_type_flags, ensure_resource_types
 *  - token types: create/update/delete_token_type
 *  - languages: create/update/delete_language (the language code is a global
 *    key; deleting a language deletes its translations in every tenant)
 *
 * Already tenant 1 since earlier versions: tenant lifecycle (2.5), global
 * MFA policies (2.8), blacklist and global user state (2.9). A null tenant
 * holds no permissions (2.8).
 *
 * System parameters and event codes had no real permission:
 *  - auth.update_sys_param allowed only user 1; it now needs
 *    system.update_sys_params (tenant 1).
 *  - public.create/delete_event_category / _event_code / _event_message had
 *    no check at all; they now need system.manage_event_codes (tenant 1).
 *  New permission node 'system' (both permissions), added to the system_admin
 *  and full_admin perm sets.
 *
 * Translations (D-02): update_translation / delete_translation accepted a
 * translation of any tenant - including tenant 1's, which everybody sees;
 * copy_translations wrote into any _to_tenant_id. The row must belong to
 * _tenant_id (37002), copies go into _tenant_id only (34002).
 *
 * Also: unsecure.set_permission_as_assignable by full code failed with
 * "operator does not exist: ltree = text".
 */

set search_path = public, const, ext, stage, helpers, internal, unsecure, auth, triggers;

select *
from public.start_version_update('2.15', 'Global operations need the permission in tenant 1',
                                 _component := 'postgresql_permissionmodel',
                                 _description := 'Permission tree, providers, resource types/roles/flags, token types and languages check the permission in tenant 1; system parameters and event codes need system.* permissions; translations validated against _tenant_id.');


/***
 *    ██████╗  █████╗ ████████╗ █████╗
 *    ██╔══██╗██╔══██╗╚══██╔══╝██╔══██╗
 *    ██║  ██║███████║   ██║   ███████║
 *    ██║  ██║██╔══██║   ██║   ██╔══██║
 *    ██████╔╝██║  ██║   ██║   ██║  ██║
 *    ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝
 *
 */

select unsecure.create_permission_as_system('System', '', false, _source := 'core')
where not exists(select from auth.permission where full_code = 'system');
select unsecure.create_permission_as_system('Update sys params', 'system', true, _source := 'core')
where not exists(select from auth.permission where full_code = 'system.update_sys_params');
select unsecure.create_permission_as_system('Manage event codes', 'system', true, _source := 'core')
where not exists(select from auth.permission where full_code = 'system.manage_event_codes');

select unsecure.create_perm_set_permissions('update_v2.15', 1, null, ps.perm_set_id
    , array ['system.update_sys_params', 'system.manage_event_codes'], 1)
from auth.perm_set ps
where ps.code in ('system_admin', 'full_admin')
  and ps.tenant_id = 1;


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
-- Global objects: permission tree, providers, resource types and roles, token types, languages
-- ----------------------------------------------------------------------------

create or replace function auth.create_permission(_created_by text, _user_id bigint, _correlation_id text, _title text, _parent_full_code text DEFAULT NULL::text, _is_assignable boolean DEFAULT true, _short_code text DEFAULT NULL::text, _source text DEFAULT NULL::text, _tenant_id integer DEFAULT 1)
    returns table(
        __created_at    timestamptz,
        __created_by    text,
        __updated_at    timestamptz,
        __updated_by    text,
        __permission_id integer,
        __is_assignable boolean,
        __code          text,
        __full_code     text,
        __node_path     text,
        __has_children  boolean,
        __short_code    text,
        __source        text
    )
    rows 1
    language plpgsql
as
$$
declare
	__last_id     int;
	__p           ext.ltree;
	__parent_id   int;
	__parent_path text;
begin

	perform
		auth.has_permission(_user_id, _correlation_id, 'permissions.create_permission', 1);  -- global object: permission in tenant 1 (D-07)

	return query
		select created_at, created_by, updated_at, updated_by, permission_id, is_assignable, code, full_code::text, node_path::text, has_children, short_code, source from unsecure.create_permission(_created_by, _user_id, _correlation_id, _title, _parent_full_code, _is_assignable, _short_code, _source);
end;
$$;

create or replace function auth.set_permission_as_assignable(_updated_by text, _user_id bigint, _correlation_id text, _permission_id integer DEFAULT NULL::integer, _permission_full_code text DEFAULT NULL::text, _is_assignable boolean DEFAULT true, _tenant_id integer DEFAULT 1)
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
		auth.has_permission(_user_id, _correlation_id, 'permissions.update_permission', 1);  -- global object: permission in tenant 1 (D-07)

	return query
		select created_at, created_by, assignment_id, tenant_id, user_group_id, user_id, perm_set_id, permission_id
		from unsecure.set_permission_as_assignable(_updated_by, _user_id, _correlation_id, _permission_id, _permission_full_code,
																							 _is_assignable);
end;
$$;

create or replace function auth.ensure_permissions(
    _created_by      text,
    _user_id         bigint,
    _correlation_id  text,
    _permissions     jsonb,
    _source          text    default null,
    _is_final_state  boolean default false,
    _tenant_id       integer default 1
)
    returns table(
        __created_at    timestamptz,
        __created_by    text,
        __updated_at    timestamptz,
        __updated_by    text,
        __permission_id integer,
        __is_assignable boolean,
        __code          text,
        __full_code     text,
        __node_path     text,
        __has_children  boolean,
        __short_code    text,
        __source        text
    )
    language plpgsql
as
$$
declare
    __item           jsonb;
    __title          text;
    __parent_code    text;
    __is_assignable  boolean;
    __short_code     text;
    __item_source    text;
    __code           text;
    __full_code      text;
    __full_codes     text[] := '{}';
    __perm_to_delete record;
begin
    -- Single permission check for the batch
    perform auth.has_permission(_user_id, _correlation_id, 'permissions.create_permission', 1);  -- global object: permission in tenant 1 (D-07)

    if _is_final_state then
        perform auth.has_permission(_user_id, _correlation_id, 'permissions.delete_permission', 1);  -- global object: permission in tenant 1 (D-07)

        if _source is null then
            raise exception '_source is required when _is_final_state is true';
        end if;
    end if;

    -- Process items sorted by hierarchy depth (parents before children)
    for __item in
        select value
        from jsonb_array_elements(_permissions)
        order by coalesce(ext.nlevel(ext.text2ltree(value ->> 'parent_code')), 0)
    loop
        __title         := __item ->> 'title';
        __parent_code   := __item ->> 'parent_code';
        __is_assignable := coalesce((__item ->> 'is_assignable')::boolean, true);
        __short_code    := __item ->> 'short_code';
        __item_source   := coalesce(__item ->> 'source', _source);
        __code          := helpers.get_code(__title, '_');

        -- Compute the full_code that would result
        if helpers.is_empty_string(__parent_code) then
            __full_code := __code;
        else
            __full_code := __parent_code || '.' || __code;
        end if;

        __full_codes := array_append(__full_codes, __full_code);

        -- Skip if already exists
        if exists (select 1 from auth.permission where full_code = __full_code::ext.ltree) then
            continue;
        end if;

        -- Delegate to unsecure.create_permission (handles node_path, full_code, short_code)
        perform unsecure.create_permission(
            _created_by, _user_id, _correlation_id,
            __title, __parent_code,
            __is_assignable, __short_code, __item_source
        );

        -- Store title as translation
        if helpers.is_not_empty_string(__title) then
            insert into public.translation (created_by, updated_by, language_code, data_group, data_object_code, context, value)
            values (_created_by, _created_by, 'en', 'permission', __full_code, 'title', __title)
            on conflict (language_code, data_group, data_object_code, context)
                where data_object_code is not null
            do update set value = excluded.value, updated_by = excluded.updated_by, updated_at = now();
            perform internal.refresh_translation_cache();
        end if;
    end loop;

    -- Final state: remove permissions with same source that are not in the input set
    if _is_final_state then
        for __perm_to_delete in
            select p.permission_id, p.full_code::text as full_code_text, p.node_path
            from auth.permission p
            where p.source = _source
              and p.full_code::text != all (__full_codes)
              -- also exclude descendants of input permissions (they may have different source)
              -- but include descendants of to-be-deleted permissions that share the same source
            order by ext.nlevel(p.node_path) desc  -- deepest first (children before parents)
        loop
            -- Skip if already deleted (as part of a parent deletion cascade)
            if not exists (select 1 from auth.permission where permission_id = __perm_to_delete.permission_id) then
                continue;
            end if;

            -- Clean up perm_set_perm references
            delete from auth.perm_set_perm where permission_id = __perm_to_delete.permission_id;

            -- Clean up permission_assignment references
            delete from auth.permission_assignment where permission_id = __perm_to_delete.permission_id;

            -- Delete the permission itself
            delete from auth.permission where permission_id = __perm_to_delete.permission_id;

            -- Journal the removal
            perform public.create_journal_message_for_entity(
                _created_by, _user_id, _correlation_id,
                12003,  -- permission_deleted
                'permission', __perm_to_delete.permission_id,
                jsonb_build_object('permission_code', __perm_to_delete.full_code_text,
                    'reason', 'final_state_sync', 'source', _source),
                1
            );
        end loop;

        -- Update has_children flags for parents that may have lost children
        update auth.permission p
        set has_children = exists (
            select 1 from auth.permission c
            where c.node_path <@ p.node_path
              and c.node_path != p.node_path
        )
        where p.full_code::text = any (__full_codes);
    end if;

    -- Return all processed permissions (existing + newly created)
    return query
        select p.created_at, p.created_by, p.updated_at, p.updated_by, p.permission_id, p.is_assignable, p.code, p.full_code::text, p.node_path::text, p.has_children, p.short_code, p.source
        from auth.permission p
        where p.full_code::text = any (__full_codes)
        order by p.full_code;
end;
$$;

create or replace function auth.create_provider(_created_by text, _user_id bigint, _correlation_id text, _provider_code text, _provider_name text, _is_active boolean DEFAULT true, _allows_group_mapping boolean default false, _allows_group_sync boolean default false, _tenant_id integer default 1)
    returns TABLE(__provider_id integer)
    rows 1
    language plpgsql
as
$$
declare
	__last_id int;
begin

	perform
		auth.has_permission(_user_id, _correlation_id, 'providers.create_provider', 1);  -- global object: permission in tenant 1 (D-07)

	insert into auth.provider (created_by, updated_by, code, is_active, allows_group_mapping, allows_group_sync)
	values (_created_by, _created_by, _provider_code, _is_active, _allows_group_mapping, _allows_group_sync)
	returning provider_id
		into __last_id;

	-- Store provider name as translation
	if _provider_name is not null then
		insert into public.translation (created_by, updated_by, language_code, data_group, data_object_code, context, value)
		values (_created_by, _created_by, 'en', 'provider', _provider_code, 'title', _provider_name)
		on conflict (language_code, data_group, data_object_code, context)
			where data_object_code is not null
		do update set value = excluded.value, updated_by = excluded.updated_by, updated_at = now();

		perform internal.refresh_translation_cache();
	end if;

	return query
		select __last_id;

	perform public.create_journal_message_for_entity(_created_by, _user_id, _correlation_id
			, 16001  -- provider_created
			, 'provider', __last_id
			, jsonb_build_object('provider_code', _provider_code, 'provider_name', _provider_name
				, 'is_active', _is_active
				, 'allows_group_mapping', _allows_group_mapping, 'allows_group_sync', _allows_group_sync)
			, 1);
end;
$$;

create or replace function auth.update_provider(_updated_by text, _user_id bigint, _correlation_id text, _provider_id integer, _provider_code text, _provider_name text, _is_active boolean DEFAULT true, _allows_group_mapping boolean default false, _allows_group_sync boolean default false, _tenant_id integer default 1)
    returns TABLE(__provider_id integer)
    rows 1
    language plpgsql
as
$$
declare
begin

	perform
		auth.has_permission(_user_id, _correlation_id, 'providers.update_provider', 1);  -- global object: permission in tenant 1 (D-07)

	return query
		update auth.provider
			set updated_at = now(),
				updated_by = _updated_by, code = _provider_code, is_active = _is_active,
				allows_group_mapping = _allows_group_mapping, allows_group_sync = _allows_group_sync
			where provider_id = _provider_id
			returning provider_id;

	-- Upsert provider name as translation
	if _provider_name is not null then
		insert into public.translation (created_by, updated_by, language_code, data_group, data_object_code, context, value)
		values (_updated_by, _updated_by, 'en', 'provider', _provider_code, 'title', _provider_name)
		on conflict (language_code, data_group, data_object_code, context)
			where data_object_code is not null
		do update set value = excluded.value, updated_by = excluded.updated_by, updated_at = now();

		perform internal.refresh_translation_cache();
	end if;

	perform public.create_journal_message_for_entity(_updated_by, _user_id, _correlation_id
			, 16002  -- provider_updated
			, 'provider', _provider_id
			, jsonb_build_object('provider_code', _provider_code, 'provider_name', _provider_name
				, 'is_active', _is_active
				, 'allows_group_mapping', _allows_group_mapping, 'allows_group_sync', _allows_group_sync)
			, 1);
end;
$$;

create or replace function auth.delete_provider(_deleted_by text, _user_id bigint, _correlation_id text, _provider_code text, _tenant_id integer default 1)
    returns TABLE(__provider_id integer)
    rows 1
    language plpgsql
as
$$
declare
	___provider_id int;
begin

	perform
		auth.has_permission(_user_id, _correlation_id, 'providers.delete_provider', 1);  -- global object: permission in tenant 1 (D-07)

	delete
		from auth.provider
			where code = _provider_code
			returning provider_id
				into ___provider_id;

	return query
		select ___provider_id;

	perform public.create_journal_message_for_entity(_deleted_by, _user_id, _correlation_id
			, 16003  -- provider_deleted
			, 'provider', ___provider_id
			, jsonb_build_object('provider_code', _provider_code)
			, 1);
end;
$$;

create or replace function auth.enable_provider(_updated_by text, _user_id bigint, _correlation_id text, _provider_code text, _tenant_id integer default 1)
    returns TABLE(__provider_id integer)
    rows 1
    language plpgsql
as
$$
declare
	___provider_id int;
begin

	perform
		auth.has_permission(_user_id, _correlation_id, 'providers.update_provider', 1);  -- global object: permission in tenant 1 (D-07)

	update auth.provider
		set is_active = true
		where code = _provider_code
		returning provider_id
			into ___provider_id;

	return query
		select ___provider_id;

	perform public.create_journal_message_for_entity(_updated_by, _user_id, _correlation_id
			, 16004  -- provider_enabled
			, 'provider', ___provider_id
			, jsonb_build_object('provider_code', _provider_code)
			, 1);
end;
$$;

create or replace function auth.disable_provider(_updated_by text, _user_id bigint, _correlation_id text, _provider_code text, _tenant_id integer default 1)
    returns TABLE(__provider_id integer)
    rows 1
    language plpgsql
as
$$
declare
	___provider_id int;
begin

	perform
		auth.has_permission(_user_id, _correlation_id, 'providers.update_provider', 1);  -- global object: permission in tenant 1 (D-07)

	update auth.provider
		set is_active = false
		where code = _provider_code
		returning provider_id
			into ___provider_id;

	return query
		select ___provider_id;

	perform public.create_journal_message_for_entity(_updated_by, _user_id, _correlation_id
			, 16005  -- provider_disabled
			, 'provider', ___provider_id
			, jsonb_build_object('provider_code', _provider_code)
			, 1);
end;
$$;

create or replace function auth.create_resource_type(
    _created_by   text,
    _user_id      bigint,
    _correlation_id text,
    _code         text,
    _title        text,
    _description  text default null,
    _tenant_id    integer default 1,
    _source       text default null,
    _key_schema   jsonb default '{}'::jsonb,
    _access_flags text[] default null,
    _language_code text default 'en'
) returns table(
    __code         text,
    __title        text,
    __full_title   text,
    __description  text,
    __is_active    boolean,
    __source       text,
    __path         text,
    __key_schema   jsonb,
    __access_flags text[]
)
    language plpgsql
as
$$
declare
    ___path ext.ltree;
    __flag text;
begin
    perform auth.has_permission(_user_id, _correlation_id, 'resources.create_resource_type', 1);  -- global object: permission in tenant 1 (D-07)

    if _access_flags is not null then
        perform unsecure.validate_access_flags(_access_flags);
    end if;

    ___path := ext.text2ltree(_code);

    insert into const.resource_type (code, source, path, key_schema)
    values (_code, _source, ___path, coalesce(_key_schema, '{}'::jsonb))
    on conflict do nothing;

    -- Translations for title + description
    if _title is not null then
        insert into public.translation (created_by, updated_by, language_code, data_group, data_object_code, context, value)
        values (_created_by, _created_by, _language_code, 'resource_type', _code, 'title', _title)
        on conflict do nothing;
    end if;
    if _description is not null then
        insert into public.translation (created_by, updated_by, language_code, data_group, data_object_code, context, value)
        values (_created_by, _created_by, _language_code, 'resource_type', _code, 'description', _description)
        on conflict do nothing;
    end if;

    -- Recompute full_title for this type and all descendants
    perform unsecure.update_resource_type_full_title_translations(___path, _language_code, _created_by);

    if _access_flags is not null then
        foreach __flag in array _access_flags
        loop
            insert into const.resource_type_flag (resource_type_code, access_flag_code)
            values (_code, __flag) on conflict do nothing;
        end loop;
    end if;

    perform unsecure.ensure_resource_access_partition(_code);

    return query
        select rt.code,
               coalesce((select mv.values->>'title' from public.mv_translation mv where mv.data_group = 'resource_type' and mv.data_object_code = rt.code and mv.language_code = _language_code), rt.code),
               (select mv.values->>'full_title' from public.mv_translation mv where mv.data_group = 'resource_type' and mv.data_object_code = rt.code and mv.language_code = _language_code),
               (select mv.values->>'description' from public.mv_translation mv where mv.data_group = 'resource_type' and mv.data_object_code = rt.code and mv.language_code = _language_code),
               rt.is_active, rt.source, rt.path::text, rt.key_schema,
               (select array_agg(rtf.access_flag_code order by rtf.access_flag_code)
                from const.resource_type_flag rtf where rtf.resource_type_code = rt.code)
        from const.resource_type rt where rt.code = _code;

    perform public.create_journal_message_for_entity(_created_by, _user_id, _correlation_id
        , 18001, 'resource_type', 0
        , jsonb_build_object('resource_type', _code, 'title', _title,
            'key_schema', _key_schema, 'access_flags', _access_flags)
        , _tenant_id);
end;
$$;

create or replace function auth.update_resource_type(
    _updated_by     text,
    _user_id        bigint,
    _correlation_id text,
    _code           text,
    _title          text    default null,
    _description    text    default null,
    _is_active      boolean default null,
    _source         text    default null,
    _tenant_id      integer default 1,
    _language_code  text    default 'en'
) returns table(
    __code         text,
    __title        text,
    __full_title   text,
    __description  text,
    __is_active    boolean,
    __source       text,
    __path         text,
    __key_schema   jsonb,
    __access_flags text[]
)
    language plpgsql
as
$$
declare
    ___path ext.ltree;
begin
    perform auth.has_permission(_user_id, _correlation_id, 'resources.create_resource_type', 1);  -- global object: permission in tenant 1 (D-07)

    if not exists (select 1 from const.resource_type where code = _code) then
        perform error.raise_35003(_code);
    end if;

    select path from const.resource_type where code = _code into ___path;

    update const.resource_type
    set is_active = coalesce(_is_active, is_active),
        source    = coalesce(_source, source)
    where code = _code;

    -- Upsert translations
    if _title is not null then
        insert into public.translation (created_by, updated_by, language_code, data_group, data_object_code, context, value)
        values (_updated_by, _updated_by, _language_code, 'resource_type', _code, 'title', _title)
        on conflict (language_code, data_group, data_object_code, context)
            where data_object_code is not null
        do update set value = excluded.value, updated_by = excluded.updated_by, updated_at = now();

        -- Recompute full_title for this type and all descendants
        perform unsecure.update_resource_type_full_title_translations(___path, _language_code, _updated_by);
    end if;
    if _description is not null then
        insert into public.translation (created_by, updated_by, language_code, data_group, data_object_code, context, value)
        values (_updated_by, _updated_by, _language_code, 'resource_type', _code, 'description', _description)
        on conflict (language_code, data_group, data_object_code, context)
            where data_object_code is not null
        do update set value = excluded.value, updated_by = excluded.updated_by, updated_at = now();
    end if;

    return query
        select rt.code,
               coalesce((select mv.values->>'title' from public.mv_translation mv where mv.data_group = 'resource_type' and mv.data_object_code = rt.code and mv.language_code = _language_code), rt.code),
               (select mv.values->>'full_title' from public.mv_translation mv where mv.data_group = 'resource_type' and mv.data_object_code = rt.code and mv.language_code = _language_code),
               (select mv.values->>'description' from public.mv_translation mv where mv.data_group = 'resource_type' and mv.data_object_code = rt.code and mv.language_code = _language_code),
               rt.is_active, rt.source, rt.path::text, rt.key_schema,
               (select array_agg(rtf.access_flag_code order by rtf.access_flag_code)
                from const.resource_type_flag rtf where rtf.resource_type_code = rt.code)
        from const.resource_type rt where rt.code = _code;

    perform public.create_journal_message_for_entity(_updated_by, _user_id, _correlation_id
        , 18002, 'resource_type', 0
        , jsonb_build_object('resource_type', _code, 'title', _title, 'is_active', _is_active)
        , _tenant_id);
end;
$$;

create or replace function auth.create_resource_role(
    _created_by     text,
    _user_id        bigint,
    _correlation_id text,
    _code           text,
    _resource_type  text,
    _title          text,
    _description    text    default null,
    _access_flags   text[]  default null,
    _source         text    default null,
    _tenant_id      integer default 1,
    _language_code  text    default 'en'
) returns table(
    __code          text,
    __resource_type text,
    __title         text,
    __description   text,
    __is_active     boolean,
    __source        text,
    __access_flags  text[]
)
    language plpgsql
as
$$
declare
    __flag text;
begin
    perform auth.has_permission(_user_id, _correlation_id, 'resources.create_resource_type', 1);  -- global object: permission in tenant 1 (D-07)
    perform unsecure.validate_resource_type(_resource_type);

    if _access_flags is not null then
        perform unsecure.validate_access_flags(_access_flags);
        perform unsecure.validate_role_flags_for_type(_code, _resource_type, _access_flags);
    end if;

    insert into const.resource_role (code, resource_type, source)
    values (_code, _resource_type, _source)
    on conflict do nothing;

    -- Translations
    if _title is not null then
        insert into public.translation (created_by, updated_by, language_code, data_group, data_object_code, context, value)
        values (_created_by, _created_by, _language_code, 'resource_role', _code, 'title', _title)
        on conflict do nothing;
    end if;
    if _description is not null then
        insert into public.translation (created_by, updated_by, language_code, data_group, data_object_code, context, value)
        values (_created_by, _created_by, _language_code, 'resource_role', _code, 'description', _description)
        on conflict do nothing;
    end if;

    if _access_flags is not null then
        foreach __flag in array _access_flags
        loop
            insert into const.resource_role_flag (resource_role_code, access_flag_code)
            values (_code, __flag) on conflict do nothing;
        end loop;
    end if;

    perform internal.refresh_translation_cache();

    return query
        select r.code, r.resource_type,
               coalesce((select mv.values->>'title' from public.mv_translation mv where mv.data_group = 'resource_role' and mv.data_object_code = r.code and mv.language_code = _language_code), r.code),
               (select mv.values->>'description' from public.mv_translation mv where mv.data_group = 'resource_role' and mv.data_object_code = r.code and mv.language_code = _language_code),
               r.is_active, r.source,
               (select array_agg(rrf.access_flag_code order by rrf.access_flag_code)
                from const.resource_role_flag rrf where rrf.resource_role_code = r.code)
        from const.resource_role r where r.code = _code;

    perform public.create_journal_message_for_entity(_created_by, _user_id, _correlation_id
        , 18003, 'resource_role', 0
        , jsonb_build_object('role_code', _code, 'resource_type', _resource_type,
            'title', _title, 'access_flags', _access_flags, 'source', _source)
        , _tenant_id);
end;
$$;

create or replace function auth.update_resource_role(
    _updated_by     text,
    _user_id        bigint,
    _correlation_id text,
    _code           text,
    _title          text    default null,
    _description    text    default null,
    _is_active      boolean default null,
    _source         text    default null,
    _tenant_id      integer default 1,
    _language_code  text    default 'en'
) returns table(
    __code          text,
    __resource_type text,
    __title         text,
    __description   text,
    __is_active     boolean,
    __source        text,
    __access_flags  text[]
)
    language plpgsql
as
$$
begin
    perform auth.has_permission(_user_id, _correlation_id, 'resources.create_resource_type', 1);  -- global object: permission in tenant 1 (D-07)

    if not exists (select 1 from const.resource_role where code = _code) then
        perform error.raise_35007(_code);
    end if;

    update const.resource_role
    set is_active = coalesce(_is_active, is_active),
        source    = coalesce(_source, source)
    where code = _code;

    if _title is not null then
        insert into public.translation (created_by, updated_by, language_code, data_group, data_object_code, context, value)
        values (_updated_by, _updated_by, _language_code, 'resource_role', _code, 'title', _title)
        on conflict (language_code, data_group, data_object_code, context)
            where data_object_code is not null
        do update set value = excluded.value, updated_by = excluded.updated_by, updated_at = now();
    end if;
    if _description is not null then
        insert into public.translation (created_by, updated_by, language_code, data_group, data_object_code, context, value)
        values (_updated_by, _updated_by, _language_code, 'resource_role', _code, 'description', _description)
        on conflict (language_code, data_group, data_object_code, context)
            where data_object_code is not null
        do update set value = excluded.value, updated_by = excluded.updated_by, updated_at = now();
    end if;

    perform internal.refresh_translation_cache();

    return query
        select r.code, r.resource_type,
               coalesce((select mv.values->>'title' from public.mv_translation mv where mv.data_group = 'resource_role' and mv.data_object_code = r.code and mv.language_code = _language_code), r.code),
               (select mv.values->>'description' from public.mv_translation mv where mv.data_group = 'resource_role' and mv.data_object_code = r.code and mv.language_code = _language_code),
               r.is_active, r.source,
               (select array_agg(rrf.access_flag_code order by rrf.access_flag_code)
                from const.resource_role_flag rrf where rrf.resource_role_code = r.code)
        from const.resource_role r where r.code = _code;

    perform public.create_journal_message_for_entity(_updated_by, _user_id, _correlation_id
        , 18004, 'resource_role', 0
        , jsonb_build_object('role_code', _code, 'title', _title, 'is_active', _is_active)
        , _tenant_id);
end;
$$;

create or replace function auth.delete_resource_role(
    _deleted_by     text,
    _user_id        bigint,
    _correlation_id text,
    _code           text,
    _tenant_id      integer default 1
) returns bigint
    language plpgsql
as
$$
declare
    __deleted_count bigint;
begin
    perform auth.has_permission(_user_id, _correlation_id, 'resources.create_resource_type', 1);  -- global object: permission in tenant 1 (D-07)

    if not exists (select 1 from const.resource_role where code = _code) then
        perform error.raise_35007(_code);
    end if;

    delete from const.resource_role where code = _code;
    get diagnostics __deleted_count = row_count;

    perform public.create_journal_message_for_entity(_deleted_by, _user_id, _correlation_id
        , 18005  -- resource_role_deleted
        , 'resource_role', 0
        , jsonb_build_object('role_code', _code)
        , _tenant_id);

    return __deleted_count;
end;
$$;

create or replace function auth.ensure_access_flags(
    _created_by     text,
    _user_id        bigint,
    _correlation_id text,
    _flags          jsonb,
    _source         text    default null,
    _tenant_id      integer default 1,
    _language_code  text    default 'en'
) returns table(__code text, __title text, __source text)
    language plpgsql
as
$$
declare
    __item jsonb;
    ___code text;
    ___title text;
    __item_source text;
begin
    perform auth.has_permission(_user_id, _correlation_id, 'resources.create_resource_type', 1);  -- global object: permission in tenant 1 (D-07)

    for __item in select value from jsonb_array_elements(_flags)
    loop
        ___code        := __item->>'code';
        ___title       := __item->>'title';
        __item_source := coalesce(__item->>'source', _source);

        if ___code is null or ___title is null then
            raise exception 'Access flag requires both "code" and "title" fields'
                using errcode = '35004';
        end if;

        insert into const.resource_access_flag (code, source)
        values (___code, __item_source)
        on conflict do nothing;

        insert into public.translation (created_by, updated_by, language_code, data_group, data_object_code, context, value)
        values (_created_by, _created_by, _language_code, 'resource_access_flag', ___code, 'title', ___title)
        on conflict (language_code, data_group, data_object_code, context)
            where data_object_code is not null
        do update set value = excluded.value, updated_by = excluded.updated_by, updated_at = now();
    end loop;

    perform internal.refresh_translation_cache();

    return query
    select f.code,
           coalesce((select mv.values->>'title' from public.mv_translation mv where mv.data_group = 'resource_access_flag' and mv.data_object_code = f.code and mv.language_code = _language_code), f.code),
           f.source
    from const.resource_access_flag f
    where f.code in (select value->>'code' from jsonb_array_elements(_flags))
    order by f.code;
end;
$$;

create or replace function auth.ensure_resource_role_flags(
    _updated_by     text,
    _user_id        bigint,
    _correlation_id text,
    _role_code      text,
    _access_flags   text[],
    _tenant_id      integer default 1
) returns table(__resource_role_code text, __access_flag_code text)
    language plpgsql
as
$$
declare
    __flag          text;
    __resource_type text;
begin
    perform auth.has_permission(_user_id, _correlation_id, 'resources.create_resource_type', 1);  -- global object: permission in tenant 1 (D-07)

    -- Null = no-op
    if _access_flags is null then
        return query
        select rrf.resource_role_code, rrf.access_flag_code
        from const.resource_role_flag rrf
        where rrf.resource_role_code = _role_code
        order by rrf.access_flag_code;
        return;
    end if;

    -- Validate role exists
    if not exists (select 1 from const.resource_role where code = _role_code) then
        perform error.raise_35007(_role_code);
    end if;

    -- Resolve resource_type for per-type flag validation
    select resource_type from const.resource_role where code = _role_code into __resource_type;

    -- Validate all flags exist globally
    if array_length(_access_flags, 1) > 0 then
        perform unsecure.validate_access_flags(_access_flags);
        perform unsecure.validate_role_flags_for_type(_role_code, __resource_type, _access_flags);
    end if;

    -- Remove flags not in the new list
    delete from const.resource_role_flag
    where resource_role_code = _role_code
      and access_flag_code != all(_access_flags);

    -- Add missing flags
    foreach __flag in array _access_flags
    loop
        insert into const.resource_role_flag (resource_role_code, access_flag_code)
        values (_role_code, __flag)
        on conflict do nothing;
    end loop;

    -- Journal
    perform public.create_journal_message_for_entity(_updated_by, _user_id, _correlation_id
        , 18004  -- resource_role_updated
        , 'resource_role', 0
        , jsonb_build_object('role_code', _role_code, 'access_flags', _access_flags)
        , _tenant_id);

    return query
    select rrf.resource_role_code, rrf.access_flag_code
    from const.resource_role_flag rrf
    where rrf.resource_role_code = _role_code
    order by rrf.access_flag_code;
end;
$$;

create or replace function auth.ensure_resource_roles(
    _created_by     text,
    _user_id        bigint,
    _correlation_id text,
    _roles          jsonb,
    _source         text    default null,
    _is_final_state boolean default false,
    _tenant_id      integer default 1,
    _language_code  text    default 'en'
) returns table(
    __code          text,
    __resource_type text,
    __title         text,
    __description   text,
    __is_active     boolean,
    __source        text,
    __access_flags  text[]
)
    language plpgsql
as
$$
declare
    __item          jsonb;
    ___code          text;
    __res_type      text;
    ___title         text;
    __desc          text;
    __item_source   text;
    ___access_flags  text[];
    __flag          text;
    __existing_code text;
begin
    perform auth.has_permission(_user_id, _correlation_id, 'resources.create_resource_type', 1);  -- global object: permission in tenant 1 (D-07)

    for __item in select value from jsonb_array_elements(_roles)
    loop
        ___code       := __item->>'code';
        __res_type   := __item->>'resource_type';
        ___title      := __item->>'title';
        __desc       := __item->>'description';
        __item_source := coalesce(__item->>'source', _source);

        if __item ? 'access_flags' and __item->'access_flags' is not null then
            select array_agg(f.value::text)
            from jsonb_array_elements_text(__item->'access_flags') as f(value)
            into ___access_flags;
        else
            ___access_flags := null;
        end if;

        perform unsecure.validate_resource_type(__res_type);

        if ___access_flags is not null then
            perform unsecure.validate_access_flags(___access_flags);
            perform unsecure.validate_role_flags_for_type(___code, __res_type, ___access_flags);
        end if;

        if exists (select 1 from const.resource_role where code = ___code) then
            update const.resource_role
            set source    = coalesce(__item_source, source),
                is_active = true
            where code = ___code;
        else
            insert into const.resource_role (code, resource_type, source)
            values (___code, __res_type, __item_source);
        end if;

        -- Translations (upsert)
        if ___title is not null then
            insert into public.translation (created_by, updated_by, language_code, data_group, data_object_code, context, value)
            values (_created_by, _created_by, _language_code, 'resource_role', ___code, 'title', ___title)
            on conflict (language_code, data_group, data_object_code, context)
                where data_object_code is not null
            do update set value = excluded.value, updated_by = excluded.updated_by, updated_at = now();
        end if;
        if __desc is not null then
            insert into public.translation (created_by, updated_by, language_code, data_group, data_object_code, context, value)
            values (_created_by, _created_by, _language_code, 'resource_role', ___code, 'description', __desc)
            on conflict (language_code, data_group, data_object_code, context)
                where data_object_code is not null
            do update set value = excluded.value, updated_by = excluded.updated_by, updated_at = now();
        end if;

        if ___access_flags is not null then
            delete from const.resource_role_flag
            where resource_role_code = ___code and access_flag_code != all(___access_flags);
            foreach __flag in array ___access_flags
            loop
                insert into const.resource_role_flag (resource_role_code, access_flag_code)
                values (___code, __flag) on conflict do nothing;
            end loop;
        end if;

        perform public.create_journal_message_for_entity(_created_by, _user_id, _correlation_id
            , 18003, 'resource_role', 0
            , jsonb_build_object('role_code', ___code, 'resource_type', __res_type,
                'title', ___title, 'access_flags', ___access_flags)
            , _tenant_id);
    end loop;

    if _is_final_state and _source is not null then
        for __existing_code in
            select r.code from const.resource_role r
            where r.source = _source and r.is_active = true
              and r.code not in (select value->>'code' from jsonb_array_elements(_roles))
        loop
            update const.resource_role set is_active = false where code = __existing_code;
        end loop;
    end if;

    perform internal.refresh_translation_cache();

    return query
        select r.code, r.resource_type,
               coalesce((select mv.values->>'title' from public.mv_translation mv where mv.data_group = 'resource_role' and mv.data_object_code = r.code and mv.language_code = _language_code), r.code),
               (select mv.values->>'description' from public.mv_translation mv where mv.data_group = 'resource_role' and mv.data_object_code = r.code and mv.language_code = _language_code),
               r.is_active, r.source,
               (select array_agg(rrf.access_flag_code order by rrf.access_flag_code)
                from const.resource_role_flag rrf where rrf.resource_role_code = r.code)
        from const.resource_role r
        where r.code in (select value->>'code' from jsonb_array_elements(_roles))
        order by r.resource_type, r.code;
end;
$$;

create or replace function auth.ensure_resource_type_flags(
    _created_by     text,
    _user_id        bigint,
    _correlation_id text,
    _resource_type  text,
    _access_flags   text[],
    _tenant_id      integer default 1
) returns table(__resource_type_code text, __access_flag_code text)
    language plpgsql
as
$$
declare
    __flag text;
begin
    perform auth.has_permission(_user_id, _correlation_id, 'resources.create_resource_type', 1);  -- global object: permission in tenant 1 (D-07)

    if _access_flags is null then
        return query
        select rtf.resource_type_code, rtf.access_flag_code
        from const.resource_type_flag rtf
        where rtf.resource_type_code = _resource_type
        order by rtf.access_flag_code;
        return;
    end if;

    if not exists (select 1 from const.resource_type where code = _resource_type) then
        perform error.raise_35003(_resource_type);
    end if;

    if array_length(_access_flags, 1) > 0 then
        perform unsecure.validate_access_flags(_access_flags);
    end if;

    delete from const.resource_type_flag
    where resource_type_code = _resource_type
      and access_flag_code != all(_access_flags);

    foreach __flag in array _access_flags
    loop
        insert into const.resource_type_flag (resource_type_code, access_flag_code)
        values (_resource_type, __flag)
        on conflict do nothing;
    end loop;

    return query
    select rtf.resource_type_code, rtf.access_flag_code
    from const.resource_type_flag rtf
    where rtf.resource_type_code = _resource_type
    order by rtf.access_flag_code;
end;
$$;

create or replace function auth.ensure_resource_types(
    _created_by     text,
    _user_id        bigint,
    _correlation_id text,
    _resource_types jsonb,
    _source         text    default null,
    _tenant_id      integer default 1,
    _language_code  text    default 'en'
) returns table(
    __code         text,
    __title        text,
    __full_title   text,
    __description  text,
    __is_active    boolean,
    __source       text,
    __path         text,
    __key_schema   jsonb,
    __access_flags text[]
)
    language plpgsql
as
$$
declare
    __item          jsonb;
    ___code          text;
    ___title         text;
    ___description   text;
    __item_source   text;
    ___key_schema    jsonb;
    ___access_flags  text[];
    __flag          text;
    ___path          ext.ltree;
begin
    perform auth.has_permission(_user_id, _correlation_id, 'resources.create_resource_type', 1);  -- global object: permission in tenant 1 (D-07)

    for __item in
        select value from jsonb_array_elements(_resource_types)
        order by ext.nlevel(ext.text2ltree(value->>'code'))
    loop
        ___code        := __item->>'code';
        ___title       := __item->>'title';
        ___description := __item->>'description';
        __item_source := coalesce(__item->>'source', _source);
        ___key_schema  := coalesce(__item->'key_schema', '{}'::jsonb);
        ___path        := ext.text2ltree(___code);

        if __item ? 'access_flags' and __item->'access_flags' is not null then
            select array_agg(f.value::text)
            from jsonb_array_elements_text(__item->'access_flags') as f(value)
            into ___access_flags;
        else
            ___access_flags := null;
        end if;

        if not exists (select 1 from const.resource_type where code = ___code) then
            if ___access_flags is not null then
                perform unsecure.validate_access_flags(___access_flags);
            end if;

            insert into const.resource_type (code, source, path, key_schema)
            values (___code, __item_source, ___path, ___key_schema)
            on conflict do nothing;
        end if;

        -- Translations (upsert)
        if ___title is not null then
            insert into public.translation (created_by, updated_by, language_code, data_group, data_object_code, context, value)
            values (_created_by, _created_by, _language_code, 'resource_type', ___code, 'title', ___title)
            on conflict (language_code, data_group, data_object_code, context)
                where data_object_code is not null
            do update set value = excluded.value, updated_by = excluded.updated_by, updated_at = now();
        end if;
        if ___description is not null then
            insert into public.translation (created_by, updated_by, language_code, data_group, data_object_code, context, value)
            values (_created_by, _created_by, _language_code, 'resource_type', ___code, 'description', ___description)
            on conflict (language_code, data_group, data_object_code, context)
                where data_object_code is not null
            do update set value = excluded.value, updated_by = excluded.updated_by, updated_at = now();
        end if;

        -- Recompute full_title for this type and all descendants
        perform unsecure.update_resource_type_full_title_translations(___path, _language_code, _created_by);

        if ___access_flags is not null then
            foreach __flag in array ___access_flags
            loop
                insert into const.resource_type_flag (resource_type_code, access_flag_code)
                values (___code, __flag) on conflict do nothing;
            end loop;
        end if;

        perform unsecure.ensure_resource_access_partition(___code);

        perform public.create_journal_message_for_entity(_created_by, _user_id, _correlation_id
            , 18001, 'resource_type', 0
            , jsonb_build_object('resource_type', ___code, 'title', ___title,
                'key_schema', ___key_schema, 'access_flags', ___access_flags)
            , _tenant_id);
    end loop;

    return query
        select rt.code,
               coalesce((select mv.values->>'title' from public.mv_translation mv where mv.data_group = 'resource_type' and mv.data_object_code = rt.code and mv.language_code = _language_code), rt.code),
               (select mv.values->>'full_title' from public.mv_translation mv where mv.data_group = 'resource_type' and mv.data_object_code = rt.code and mv.language_code = _language_code),
               (select mv.values->>'description' from public.mv_translation mv where mv.data_group = 'resource_type' and mv.data_object_code = rt.code and mv.language_code = _language_code),
               rt.is_active, rt.source, rt.path::text, rt.key_schema,
               (select array_agg(rtf.access_flag_code order by rtf.access_flag_code)
                from const.resource_type_flag rtf where rtf.resource_type_code = rt.code)
        from const.resource_type rt
        where rt.code in (select value->>'code' from jsonb_array_elements(_resource_types))
        order by rt.path;
end;
$$;

create or replace function public.create_token_type(
    _created_by text,
    _user_id bigint,
    _correlation_id text,
    _code text,
    _default_expiration_in_seconds integer default null,
    _tenant_id integer default 1
) returns table(
    __code                          text,
    __default_expiration_in_seconds integer,
    __is_system                     boolean
)
    rows 1
    language plpgsql
as
$$
begin
    perform auth.has_permission(_user_id, _correlation_id, 'token_configuration.create_token_type', 1);  -- global object: permission in tenant 1 (D-07)

    insert into const.token_type (code, default_expiration_in_seconds, is_system)
    values (_code, _default_expiration_in_seconds, false);

    perform public.create_journal_message_for_entity(_created_by, _user_id, _correlation_id
        , 19001  -- token_type_created
        , 'token_type', 0
        , jsonb_build_object('token_type_code', _code, 'actor', _created_by)
        , _tenant_id);

    return query
        select code, default_expiration_in_seconds, is_system
        from const.token_type
        where code = _code;
end;
$$;

create or replace function public.update_token_type(
    _updated_by text,
    _user_id bigint,
    _correlation_id text,
    _code text,
    _default_expiration_in_seconds integer default null,
    _tenant_id integer default 1
) returns table(
    __code                          text,
    __default_expiration_in_seconds integer,
    __is_system                     boolean
)
    rows 1
    language plpgsql
as
$$
declare
    __is_system boolean;
begin
    perform auth.has_permission(_user_id, _correlation_id, 'token_configuration.update_token_type', 1);  -- global object: permission in tenant 1 (D-07)

    select is_system
    into __is_system
    from const.token_type
    where code = _code;

    if __is_system is null then
        perform error.raise_36001(_code);
    end if;

    if __is_system then
        perform error.raise_36002(_code);
    end if;

    update const.token_type
    set default_expiration_in_seconds = _default_expiration_in_seconds
    where code = _code;

    perform public.create_journal_message_for_entity(_updated_by, _user_id, _correlation_id
        , 19002  -- token_type_updated
        , 'token_type', 0
        , jsonb_build_object('token_type_code', _code, 'actor', _updated_by)
        , _tenant_id);

    return query
        select code, default_expiration_in_seconds, is_system
        from const.token_type
        where code = _code;
end;
$$;

create or replace function public.delete_token_type(
    _deleted_by text,
    _user_id bigint,
    _correlation_id text,
    _code text,
    _tenant_id integer default 1
) returns void
    language plpgsql
as
$$
declare
    __is_system boolean;
begin
    perform auth.has_permission(_user_id, _correlation_id, 'token_configuration.delete_token_type', 1);  -- global object: permission in tenant 1 (D-07)

    select is_system
    into __is_system
    from const.token_type
    where code = _code;

    if __is_system is null then
        perform error.raise_36001(_code);
    end if;

    if __is_system then
        perform error.raise_36002(_code);
    end if;

    delete from const.token_type where code = _code;

    perform public.create_journal_message_for_entity(_deleted_by, _user_id, _correlation_id
        , 19003  -- token_type_deleted
        , 'token_type', 0
        , jsonb_build_object('token_type_code', _code, 'actor', _deleted_by)
        , _tenant_id);
end;
$$;

create or replace function public.create_language(
    _created_by text,
    _user_id bigint,
    _correlation_id text,
    _code text,
    _value text,
    _is_frontend_language boolean DEFAULT false,
    _is_backend_language boolean DEFAULT false,
    _is_communication_language boolean DEFAULT false,
    _frontend_logical_order integer DEFAULT 0,
    _backend_logical_order integer DEFAULT 0,
    _communication_logical_order integer DEFAULT 0,
    _is_default_frontend boolean DEFAULT false,
    _is_default_backend boolean DEFAULT false,
    _is_default_communication boolean DEFAULT false,
    _custom_data jsonb DEFAULT null,
    _tenant_id integer DEFAULT 1
)
    returns table(
        __created_at                  timestamptz,
        __created_by                  text,
        __updated_at                  timestamptz,
        __updated_by                  text,
        __code                        text,
        __value                       text,
        __tenant_id                   integer,
        __is_frontend_language        boolean,
        __is_backend_language         boolean,
        __is_communication_language   boolean,
        __frontend_logical_order      integer,
        __backend_logical_order       integer,
        __communication_logical_order integer,
        __is_default_frontend         boolean,
        __is_default_backend          boolean,
        __is_default_communication    boolean,
        __custom_data                 jsonb
    )
    rows 1
    language plpgsql
as
$$
begin
    perform auth.has_permission(_user_id, _correlation_id, 'languages.create_language', 1);  -- global object: permission in tenant 1 (D-07)

    -- Unset other defaults when setting this as default
    if _is_default_frontend then
        update const.language set is_default_frontend = false, updated_by = _created_by, updated_at = now()
        where is_default_frontend = true and tenant_id = _tenant_id;
    end if;
    if _is_default_backend then
        update const.language set is_default_backend = false, updated_by = _created_by, updated_at = now()
        where is_default_backend = true and tenant_id = _tenant_id;
    end if;
    if _is_default_communication then
        update const.language set is_default_communication = false, updated_by = _created_by, updated_at = now()
        where is_default_communication = true and tenant_id = _tenant_id;
    end if;

    return query
        insert into const.language (created_by, updated_by, code, value, tenant_id,
            is_frontend_language, is_backend_language, is_communication_language,
            frontend_logical_order, backend_logical_order, communication_logical_order,
            is_default_frontend, is_default_backend, is_default_communication, custom_data)
        values (_created_by, _created_by, _code, _value, _tenant_id,
            _is_frontend_language, _is_backend_language, _is_communication_language,
            _frontend_logical_order, _backend_logical_order, _communication_logical_order,
            _is_default_frontend, _is_default_backend, _is_default_communication, _custom_data)
        returning created_at, created_by, updated_at, updated_by, code, value, tenant_id,
                  is_frontend_language, is_backend_language, is_communication_language,
                  frontend_logical_order, backend_logical_order, communication_logical_order,
                  is_default_frontend, is_default_backend, is_default_communication, custom_data;

    perform public.create_journal_message(_created_by, _user_id, _correlation_id
        , 20001  -- language_created
        , null::jsonb  -- keys
        , jsonb_strip_nulls(jsonb_build_object(
            'language_code', _code, 'language_value', _value,
            'is_frontend_language', _is_frontend_language,
            'is_backend_language', _is_backend_language,
            'is_communication_language', _is_communication_language))
        , _tenant_id);
end;
$$;

create or replace function public.update_language(
    _created_by text,
    _user_id bigint,
    _correlation_id text,
    _code text,
    _value text DEFAULT null,
    _is_frontend_language boolean DEFAULT null,
    _is_backend_language boolean DEFAULT null,
    _is_communication_language boolean DEFAULT null,
    _frontend_logical_order integer DEFAULT null,
    _backend_logical_order integer DEFAULT null,
    _communication_logical_order integer DEFAULT null,
    _is_default_frontend boolean DEFAULT null,
    _is_default_backend boolean DEFAULT null,
    _is_default_communication boolean DEFAULT null,
    _custom_data jsonb DEFAULT null,
    _tenant_id integer DEFAULT 1
)
    returns table(
        __created_at                  timestamptz,
        __created_by                  text,
        __updated_at                  timestamptz,
        __updated_by                  text,
        __code                        text,
        __value                       text,
        __tenant_id                   integer,
        __is_frontend_language        boolean,
        __is_backend_language         boolean,
        __is_communication_language   boolean,
        __frontend_logical_order      integer,
        __backend_logical_order       integer,
        __communication_logical_order integer,
        __is_default_frontend         boolean,
        __is_default_backend          boolean,
        __is_default_communication    boolean,
        __custom_data                 jsonb
    )
    rows 1
    language plpgsql
as
$$
begin
    perform auth.has_permission(_user_id, _correlation_id, 'languages.update_language', 1);  -- global object: permission in tenant 1 (D-07)

    if not exists (select 1 from const.language where code = _code) then
        perform error.raise_37001(_code);
    end if;

    -- Unset other defaults when setting this as default
    if _is_default_frontend = true then
        update const.language set is_default_frontend = false, updated_by = _created_by, updated_at = now()
        where is_default_frontend = true and code <> _code and tenant_id = _tenant_id;
    end if;
    if _is_default_backend = true then
        update const.language set is_default_backend = false, updated_by = _created_by, updated_at = now()
        where is_default_backend = true and code <> _code and tenant_id = _tenant_id;
    end if;
    if _is_default_communication = true then
        update const.language set is_default_communication = false, updated_by = _created_by, updated_at = now()
        where is_default_communication = true and code <> _code and tenant_id = _tenant_id;
    end if;

    return query
        update const.language
        set updated_by                  = _created_by
          , updated_at                  = now()
          , value                       = coalesce(_value, value)
          , is_frontend_language        = coalesce(_is_frontend_language, is_frontend_language)
          , is_backend_language         = coalesce(_is_backend_language, is_backend_language)
          , is_communication_language   = coalesce(_is_communication_language, is_communication_language)
          , frontend_logical_order      = coalesce(_frontend_logical_order, frontend_logical_order)
          , backend_logical_order       = coalesce(_backend_logical_order, backend_logical_order)
          , communication_logical_order = coalesce(_communication_logical_order, communication_logical_order)
          , is_default_frontend         = coalesce(_is_default_frontend, is_default_frontend)
          , is_default_backend          = coalesce(_is_default_backend, is_default_backend)
          , is_default_communication    = coalesce(_is_default_communication, is_default_communication)
          , custom_data                 = coalesce(_custom_data, custom_data)
        where code = _code
        returning created_at, created_by, updated_at, updated_by, code, value, tenant_id,
                  is_frontend_language, is_backend_language, is_communication_language,
                  frontend_logical_order, backend_logical_order, communication_logical_order,
                  is_default_frontend, is_default_backend, is_default_communication, custom_data;

    perform public.create_journal_message(_created_by, _user_id, _correlation_id
        , 20002  -- language_updated
        , null::jsonb  -- keys
        , jsonb_strip_nulls(jsonb_build_object('language_code', _code, 'language_value', _value))
        , _tenant_id);
end;
$$;

create or replace function public.delete_language(
    _created_by text,
    _user_id bigint,
    _correlation_id text,
    _code text,
    _tenant_id integer DEFAULT 1
)
    returns void
    language plpgsql
as
$$
begin
    perform auth.has_permission(_user_id, _correlation_id, 'languages.delete_language', 1);  -- global object: permission in tenant 1 (D-07)

    if not exists (select 1 from const.language where code = _code) then
        perform error.raise_37001(_code);
    end if;

    -- CASCADE on translation FK handles cleanup
    delete from const.language where code = _code;

    perform public.create_journal_message(_created_by, _user_id, _correlation_id
        , 20003  -- language_deleted
        , null::jsonb  -- keys
        , jsonb_build_object('language_code', _code)
        , _tenant_id);
end;
$$;

create or replace function auth.ensure_provider(_created_by text, _user_id bigint, _correlation_id text, _provider_code text, _provider_name text, _is_active boolean default true, _allows_group_mapping boolean default false, _allows_group_sync boolean default false, _tenant_id integer default 1)
    returns table(__provider_id integer, __is_new boolean)
    rows 1
    language plpgsql
as
$$
declare
    __existing_id int;
    __new_id int;
begin
    perform auth.has_permission(_user_id, _correlation_id, 'providers.create_provider', 1);  -- global object (D-07)

    select provider_id
    from auth.provider
    where code = _provider_code
    into __existing_id;

    if __existing_id is not null then
        return query select __existing_id, false;
        return;
    end if;

    select p.__provider_id
    from auth.create_provider(_created_by, _user_id, _correlation_id, _provider_code, _provider_name, _is_active, _allows_group_mapping, _allows_group_sync, _tenant_id) p
    into __new_id;

    return query select __new_id, true;
end;
$$;

create or replace function unsecure.set_permission_as_assignable(_updated_by text, _user_id bigint, _correlation_id text, _permission_id integer DEFAULT NULL::integer, _permission_full_code text DEFAULT NULL::text, _is_assignable boolean DEFAULT true) returns SETOF auth.permission_assignment
    language plpgsql
as
$$
declare
	__permission_id        int;
	__permission_full_code text;
begin

	if
		_permission_id is null and _permission_full_code is null then
		perform error.raise_52274();
	end if;

	__permission_id := _permission_id;

	if
		__permission_id is null then
		select permission_id
		from auth.permission
		where full_code = _permission_full_code::ext.ltree
		into __permission_id;

		if
			__permission_id is null then
			perform error.raise_52275(_permission_full_code);
		end if;
	end if;

	update auth.permission
	set updated_at    = now()
		, updated_by    = _updated_by
		, is_assignable = _is_assignable
	where permission_id = __permission_id
	returning full_code
		into __permission_full_code;

	-- Invalidate cache for all users who have this permission (directly or via perm_sets/groups)
	perform unsecure.invalidate_permission_users_cache(_updated_by, __permission_id);

	perform public.create_journal_message_for_entity(_updated_by, _user_id, _correlation_id
			, 12002  -- permission_updated
			, 'permission', __permission_id
			, jsonb_build_object('permission_code', __permission_full_code, 'is_assignable', _is_assignable)
			, 1);
end;
$$;

-- ----------------------------------------------------------------------------
-- System parameters and event codes: new system.* permissions
-- ----------------------------------------------------------------------------

create or replace function auth.update_sys_param(
    _user_id      bigint,
    _group_code   text,
    _code         text,
    _text_value   text    default null,
    _number_value bigint  default null,
    _bool_value   boolean default null
) returns const.sys_param
    language plpgsql
as
$$
declare
    __result const.sys_param;
begin
    perform auth.has_permission(_user_id, null, 'system.update_sys_params', 1);  -- global (D-07)

    insert into const.sys_param (group_code, code, text_value, number_value, bool_value, created_by, updated_by)
    values (_group_code, _code, _text_value, _number_value, _bool_value, 'system', 'system')
    on conflict (group_code, code) do update
        set text_value   = excluded.text_value,
            number_value = excluded.number_value,
            bool_value   = excluded.bool_value,
            updated_by   = 'system',
            updated_at   = now()
    returning * into __result;

    return __result;
end;
$$;

create or replace function public.create_event_category(
    _created_by text,
    _user_id bigint,
    _correlation_id text,
    _category_code text,
    _title text,
    _range_start integer,
    _range_end integer,
    _is_error boolean default false,
    _source text default null
) returns table(
    __category_code text,
    __range_start   integer,
    __range_end     integer,
    __is_error      boolean,
    __source        text
)
    rows 1
    language plpgsql
as
$$
begin
    perform auth.has_permission(_user_id, _correlation_id, 'system.manage_event_codes', 1);  -- global (D-07)

    insert into const.event_category (category_code, range_start, range_end, is_error, source)
    values (_category_code, _range_start, _range_end, _is_error, _source);

    -- Store title as translation
    if _title is not null then
        insert into public.translation (created_by, updated_by, language_code, data_group, data_object_code, context, value)
        values (_created_by, _created_by, 'en', 'event_category', _category_code, 'title', _title)
        on conflict do nothing;
    end if;

    return query
        select category_code, range_start, range_end, is_error, source
        from const.event_category
        where category_code = _category_code;
end;
$$;

create or replace function public.delete_event_category(
    _deleted_by text,
    _user_id bigint,
    _correlation_id text,
    _category_code text
) returns void
    language plpgsql
as
$$
begin
    perform auth.has_permission(_user_id, _correlation_id, 'system.manage_event_codes', 1);  -- global (D-07)

    -- Check category exists
    if not exists (select 1 from const.event_category where category_code = _category_code) then
        perform error.raise_31014(_category_code);
    end if;

    -- Check no system events belong to this category
    if exists (select 1 from const.event_code where category_code = _category_code and is_system = true) then
        perform error.raise_31010(
            (select event_id from const.event_code where category_code = _category_code and is_system = true limit 1)
        );
    end if;

    -- Check no event codes reference it
    if exists (select 1 from const.event_code where category_code = _category_code) then
        perform error.raise_31012(_category_code);
    end if;

    -- Delete the category
    delete from const.event_category where category_code = _category_code;
end;
$$;

create or replace function public.create_event_code(
    _created_by text,
    _user_id bigint,
    _correlation_id text,
    _event_id integer,
    _code text,
    _category_code text,
    _title text,
    _description text default null,
    _is_read_only boolean default false,
    _source text default null
) returns table(
    __event_id      integer,
    __code          text,
    __category_code text,
    __is_read_only  boolean,
    __is_system     boolean,
    __source        text
)
    rows 1
    language plpgsql
as
$$
declare
    __range_start integer;
    __range_end integer;
begin
    perform auth.has_permission(_user_id, _correlation_id, 'system.manage_event_codes', 1);  -- global (D-07)

    -- Validate category exists
    select range_start, range_end
    into __range_start, __range_end
    from const.event_category
    where category_code = _category_code;

    if __range_start is null then
        perform error.raise_31014(_category_code);
    end if;

    -- Validate event_id is within the category's range
    if _event_id < __range_start or _event_id > __range_end then
        perform error.raise_31013(_event_id, _category_code, __range_start, __range_end);
    end if;

    -- Always insert with is_system = false (system events come from seed only)
    insert into const.event_code (event_id, code, category_code, is_read_only, is_system, source)
    values (_event_id, _code, _category_code, _is_read_only, false, _source);

    -- Store title + description as translations
    if _title is not null then
        insert into public.translation (created_by, updated_by, language_code, data_group, data_object_code, context, value)
        values (_created_by, _created_by, 'en', 'event_code', _code, 'title', _title)
        on conflict do nothing;
    end if;
    if _description is not null then
        insert into public.translation (created_by, updated_by, language_code, data_group, data_object_code, context, value)
        values (_created_by, _created_by, 'en', 'event_code', _code, 'description', _description)
        on conflict do nothing;
    end if;

    return query
        select event_id, code, category_code, is_read_only, is_system, source
        from const.event_code
        where event_id = _event_id;
end;
$$;

create or replace function public.delete_event_code(
    _deleted_by text,
    _user_id bigint,
    _correlation_id text,
    _event_id integer
) returns void
    language plpgsql
as
$$
declare
    __is_system boolean;
begin
    perform auth.has_permission(_user_id, _correlation_id, 'system.manage_event_codes', 1);  -- global (D-07)

    -- Check event code exists and get is_system flag
    select is_system
    into __is_system
    from const.event_code
    where event_id = _event_id;

    if __is_system is null then
        perform error.raise_31011(_event_id);
    end if;

    -- Protect system events
    if __is_system then
        perform error.raise_31010(_event_id);
    end if;

    -- Cascade: delete related event messages
    delete from const.event_message where event_id = _event_id;

    -- Delete the event code
    delete from const.event_code where event_id = _event_id;
end;
$$;

create or replace function public.create_event_message(
    _created_by text,
    _user_id bigint,
    _correlation_id text,
    _event_id integer,
    _message_template text,
    _language_code text default 'en'
) returns table(
    __created_at       timestamptz,
    __created_by       text,
    __updated_at       timestamptz,
    __updated_by       text,
    __event_message_id integer,
    __event_id         integer,
    __language_code    text,
    __message_template text,
    __is_active        boolean
)
    rows 1
    language plpgsql
as
$$
begin
    perform auth.has_permission(_user_id, _correlation_id, 'system.manage_event_codes', 1);  -- global (D-07)

    -- Validate event_code exists
    if not exists (select 1 from const.event_code where event_id = _event_id) then
        perform error.raise_31011(_event_id);
    end if;

    insert into const.event_message (created_by, updated_by, event_id, language_code, message_template)
    values (_created_by, _created_by, _event_id, _language_code, _message_template);

    return query
        select created_at, created_by, updated_at, updated_by, event_message_id, event_id, language_code, message_template, is_active
        from const.event_message
        where event_id = _event_id
          and language_code = _language_code
          and is_active = true;
end;
$$;

create or replace function public.delete_event_message(
    _deleted_by text,
    _user_id bigint,
    _correlation_id text,
    _event_message_id integer
) returns void
    language plpgsql
as
$$
declare
    __event_id integer;
    __is_system boolean;
begin
    perform auth.has_permission(_user_id, _correlation_id, 'system.manage_event_codes', 1);  -- global (D-07)

    -- Get the parent event_id
    select event_id
    into __event_id
    from const.event_message
    where event_message_id = _event_message_id;

    if __event_id is null then
        perform error.raise_31011(0);
    end if;

    -- Check parent event_code is_system
    select is_system
    into __is_system
    from const.event_code
    where event_id = __event_id;

    if __is_system then
        perform error.raise_31010(__event_id);
    end if;

    -- Delete the message
    delete from const.event_message where event_message_id = _event_message_id;
end;
$$;

-- ----------------------------------------------------------------------------
-- Translations: rows of _tenant_id only
-- ----------------------------------------------------------------------------

create or replace function public.update_translation(
    _created_by text,
    _user_id bigint,
    _correlation_id text,
    _translation_id integer,
    _value text,
    _tenant_id integer DEFAULT 1
)
    returns table(
        __created_at       timestamptz,
        __created_by       text,
        __updated_at       timestamptz,
        __updated_by       text,
        __translation_id   integer,
        __language_code    text,
        __tenant_id        integer,
        __data_group       text,
        __data_object_code text,
        __data_object_id   bigint,
        __context          text,
        __value            text
    )
    rows 1
    language plpgsql
as
$$
begin
    perform auth.has_permission(_user_id, _correlation_id, 'translations.update_translation', _tenant_id);

    if not exists (select 1 from public.translation where translation_id = _translation_id and tenant_id = _tenant_id) then
        perform error.raise_37002(_translation_id);
    end if;

    return query
        update public.translation
        set updated_by = _created_by
          , updated_at = now()
          , value      = _value
        where translation_id = _translation_id
        returning created_at, created_by, updated_at, updated_by, translation_id,
            language_code, tenant_id, data_group, data_object_code, data_object_id,
            context, value;

    perform public.create_journal_message_for_entity(_created_by, _user_id, _correlation_id
        , 21002  -- translation_updated
        , 'translation', _translation_id::bigint
        , jsonb_build_object('translation_id', _translation_id, 'value', _value)
        , _tenant_id);
end;
$$;

create or replace function public.delete_translation(
    _created_by text,
    _user_id bigint,
    _correlation_id text,
    _translation_id integer,
    _tenant_id integer DEFAULT 1
)
    returns void
    language plpgsql
as
$$
begin
    perform auth.has_permission(_user_id, _correlation_id, 'translations.delete_translation', _tenant_id);

    if not exists (select 1 from public.translation where translation_id = _translation_id and tenant_id = _tenant_id) then
        perform error.raise_37002(_translation_id);
    end if;

    delete from public.translation where translation_id = _translation_id;

    perform public.create_journal_message_for_entity(_created_by, _user_id, _correlation_id
        , 21003  -- translation_deleted
        , 'translation', _translation_id::bigint
        , jsonb_build_object('translation_id', _translation_id)
        , _tenant_id);
end;
$$;

create or replace function public.copy_translations(
    _created_by text,
    _user_id bigint,
    _correlation_id text,
    _from_language_code text,
    _to_language_code text,
    _overwrite boolean default false,
    _data_group text default null,
    _from_tenant_id integer default 1,
    _to_tenant_id integer default 1,
    _tenant_id integer default 1
)
    returns table(__operation text, __count bigint)
    language plpgsql
as
$$
declare
    __updated_count bigint := 0;
    __inserted_count bigint := 0;
begin
    perform auth.has_permission(_user_id, _correlation_id, 'translations.copy_translations', _tenant_id);

    -- only into the caller's own tenant (D-02)
    if _to_tenant_id is distinct from _tenant_id then
        perform error.raise_34002(_tenant_id);
    end if;

    if not exists (select 1 from const.language where code = _from_language_code) then
        perform error.raise_37001(_from_language_code);
    end if;
    if not exists (select 1 from const.language where code = _to_language_code) then
        perform error.raise_37001(_to_language_code);
    end if;

    -- Phase 1: Update existing translations if overwrite is enabled
    if _overwrite then
        with source as (
            select data_group, data_object_code, data_object_id, context, value
            from public.translation
            where language_code = _from_language_code
                and tenant_id = _from_tenant_id
                and (_data_group is null or data_group = _data_group)
        )
        update public.translation t
        set value      = s.value
          , updated_by = _created_by
          , updated_at = now()
        from source s
        where t.language_code = _to_language_code
            and t.tenant_id = _to_tenant_id
            and t.data_group = s.data_group
            and t.context = s.context
            and (
                (t.data_object_code is not null and t.data_object_code = s.data_object_code)
                or (t.data_object_id is not null and t.data_object_id = s.data_object_id)
            );

        get diagnostics __updated_count = row_count;
    end if;

    -- Phase 2: Insert missing translations
    insert into public.translation (created_by, updated_by, language_code, tenant_id,
        data_group, data_object_code, data_object_id, context, value)
    select _created_by, _created_by, _to_language_code, _to_tenant_id,
        s.data_group, s.data_object_code, s.data_object_id, s.context, s.value
    from public.translation s
    where s.language_code = _from_language_code
        and s.tenant_id = _from_tenant_id
        and (_data_group is null or s.data_group = _data_group)
        and not exists (
            select 1 from public.translation e
            where e.language_code = _to_language_code
                and e.tenant_id = _to_tenant_id
                and e.data_group = s.data_group
                and e.context = s.context
                and (
                    (s.data_object_code is not null and e.data_object_code = s.data_object_code)
                    or (s.data_object_id is not null and e.data_object_id = s.data_object_id)
                )
        );

    get diagnostics __inserted_count = row_count;

    -- Refresh materialized view
    perform internal.refresh_translation_cache();

    perform public.create_journal_message(_created_by, _user_id, _correlation_id
        , 21004  -- translations_copied
        , null::jsonb
        , jsonb_build_object(
            'from_language', _from_language_code, 'to_language', _to_language_code,
            'overwrite', _overwrite, 'data_group', _data_group,
            'updated_count', __updated_count, 'inserted_count', __inserted_count)
        , _tenant_id);

    return query
        select 'updated'::text, __updated_count
        union all
        select 'inserted'::text, __inserted_count;
end;
$$;


select *
from public.stop_version_update('2.15', _component := 'postgresql_permissionmodel');
