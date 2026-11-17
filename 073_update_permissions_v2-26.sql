/*
 * PostgreSQL Permissions Model — update v2.26
 * ===========================================
 *
 * Tenant owners above tenant admins (decided with the user after D-13).
 *
 *  - auth.perm_set.is_owner_only: outside tenant 1, only an active tenant owner
 *    (or user 1) may give out or take away such a perm set - directly, through
 *    a group (members, mappings, invitations, actions, API keys) - or edit it.
 *    The no-escalation check (D-19) carries it: a grant of an owner-only set
 *    asks for "<code> (tenant owners only)", which only the exempt hold.
 *    tenant_admin is owner-only in every tenant; copy_perm_set keeps the flag.
 *    Tenant 1 (templates, platform) is not affected.
 *  - tenant_admin loses tenants.assign_owner: admins don't appoint owners.
 *  - tenant_admin gets the tenant's groups.* permissions (create, update, lock,
 *    delete, members, mappings, reads); D-19 still applies to each group.
 *  - Fixed: auth.delete_user_group failed for a group with mappings.
 */

set search_path = public, const, ext, stage, helpers, internal, unsecure, auth, triggers;

select *
from public.start_version_update('2.26', 'Tenant owners above tenant admins',
                                 _component := 'postgresql_permissionmodel',
                                 _description := 'Owner-only perm sets (tenant_admin): only tenant owners give them out, take them away or edit them outside tenant 1; tenant_admin loses tenants.assign_owner and gets groups.*.');


/***
 *    owner-only perm sets
 */

alter table auth.perm_set
    add column if not exists is_owner_only boolean default false not null;

update auth.perm_set
set is_owner_only = true
where code = 'tenant_admin'
  and not is_owner_only;

-- what an owner-only perm set adds to a grant: a code only the exempt (user 1, tenant owners) hold
create or replace function unsecure.get_owner_only_perm_set_codes(_perm_set_ids integer[]) returns text[]
    stable
    language sql
as
$$
select coalesce(array_agg(ps.code || ' (tenant owners only)' order by ps.code), array []::text[])
from auth.perm_set ps
where ps.perm_set_id = any (_perm_set_ids)
  and ps.is_owner_only
  and ps.tenant_id <> 1;
$$;


/***
 *    tenant_admin: groups yes, owners no
 */

select unsecure.create_perm_set_permissions('update_v2.26', 1, null, ps.perm_set_id
    , array ['groups.create_group', 'groups.update_group', 'groups.lock_group', 'groups.delete_group'
        , 'groups.create_member', 'groups.delete_member', 'groups.create_mapping', 'groups.delete_mapping'
        , 'groups.get_group', 'groups.get_groups', 'groups.get_members', 'groups.get_mapping'
        , 'groups.get_permissions'], ps.tenant_id)
from auth.perm_set ps
where ps.code = 'tenant_admin';

select unsecure.delete_perm_set_permissions('update_v2.26', 1, null, ps.perm_set_id
    , array ['tenants.assign_owner'], ps.tenant_id)
from auth.perm_set ps
where ps.code = 'tenant_admin'
  and exists(select
             from auth.perm_set_perm psp
                      inner join auth.permission p on p.permission_id = psp.permission_id
             where psp.perm_set_id = ps.perm_set_id
               and p.full_code = 'tenants.assign_owner');

/***
 *    the checks carry the owner-only sets
 */

create or replace function unsecure.get_perm_set_permission_codes(_perm_set_ids integer[]) returns text[]
    stable
    language sql
as
$$
select coalesce(array_agg(distinct ep.permission_code::text), array []::text[])
           || unsecure.get_owner_only_perm_set_codes(_perm_set_ids)  -- v2.26
from auth.effective_permissions ep
where ep.perm_set_id = any (_perm_set_ids)
  and ep.permission_is_assignable;
$$;

create or replace function unsecure.copy_perm_set(_created_by text, _user_id bigint, _correlation_id text, _source_perm_set_code text, _source_tenant_id integer, _target_tenant_id integer, _new_title text DEFAULT NULL::text) returns SETOF auth.perm_set
    language plpgsql
as
$$
declare
	__created_perm_set   auth.perm_set;
	__source_perm_set    auth.perm_set;
	__source_tenant_code text;
	__target_tenant_code text;
	__effective_title    text;
begin

	select t.code
	from auth.tenant t
	where t.tenant_id = _source_tenant_id
	into __source_tenant_code;

	select t.code
	from auth.tenant t
	where t.tenant_id = _target_tenant_id
	into __target_tenant_code;

	select *
	from auth.perm_set
	where code = _source_perm_set_code
		and tenant_id = _source_tenant_id
	into __source_perm_set;

	if
		__source_perm_set is null then
		perform error.raise_52282(_source_perm_set_code);
	end if;

	-- Resolve effective title: use _new_title if provided, otherwise look up source title from translation
	__effective_title := coalesce(_new_title,
		(select mv.values->>'title' from public.mv_translation mv
		 where mv.data_group = 'perm_set' and mv.data_object_code = __source_perm_set.code and mv.language_code = 'en'));

	insert into auth.perm_set(created_by, updated_by, tenant_id, is_system,
														is_assignable, code, source, is_owner_only)
	values ( _created_by, _created_by, _target_tenant_id
				 , __source_perm_set.is_system, __source_perm_set.is_assignable, helpers.get_code(__effective_title)
				 , __source_perm_set.source, __source_perm_set.is_owner_only)
	returning *
		into __created_perm_set;

	-- Store title as translation for the new perm_set
	insert into public.translation (created_by, updated_by, language_code, data_group, data_object_code, context, value)
	values (_created_by, _created_by, 'en', 'perm_set', __created_perm_set.code, 'title', __effective_title)
	on conflict (language_code, data_group, data_object_code, context)
		where data_object_code is not null
	do update set value = excluded.value, updated_by = excluded.updated_by, updated_at = now();

	perform internal.refresh_translation_cache();

-- copy assigned permissions

	insert into auth.perm_set_perm (created_by, perm_set_id, permission_id)
	select _created_by, __created_perm_set.perm_set_id, permission_id
	from auth.perm_set_perm
	where perm_set_id = __source_perm_set.perm_set_id;

	perform public.create_journal_message_for_entity(_created_by, _user_id, _correlation_id
			, 12020  -- perm_set_created
			, 'perm_set', __created_perm_set.perm_set_id
			, jsonb_build_object('perm_set_code', __created_perm_set.code
				, 'tenant_title', __target_tenant_code
				, 'source_perm_set_code', _source_perm_set_code
				, 'source_tenant', __source_tenant_code)
			, _target_tenant_id);

	return query select * from auth.perm_set where perm_set_id = __created_perm_set.perm_set_id;
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

	-- D-19: only permissions the caller holds; owner-only sets only by owners (v2.26)
	perform unsecure.validate_permissions_held(_user_id, _correlation_id
		, unsecure.get_permission_codes(_permissions)
			|| unsecure.get_owner_only_perm_set_codes(array [_perm_set_id]), _tenant_id);

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

	-- D-19: only permissions the caller holds; owner-only sets only by owners (v2.26)
	perform unsecure.validate_permissions_held(_user_id, _correlation_id
		, unsecure.get_permission_codes(_permissions)
			|| unsecure.get_owner_only_perm_set_codes(array [_perm_set_id]), _tenant_id);

	return query
		select *
		from unsecure.delete_perm_set_permissions(_created_by, _user_id, _correlation_id
			, _perm_set_id, _permissions, _tenant_id);
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

	-- owner-only sets are edited only by owners (v2.26)
	perform unsecure.validate_permissions_held(_user_id, _correlation_id
		, unsecure.get_owner_only_perm_set_codes(array [_perm_set_id]), _tenant_id);

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
                                              from jsonb_array_elements(_perm_sets) i))
            -- owner-only sets it would change or (final state) delete, v2.26
            || unsecure.get_owner_only_perm_set_codes(array(select ps.perm_set_id
                                                            from auth.perm_set ps
                                                            where ps.tenant_id = _tenant_id
                                                              and (ps.code in (select helpers.get_code(i ->> 'title', '_')
                                                                               from jsonb_array_elements(_perm_sets) i)
                                                                or (_is_final_state and ps.source = _source))))
        , _tenant_id);
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

	-- a group with mappings couldn't be deleted (foreign key), v2.26
	delete from auth.user_group_member where user_group_id = _user_group_id;
	delete from auth.user_group_mapping where user_group_id = _user_group_id;

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

select *
from public.stop_version_update('2.26', _component := 'postgresql_permissionmodel');
