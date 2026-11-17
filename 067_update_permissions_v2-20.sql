/*
 * PostgreSQL Permissions Model — update v2.20
 * ===========================================
 *
 * Default groups are gone (D-13, step 1 of audit/design-d13-tenant-actions.md).
 *
 * unsecure.recalculate_user_groups runs at every login and on every permission
 * cache miss. It added the user to every is_default group of EVERY tenant. A
 * tenant owner (groups.update_group in their tenant) could mark a group of
 * their tenant as default and pull every user who signs in anywhere into it -
 * and so into the tenant's member lists, pickers and notifications.
 *
 * Default groups had no rules either ("everyone, everywhere" was the only
 * option) and no application used them. They are replaced later by actions
 * (on_registration / on_entry, with rules) and rule mappings on groups.
 *
 * Removed:
 *  - auth.user_group.is_default (and its check constraint), the column of the
 *    view auth.active_user_groups
 *  - the default-group branch of unsecure.recalculate_user_groups
 *  - auth.assign_user_default_groups, unsecure.assign_user_default_groups and
 *    the permission users.add_to_default_groups
 *  - the _is_default parameter of auth.create_user_group, auth.update_user_group,
 *    unsecure.create_user_group, unsecure.create_user_group_as_system
 *  - the __is_default column of auth/unsecure.get_user_group_by_id,
 *    auth.search_user_groups, auth.ensure_user_groups (an is_default key in
 *    the ensure_user_groups payload is ignored)
 *
 * Memberships that default groups created stay; they are ordinary 'manual'
 * memberships now. tenant.is_default (the default tenant) is not affected.
 */

set search_path = public, const, ext, stage, helpers, internal, unsecure, auth, triggers;

select *
from public.start_version_update('2.20', 'Default groups are removed',
                                 _component := 'postgresql_permissionmodel',
                                 _description := 'user_group.is_default, assign_user_default_groups and users.add_to_default_groups are gone; login no longer adds users to the default groups of every tenant; _is_default / __is_default removed from the group functions.');


-- ---------------------------------------------------------------------------
-- the permission users.add_to_default_groups
-- ---------------------------------------------------------------------------
do
$$
declare
    __permission_id int;
begin
    select permission_id
    from auth.permission
    where full_code = 'users.add_to_default_groups'::ext.ltree
    into __permission_id;

    if __permission_id is not null then
        perform unsecure.invalidate_permission_users_cache('update_v2.20', __permission_id);

        delete from auth.permission_assignment where permission_id = __permission_id;
        -- perm_set_perm rows cascade
        delete from auth.permission where permission_id = __permission_id;
    end if;
end;
$$;


-- ---------------------------------------------------------------------------
-- functions and view that use the flag
-- ---------------------------------------------------------------------------
drop function if exists auth.assign_user_default_groups(text, bigint, text, bigint, integer);
drop function if exists unsecure.assign_user_default_groups(text, bigint, text, bigint, integer);

drop view if exists auth.active_user_groups;

drop function if exists unsecure.create_user_group(text, bigint, text, text, boolean, boolean, boolean, boolean, boolean, integer, text);
drop function if exists unsecure.create_user_group_as_system(text, boolean, boolean, boolean, integer);
drop function if exists auth.create_user_group(text, bigint, text, text, boolean, boolean, boolean, boolean, integer, text);
drop function if exists auth.update_user_group(text, bigint, text, integer, text, boolean, boolean, boolean, boolean, integer);
drop function if exists unsecure.get_user_group_by_id(text, bigint, integer, integer);
drop function if exists auth.get_user_group_by_id(text, bigint, text, integer, integer);
drop function if exists auth.search_user_groups(bigint, text, jsonb, integer, integer, integer, integer);
drop function if exists auth.ensure_user_groups(text, bigint, text, jsonb, integer, text, boolean);

alter table auth.user_group drop column if exists is_default;

create view auth.active_user_groups
            (user_group_id, is_system, is_external, is_assignable, is_active, group_title, group_code, tenant_id, tenant_code, tenant_title) as
select ug.user_group_id
     , ug.is_system
     , ug.is_external
     , ug.is_assignable
     , ug.is_active
     , ug.title as group_title
     , ug.code  as group_code
     , ug.tenant_id
     , t.code   as tenant_code
     , t.title  as tenant_title
from auth.user_group ug
         left join auth.tenant t on ug.tenant_id = t.tenant_id
where ug.is_active;

create or replace function unsecure.create_user_group(_created_by text, _user_id bigint, _correlation_id text, _title text, _is_assignable boolean DEFAULT true, _is_active boolean DEFAULT true, _is_external boolean DEFAULT false, _is_system boolean DEFAULT false, _tenant_id integer DEFAULT 1, _source text DEFAULT NULL)
    returns TABLE(__user_group_id integer)
    rows 1
    language plpgsql
as
$$
declare
	__last_id int;
begin

	insert into auth.user_group ( created_by, updated_by, tenant_id, title, is_system, is_assignable
															, is_active, is_external, source)
	values ( _created_by, _created_by, _tenant_id, _title, _is_system, _is_assignable, _is_active
				 , _is_external, _source)
	returning user_group_id
		into __last_id;

	return query
		select __last_id;

	perform public.create_journal_message_for_entity(_created_by, _user_id, _correlation_id
			, 13001  -- group_created
			, 'group', __last_id
			, jsonb_build_object('group_title', _title, 'tenant_title', _tenant_id::text
				, 'is_system', _is_system
				, 'is_assignable', _is_assignable, 'is_active', _is_active)
			, _tenant_id);

end ;
$$;

create or replace function unsecure.create_user_group_as_system(_title text, _is_system boolean DEFAULT false, _is_assignable boolean DEFAULT true, _tenant_id integer DEFAULT 1) returns SETOF auth.user_group
    rows 1
    language plpgsql
as
$$
declare
	__user_group_id int;
begin
	select g.__user_group_id
	from unsecure.create_user_group('system', 1, null, _title, _is_assignable, true, false, _is_system, _tenant_id) g
	into __user_group_id;

	return query
		select ug.*
		from auth.user_group ug
		where ug.user_group_id = __user_group_id;
end;
$$;

create or replace function auth.create_user_group(_created_by text, _user_id bigint, _correlation_id text, _title text, _is_assignable boolean DEFAULT true, _is_active boolean DEFAULT true, _is_external boolean DEFAULT false, _tenant_id integer DEFAULT 1, _source text DEFAULT NULL)
    returns TABLE(__user_group_id integer)
    rows 1
    language plpgsql
as
$$
begin
	perform
		auth.has_permission(_user_id, _correlation_id,
												'groups.create_group', _tenant_id);

	return query
		select *
		from unsecure.create_user_group(_created_by, _user_id, _correlation_id, _title
			, _is_assignable, _is_active, _is_external, false, _tenant_id, _source);
end ;
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

	perform unsecure.validate_user_group_in_tenant(_user_group_id, _tenant_id);

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

create or replace function unsecure.get_user_group_by_id(_requested_by text, _user_id bigint, _user_group_id integer, _tenant_id integer DEFAULT 1)
    returns TABLE(__user_group_id integer, __tenant_id integer, __title text, __code text, __is_system boolean, __is_external boolean, __is_assignable boolean, __is_active boolean)
    language plpgsql
as
$$
begin
	return query select user_group_id
										, tenant_id
										, title
										, code
										, is_system
										, is_external
										, is_assignable
										, is_active
							 from auth.user_group
							 where user_group_id = _user_group_id;

	-- Read operation - journal message omitted (use journal level 'all' to log reads)
end
$$;

create or replace function auth.get_user_group_by_id(_requested_by text, _user_id bigint, _correlation_id text, _user_group_id integer, _tenant_id integer DEFAULT 1)
    returns TABLE(__user_group_id integer, __tenant_id integer, __title text, __code text, __is_system boolean, __is_external boolean, __is_assignable boolean, __is_active boolean)
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
begin
    __effective_tenant_id := internal.resolve_cross_tenant_access(
        _user_id, _correlation_id, 'groups.get_all_groups', 'groups.get_group', _tenant_id, _target_tenant_id);

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

create or replace function auth.ensure_user_groups(
    _created_by      text,
    _user_id         bigint,
    _correlation_id  text,
    _user_groups     jsonb,
    _tenant_id       integer default 1,
    _source          text    default null,
    _is_final_state  boolean default false
)
    returns table(
        __created_at                   timestamptz,
        __created_by                   text,
        __updated_at                   timestamptz,
        __updated_by                   text,
        __user_group_id                integer,
        __tenant_id                    integer,
        __title                        text,
        __code                         text,
        __is_system                    boolean,
        __is_external                  boolean,
        __is_assignable                boolean,
        __is_active                    boolean,
        __can_members_manage_others    boolean,
        __can_members_see_others       boolean,
        __is_synced                    boolean,
        __create_missing_users_on_sync boolean,
        __source                       text
    )
    language plpgsql
as
$$
declare
    __item            jsonb;
    __title           text;
    __is_assignable   boolean;
    __is_active       boolean;
    __is_external     boolean;
    __code            text;
    __input_codes     text[] := '{}';
    __group_to_delete record;
begin
    -- Single permission check for the batch
    perform auth.has_permission(_user_id, _correlation_id, 'groups.create_group', _tenant_id);

    if _is_final_state then
        perform auth.has_permission(_user_id, _correlation_id, 'groups.delete_group', _tenant_id);

        if _source is null then
            raise exception '_source is required when _is_final_state is true';
        end if;
    end if;

    for __item in
        select value
        from jsonb_array_elements(_user_groups)
    loop
        __title         := __item ->> 'title';
        __is_assignable := coalesce((__item ->> 'is_assignable')::boolean, true);
        __is_active     := coalesce((__item ->> 'is_active')::boolean, true);
        __is_external   := coalesce((__item ->> 'is_external')::boolean, false);
        __code          := helpers.get_code(__title, '_');

        __input_codes := array_append(__input_codes, __code);

        -- Skip if already exists for this tenant
        if exists (select 1 from auth.user_group where code = __code and tenant_id = _tenant_id) then
            continue;
        end if;

        -- Delegate to unsecure.create_user_group (is_system always false)
        perform unsecure.create_user_group(
            _created_by, _user_id, _correlation_id,
            __title, __is_assignable, __is_active, __is_external,
            false, _tenant_id, _source
        );
    end loop;

    -- Final state: remove groups with same source+tenant that are not in the input set
    if _is_final_state then
        for __group_to_delete in
            select ug.user_group_id, ug.code
            from auth.user_group ug
            where ug.source = _source
              and ug.tenant_id = _tenant_id
              and ug.is_system = false
              and ug.code != all (__input_codes)
        loop
            -- Clean up user_group_mapping references
            delete from auth.user_group_mapping
            where user_group_id = __group_to_delete.user_group_id;

            -- Clean up permission_assignment references
            delete from auth.permission_assignment
            where user_group_id = __group_to_delete.user_group_id;

            -- Delete the group (trg_cache_user_group_before_delete handles cache invalidation)
            -- Cascades to user_group_member and owner
            delete from auth.user_group
            where user_group_id = __group_to_delete.user_group_id;

            -- Journal the removal
            perform public.create_journal_message_for_entity(
                _created_by, _user_id, _correlation_id,
                13003,  -- group_deleted
                'group', __group_to_delete.user_group_id,
                jsonb_build_object('group_code', __group_to_delete.code,
                    'reason', 'final_state_sync', 'source', _source),
                _tenant_id
            );
        end loop;
    end if;

    -- Return all processed groups (existing + newly created)
    return query
        select ug.created_at, ug.created_by, ug.updated_at, ug.updated_by, ug.user_group_id, ug.tenant_id, ug.title, ug.code, ug.is_system, ug.is_external, ug.is_assignable, ug.is_active, ug.can_members_manage_others, ug.can_members_see_others, ug.is_synced, ug.create_missing_users_on_sync, ug.source
        from auth.user_group ug
        where ug.tenant_id = _tenant_id
          and ug.code in (
            select helpers.get_code(item ->> 'title', '_')
            from jsonb_array_elements(_user_groups) as item
        )
        order by ug.title;
end;
$$;

-- login and the permission rebuild no longer add anyone to default groups
create or replace function unsecure.recalculate_user_groups(_created_by text, _target_user_id bigint, _provider_code text)
    returns TABLE(__tenant_id integer, __user_group_id integer, __user_group_code text)
    language plpgsql
as
$$
declare
    __not_really_used int;
    __provider_groups text[];
    __provider_roles  text[];
begin

    -- Validate provider code exists (prevent silent failures with NULL arrays)
    if _provider_code is not null and not exists(select 1 from auth.provider where code = _provider_code) then
        raise exception 'Provider "%" does not exist', _provider_code
            using errcode = '22023';  -- invalid_parameter_value
    end if;

    select provider_groups
         , provider_roles
    from auth.user_identity
    where provider_code = _provider_code
      and user_id = _target_user_id
    into __provider_groups, __provider_roles;

    -- Skip mapping resolution when provider does not allow group mapping
    if _provider_code is not null
       and not coalesce((select allows_group_mapping from auth.provider where code = _provider_code), false) then
        return query
            select distinct ug.tenant_id
                          , ug.user_group_id
                          , ug.code
            from auth.user_group_member ugm
                     inner join auth.user_group ug on ug.user_group_id = ugm.user_group_id
            where ugm.user_id = _target_user_id;
        return;
    end if;

    -- cleanup membership of groups user is no longer part of
    with affected_deleted_group_tenants as (
        delete
            from auth.user_group_member
                where user_id = _target_user_id
                    and mapping_id is not null
                    -- synced groups take their members from the sync only (v2.19)
                    and user_group_id not in (select sg.user_group_id from auth.user_group sg where sg.is_synced)
                    and user_group_id not in (
                        select distinct ugm.user_group_id
                        from unnest(__provider_groups) g
                                 inner join auth.user_group_mapping ugm
                                            on ugm.provider_code = _provider_code and ugm.mapped_object_id = lower(g)
                                 inner join auth.user_group u
                                            on u.user_group_id = ugm.user_group_id
                        union
                        select distinct ugm.user_group_id
                        from unnest(__provider_roles) r
                                 inner join auth.user_group_mapping ugm
                                            on ugm.provider_code = _provider_code and ugm.mapped_role = lower(r)
                                 inner join auth.user_group u
                                            on u.user_group_id = ugm.user_group_id)
                returning user_group_id)
       , affected_group_tenants as (
        insert
            into auth.user_group_member (created_by, user_id, user_group_id, mapping_id, member_type_code)
                select distinct _created_by
                              , _target_user_id
                              , ugm.user_group_id
                              , ugm.user_group_mapping_id
                              , 'external'
                from unnest(__provider_groups) g
                         inner join auth.user_group_mapping ugm
                                    on ugm.provider_code = _provider_code and ugm.mapped_object_id = lower(g)
                where ugm.user_group_id not in (
                    select user_group_id
                    from auth.user_group_member
                    where user_id = _target_user_id)
                  and not exists(select from auth.user_group sg
                                 where sg.user_group_id = ugm.user_group_id and sg.is_synced)
                returning user_group_id)
       , affected_role_tenants as (
        insert
            into auth.user_group_member (created_by, user_id, user_group_id, mapping_id, member_type_code)
                select distinct _created_by
                              , _target_user_id
                              , ugm.user_group_id
                              , ugm.user_group_mapping_id
                              , 'external'
                from unnest(__provider_roles) r
                         inner join auth.user_group_mapping ugm
                                    on ugm.provider_code = _provider_code and ugm.mapped_role = lower(r)
                where ugm.user_group_id not in (
                    select user_group_id
                    from auth.user_group_member
                    where user_id = _target_user_id)
                  and not exists(select from auth.user_group sg
                                 where sg.user_group_id = ugm.user_group_id and sg.is_synced)
                returning user_group_id)
       , all_group_ids as (
        select user_group_id
        from affected_deleted_group_tenants
        union
        select user_group_id
        from affected_group_tenants
        union
        select user_group_id
        from affected_role_tenants)
       , all_tenants as (
        select tenant_id
        from all_group_ids ids
                 inner join auth.user_group ug
                            on ids.user_group_id = ug.user_group_id
        group by tenant_id)
       -- variable not really used, it's there just to avoid 'query has no destination for result data'
    select at.tenant_id
    from all_tenants at
       , lateral unsecure.clear_permission_cache(_created_by, _target_user_id, at.tenant_id) r
    into __not_really_used;

    return query
        select distinct ug.tenant_id
                      , ug.user_group_id
                      , ug.code
        from auth.user_group_member ugm
                 inner join auth.user_group ug on ug.user_group_id = ugm.user_group_id
        where ugm.user_id = _target_user_id;
end;
$$;


select *
from public.stop_version_update('2.20', _component := 'postgresql_permissionmodel');
