/*
 * PostgreSQL Permissions Model — update v2.19
 * ===========================================
 *
 * External group sync (scenario: Azure groups synced into local groups).
 *
 * Sync exists so users can be referenced before their first login (for example
 * a combo of potential product owners = members of a local group mapped to
 * several Azure groups) and so people leaving the Azure group lose the
 * membership on the sync schedule. It did not work:
 *
 *  - auth.process_external_group_member_sync always failed
 *    ("operator does not exist: boolean || integer"), and it was the only
 *    place that removed members. The per-mapping function only added.
 *  - Neither sync function checked a permission (the check was commented out).
 *  - The login step (unsecure.recalculate_user_groups) treated synced rows
 *    like login-mapped rows: a login whose token lacked the group deleted the
 *    synced membership, the next sync added it back.
 *
 * Now:
 *
 *  - One source per group. A synced group (is_synced) takes its members only
 *    from the sync; login neither adds nor removes them. Other external /
 *    hybrid groups take mapped members from the token at login, as before.
 *  - Each per-mapping run reconciles fully: adds the staged members (creating
 *    missing users when create_missing_users_on_sync) and removes members of
 *    that mapping who are no longer staged. Removal deletes the membership
 *    only, never the user. A user in several mapped groups keeps the
 *    membership while any of their mappings still has them.
 *  - process_external_group_member_sync runs every mapping of the synced
 *    groups (optionally of one group). A mapping whose stage is empty loses
 *    all its members - load every mapping before running it.
 *  - Both need the new permission groups.sync_members in tenant 1 (the syncer
 *    serves every tenant); svc_group_syncer, system_admin and full_admin get
 *    it. The logic lives in unsecure.process_external_group_member_sync_by_mapping.
 *  - Syncing a group that is not is_synced raises 33025.
 */

set search_path = public, const, ext, stage, helpers, internal, unsecure, auth, triggers;

select *
from public.start_version_update('2.19', 'External group sync works',
                                 _component := 'postgresql_permissionmodel',
                                 _description := 'Synced groups take members only from the sync (login leaves them alone); each sync run adds and removes; groups.sync_members permission in tenant 1; the full sync no longer fails.');


insert into const.event_code (event_id, code, category_code, is_system, source)
values (33025, 'err_group_not_synced', 'user_error', true, 'core')
on conflict do nothing;

insert into const.event_message (event_id, language_code, message_template)
values (33025, 'en', 'User group (id: {user_group_id}) is not synchronized')
on conflict do nothing;

-- 33025: group sync requested for a group that is not is_synced
create or replace function error.raise_33025(_user_group_id integer) returns void
    language plpgsql
as
$$
begin
    raise exception 'User group (id: %) is not synchronized', _user_group_id
        using errcode = '33025';
end;
$$;


select unsecure.create_permission_as_system('Sync members', 'groups', true, _source := 'core')
where not exists(select from auth.permission where full_code = 'groups.sync_members');

select unsecure.create_perm_set_permissions('update_v2.19', 1, null, ps.perm_set_id
    , array ['groups.sync_members'], 1)
from auth.perm_set ps
where ps.code in ('svc_group_syncer_permissions', 'system_admin', 'full_admin')
  and ps.tenant_id = 1;


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

    insert into auth.user_group_member (created_by, user_group_id, user_id, member_type_code)
    select _created_by, ug.user_group_id, _target_user_id, 'manual'
    from auth.user_group ug
    where is_default
    on conflict (user_group_id, user_id, coalesce(mapping_id, 0)) do nothing;

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


create or replace function unsecure.process_external_group_member_sync_by_mapping(_run_by text, _user_id bigint, _correlation_id text, _user_group_mapping_id integer)
    returns TABLE(__user_group_id integer, __user_group_mapping_id integer, __state_code text, __user_id bigint, __upn text)
    language plpgsql
as
$$
declare
	__create_missing_users_on_sync bool;
	__user_group_id                int;
	__provider_code                text;
	__to_create_number             bigint;
	__is_synced                    bool;
	__tenant_id                    int;
	__removed_count                bigint;
begin
	select ugm.user_group_id, create_missing_users_on_sync, provider_code, ug.is_synced, ug.tenant_id
	from auth.user_group_mapping ugm
				 inner join auth.user_group ug on ugm.user_group_id = ug.user_group_id
	where ugm.user_group_mapping_id = _user_group_mapping_id
	into __user_group_id, __create_missing_users_on_sync, __provider_code, __is_synced, __tenant_id;

	if __user_group_id is null then
		perform error.raise_33022(_user_group_mapping_id, null);
	end if;

	-- only synced groups: their members come from the sync alone (v2.19)
	if not __is_synced then
		perform error.raise_33025(__user_group_id);
	end if;
	perform auth.validate_provider_allows_group_sync(__provider_code);
	drop table if exists __temp_current_members;
	create temporary table __temp_current_members as
	select ui.user_id, ui.username as upn
	from auth.user_group_member ugm
				 inner join auth.user_info ui on ugm.user_id = ui.user_id
	where ugm.mapping_id = _user_group_mapping_id;
	drop table if exists __temp_ensure_users;
	create temporary table __temp_ensure_users as
	select egm.external_group_member_id,
				 egm.member_upn,
				 egm.member_display_name,
				 egm.member_email,
				 egm.user_group_mapping_id
	from stage.external_group_member egm
				 left join auth.user_info ui on lower(egm.member_upn) = ui.username
	where egm.user_group_mapping_id = _user_group_mapping_id
		and ui.user_id is null;
	drop table if exists __temp_members_comparison;
	create temporary table __temp_members_comparison as
	select case
					 when current_members.user_id is null
						 then 'create'
					 else 'update' end as operation,
				 ui.user_id,
				 egm.user_group_mapping_id
	from stage.external_group_member egm
				 inner join auth.user_info ui on lower(egm.member_upn) = ui.username
				 left join __temp_current_members as current_members on lower(egm.member_upn) = current_members.upn
	where egm.user_group_mapping_id = _user_group_mapping_id;
	select count(1)
	from __temp_members_comparison
	where operation = 'create'
	into __to_create_number;
	drop table if exists __temp_ensured_users;
	create temporary table __temp_ensured_users as
	select user_group_mapping_id,
				 created_user.__user_id user_id
	from __temp_ensure_users eu,
			 unsecure.ensure_user_info(_run_by, _user_id, _correlation_id, member_upn,
														 member_display_name, __provider_code, member_email) created_user
	where __create_missing_users_on_sync;
	-- members of this mapping who are no longer staged lose the membership
	-- (never the user); other mappings of the group keep theirs
	drop table if exists __temp_removed_members;
	create temporary table __temp_removed_members as
	with removed as (
		delete
		from auth.user_group_member ugm
			using auth.user_info ui
		where ui.user_id = ugm.user_id
			and ugm.mapping_id = _user_group_mapping_id
			and not exists(select
										 from stage.external_group_member egm
										 where egm.user_group_mapping_id = _user_group_mapping_id
											 and lower(egm.member_upn) = ui.username)
		returning ugm.user_id)
	select user_id
	from removed;

	get diagnostics __removed_count = row_count;

	if __removed_count > 0 then
		perform public.create_journal_message_for_entity(_run_by, _user_id, _correlation_id
			, 13011  -- group_member_removed
			, 'group', __user_group_id
			, jsonb_build_object('user_group_mapping_id', _user_group_mapping_id
				, 'action', 'sync_cleanup', 'members_deleted', __removed_count)
			, 1);
	end if;

	return query
		with combined_create_users as materialized (select user_group_mapping_id,
																											 user_id
																								from __temp_ensured_users
																								union
																								select user_group_mapping_id,
																											 user_id
																								from __temp_members_comparison cm
																								where operation = 'create'),
				 created_members as materialized (
					 insert into auth.user_group_member (created_by, user_group_id, user_id, mapping_id, member_type_code)
						 select _run_by, __user_group_id, cu.user_id, cu.user_group_mapping_id, 'synced'
						 from combined_create_users cu
						 returning user_id),
				 updated_members as materialized (
					 update auth.user_group_member
						 set member_type_code = 'synced'
						 where mapping_id = _user_group_mapping_id and member_type_code != 'synced' and
									 user_id in (select user_id from __temp_members_comparison where operation = 'update')
						 returning user_id),
				 combined_results as (select 'created' operation, eu.user_id
															from __temp_ensured_users eu
															union
															select 'created' operation, cm.user_id
															from created_members cm
															union
															select 'updated', um.user_id
															from updated_members um
															union
															select 'deleted', rm.user_id
															from __temp_removed_members rm)
		select __user_group_id,
					 __user_group_mapping_id,
					 operation,
					 ui.user_id,
					 ui.username
		from combined_results cr
					 inner join auth.user_info ui on cr.user_id = ui.user_id;
	perform public.create_journal_message_for_entity(_run_by, _user_id, _correlation_id
		, 13030  -- group_members_synced
		, 'group', __user_group_id
		, jsonb_build_object('user_group_mapping_id', _user_group_mapping_id,
			'provider_code', __provider_code,
			'members_created', (select count(*) from __temp_members_comparison where operation = 'create'),
			'users_ensured', (select count(*) from __temp_ensured_users))
		, 1);
	drop table if exists __temp_ensure_users;
	drop table if exists __temp_ensured_users;
	drop table if exists __temp_current_members;
	drop table if exists __temp_members_comparison;
	drop table if exists __temp_removed_members;
end;
$$;


create or replace function auth.process_external_group_member_sync_by_mapping(_run_by text, _user_id bigint, _correlation_id text, _user_group_mapping_id integer)
    returns TABLE(__user_group_id integer, __user_group_mapping_id integer, __state_code text, __user_id bigint, __upn text)
    language plpgsql
as
$$
begin
	perform auth.has_permission(_user_id, _correlation_id, 'groups.sync_members', 1);  -- the syncer serves every tenant

	return query
		select s.__user_group_id, s.__user_group_mapping_id, s.__state_code, s.__user_id, s.__upn
		from unsecure.process_external_group_member_sync_by_mapping(_run_by, _user_id, _correlation_id, _user_group_mapping_id) s;
end;
$$;


-- Runs every mapping of the synced groups (or of one group). Load the stage for
-- every mapping first: a mapping with nothing staged loses all its members.
create or replace function auth.process_external_group_member_sync(_run_by text, _user_id bigint, _correlation_id text, _user_group_id integer DEFAULT NULL::integer)
    returns TABLE(__user_group_id integer, __user_group_mapping_id integer, __state_code text, __user_id bigint, __upn text)
    language plpgsql
as
$$
declare
	__mapping record;
begin
	perform auth.has_permission(_user_id, _correlation_id, 'groups.sync_members', 1);  -- the syncer serves every tenant

	for __mapping in
		select ugm.user_group_mapping_id
		from auth.user_group_mapping ugm
					 inner join auth.user_group ug on ug.user_group_id = ugm.user_group_id
					 inner join auth.provider p on p.code = ugm.provider_code
		where ug.is_synced
			and p.allows_group_sync
			and (_user_group_id is null or ug.user_group_id = _user_group_id)
		order by ug.user_group_id, ugm.user_group_mapping_id
		loop
			return query
				select s.__user_group_id, s.__user_group_mapping_id, s.__state_code, s.__user_id, s.__upn
				from unsecure.process_external_group_member_sync_by_mapping(_run_by, _user_id, _correlation_id
					, __mapping.user_group_mapping_id) s;
		end loop;
end;
$$;


select *
from public.stop_version_update('2.19', _component := 'postgresql_permissionmodel');
