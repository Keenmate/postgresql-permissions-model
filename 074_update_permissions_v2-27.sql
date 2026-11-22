/*
 * PostgreSQL Permissions Model — update v2.27
 * ===========================================
 *
 * Tenant membership events: joining and leaving a tenant (use cases 1-7,
 * audit/use-cases.md).
 *
 * Membership is computed (auth.tenant_memberships, v2.17), so leaving a tenant
 * means losing the last thing that made the user a member. Nothing calls a
 * function when an IdP drops a user from a group, so the change is detected:
 *
 *  - auth.tenant_membership_state is a snapshot of the memberships, filled from
 *    the view here without firing anything.
 *  - unsecure.reconcile_tenant_memberships(users) compares the snapshot with
 *    the view: a new membership fires on_join (new action event); a missing one
 *    gets a strike (not_found_strike_count, missing_since); one that comes back
 *    is reset; on_leave fires once the strikes reach
 *    tenant_membership.leave_strike_limit (default 1) and
 *    tenant_membership.leave_grace_minutes (default 0) have passed since it went
 *    missing. Like ad_object.not_found_strike_count in the document hub: a
 *    provider that sends no groups once (an outage, a groups overage) needn't
 *    make everyone leave. Journal 11016 tenant_member_joined / 11017
 *    tenant_member_left. System and API (technical) users are not tracked.
 *  - Observations: every provider login (ensure_groups_and_permissions), the
 *    group sync, the admin changes (group members, direct assignments, group
 *    assignments, owners, group enable/disable/delete) and the sweep
 *    auth.process_tenant_memberships, which the app calls on a schedule: it
 *    catches what no hook saw (resource grants, mapping changes, rule edits)
 *    and the grace periods that ran out. The permission-cache rebuild is not
 *    an observation.
 *  - Disabled or locked users don't leave; a deleted user leaves every tenant
 *    once (on_leave in delete_user_info, as before) and the snapshot rows go.
 *  - Platform actions on_join / on_leave run once per tenant joined or left;
 *    every on_join / on_leave run gets {data.tenant_id} and {data.tenant_code}.
 */

set search_path = public, const, ext, stage, helpers, internal, unsecure, auth, triggers;

select *
from public.start_version_update('2.27', 'Tenant membership events',
                                 _component := 'postgresql_permissionmodel',
                                 _description := 'Leaving a tenant = losing membership: a membership snapshot fires on_join for new memberships and on_leave for lost ones after a strike limit and a grace period (tenant_membership sys_params); observed at login, sync, admin changes and by the sweep auth.process_tenant_memberships.');


/***
 *    events, system parameters
 */

insert into const.action_event (code)
values ('on_join')
on conflict do nothing;

insert into const.event_code (event_id, code, category_code, is_system, source)
values (11016, 'tenant_member_joined', 'tenant_event', true, 'core'),
       (11017, 'tenant_member_left', 'tenant_event', true, 'core')
on conflict do nothing;

insert into const.event_message (event_id, language_code, message_template)
values (11016, 'en', 'User "{username}" joined tenant "{tenant_title}"'),
       (11017, 'en', 'User "{username}" left tenant "{tenant_title}" ({strike_count} strikes)')
on conflict do nothing;

insert into const.sys_param (group_code, code, text_value, number_value, is_system, created_by, updated_by)
values ('tenant_membership', 'leave_strike_limit', '1', 1, true, 'update_v2.27', 'update_v2.27'),
       ('tenant_membership', 'leave_grace_minutes', '0', 0, true, 'update_v2.27', 'update_v2.27')
on conflict (group_code, code) do nothing;


/***
 *    the snapshot
 */

create table if not exists auth.tenant_membership_state
(
    created_at             timestamptz default now()     not null,
    created_by             text        default 'unknown' not null,
    updated_at             timestamptz default now()     not null,
    updated_by             text        default 'unknown' not null,
    tenant_id              integer                       not null
        references auth.tenant on delete cascade,
    user_id                bigint                        not null
        references auth.user_info on delete cascade,
    missing_since          timestamptz,  -- null = a member
    not_found_strike_count integer     default 0         not null,
    constraint tenant_membership_state_pkey primary key (tenant_id, user_id),
    constraint tenant_membership_state_created_by_check check (length(created_by) <= 250),
    constraint tenant_membership_state_updated_by_check check (length(updated_by) <= 250)
);

create index if not exists ix_tenant_membership_state_user on auth.tenant_membership_state (user_id);
create index if not exists ix_tenant_membership_state_missing
    on auth.tenant_membership_state (missing_since)
    where missing_since is not null;

comment on table auth.tenant_membership_state is 'Snapshot of auth.tenant_memberships (v2.27): new rows fire on_join, missing ones collect strikes until on_leave fires. Kept by unsecure.reconcile_tenant_memberships';

-- today's members, without firing anything
insert into auth.tenant_membership_state (created_by, updated_by, tenant_id, user_id)
select distinct 'update_v2.27', 'update_v2.27', tm.tenant_id, tm.user_id
from auth.tenant_memberships tm
         inner join auth.user_info ui on ui.user_id = tm.user_id
where ui.user_type_code not in ('system', 'api')
on conflict do nothing;


-- compares the snapshot with auth.tenant_memberships for the users (null = all):
-- joined (on_join), missing (a strike), returned (reset), left (on_leave). Each
-- call is an observation. The snapshot changes before any action runs, so an
-- action that changes memberships (and reconciles again) sees it.
create or replace function unsecure.reconcile_tenant_memberships(_created_by text, _user_id bigint, _correlation_id text,
                                                                 _target_user_ids bigint[] default null)
    returns table(__tenant_id integer, __target_user_id bigint, __change_code text)
    language plpgsql
as
$$
declare
    __strike_limit  integer;
    __grace         interval;
    __row           record;
    __strikes       integer;
    __missing_since timestamptz;
    __events        jsonb := '[]';
    __event         jsonb;
begin
    select greatest(coalesce((select coalesce(sp.number_value, sp.text_value::bigint)
                              from const.sys_param sp
                              where sp.group_code = 'tenant_membership'
                                and sp.code = 'leave_strike_limit'), 1), 1)::integer
         , make_interval(mins => coalesce((select coalesce(sp.number_value, sp.text_value::bigint)
                                           from const.sys_param sp
                                           where sp.group_code = 'tenant_membership'
                                             and sp.code = 'leave_grace_minutes'), 0)::integer)
    into __strike_limit, __grace;

    for __row in
        with current_memberships as (
            select distinct tm.tenant_id
                          , tm.user_id
            from auth.tenant_memberships tm
                     inner join auth.user_info ui on ui.user_id = tm.user_id
            where ui.user_type_code not in ('system', 'api')
              and (_target_user_ids is null or tm.user_id = any (_target_user_ids)))
           , states as (
            select s.tenant_id
                 , s.user_id
                 , s.missing_since
            from auth.tenant_membership_state s
            where _target_user_ids is null
               or s.user_id = any (_target_user_ids))
        select coalesce(cm.tenant_id, st.tenant_id) as tenant_id
             , coalesce(cm.user_id, st.user_id)     as user_id
             , case
                   when st.user_id is null then 'joined'
                   when cm.user_id is null then 'missing'
                   else 'returned'
            end                                     as change_code
        from current_memberships cm
                 full join states st on st.tenant_id = cm.tenant_id and st.user_id = cm.user_id
        where st.user_id is null
           or cm.user_id is null
           or st.missing_since is not null
        order by 2, 1
    loop
        __change_code := __row.change_code;

        if __row.change_code = 'joined' then
            insert into auth.tenant_membership_state (created_by, updated_by, tenant_id, user_id)
            values (_created_by, _created_by, __row.tenant_id, __row.user_id)
            on conflict do nothing;

            if not found then
                continue;  -- an action of this run got there first
            end if;
        elsif __row.change_code = 'returned' then
            update auth.tenant_membership_state s
            set updated_by             = _created_by
              , updated_at             = now()
              , missing_since          = null
              , not_found_strike_count = 0
            where s.tenant_id = __row.tenant_id
              and s.user_id = __row.user_id;
        else
            update auth.tenant_membership_state s
            set updated_by             = _created_by
              , updated_at             = now()
              , missing_since          = coalesce(s.missing_since, now())
              , not_found_strike_count = s.not_found_strike_count + 1
            where s.tenant_id = __row.tenant_id
              and s.user_id = __row.user_id
            returning s.not_found_strike_count, s.missing_since
                into __strikes, __missing_since;

            if not found then
                continue;
            end if;

            if __strikes >= __strike_limit and __missing_since + __grace <= now() then
                delete
                from auth.tenant_membership_state s
                where s.tenant_id = __row.tenant_id
                  and s.user_id = __row.user_id;

                __change_code := 'left';
            end if;
        end if;

        if __change_code in ('joined', 'left') then
            __events := __events || jsonb_build_object('tenant_id', __row.tenant_id, 'user_id', __row.user_id
                , 'change_code', __change_code, 'strike_count', __strikes);
        end if;

        __tenant_id := __row.tenant_id;
        __target_user_id := __row.user_id;
        return next;
    end loop;

    -- the journal and the actions, once the snapshot is settled
    for __event in select e from jsonb_array_elements(__events) e
    loop
        perform public.create_journal_message_for_entity(_created_by, _user_id, _correlation_id
            , case when __event ->> 'change_code' = 'joined' then 11016 else 11017 end  -- tenant_member_joined / _left
            , 'tenant', (__event ->> 'tenant_id')::integer
            , jsonb_build_object('username', (select ui.username from auth.user_info ui where ui.user_id = (__event ->> 'user_id')::bigint)
                , 'tenant_title', (select t.title from auth.tenant t where t.tenant_id = (__event ->> 'tenant_id')::integer)
                , 'target_user_id', (__event ->> 'user_id')::bigint
                , 'strike_count', (__event ->> 'strike_count')::integer)
            , (__event ->> 'tenant_id')::integer);

        perform unsecure.run_actions(_created_by, _user_id, _correlation_id
            , case when __event ->> 'change_code' = 'joined' then 'on_join' else 'on_leave' end
            , (__event ->> 'user_id')::bigint
            , _tenant_id := (__event ->> 'tenant_id')::integer
            , _extra_data := jsonb_build_object('tenant_id', (__event ->> 'tenant_id')::integer
                , 'tenant_code', (select t.code from auth.tenant t where t.tenant_id = (__event ->> 'tenant_id')::integer)));
    end loop;
end;
$$;

-- the sweep: the app calls it on a schedule (for everyone or one user); it is an
-- observation like a login
create or replace function auth.process_tenant_memberships(_run_by text, _user_id bigint, _correlation_id text,
                                                           _target_user_id bigint default null)
    returns table(__tenant_id integer, __target_user_id bigint, __change_code text)
    language plpgsql
as
$$
begin
    perform auth.has_permission(_user_id, _correlation_id, 'actions.process_action_steps', 1);

    return query
        select r.__tenant_id, r.__target_user_id, r.__change_code
        from unsecure.reconcile_tenant_memberships(_run_by, _user_id, _correlation_id
                 , case when _target_user_id is not null then array [_target_user_id] end) r;
end;
$$;


/***
 *    the observations
 */

create or replace function triggers.validate_sys_param() returns trigger
    language plpgsql
as
$$
begin
    if tg_op = 'DELETE' then
        if old.is_system then
            perform error.raise_31015(old.group_code, old.code);
        end if;
        return old;
    end if;

    if tg_op = 'UPDATE' and old.is_system and not new.is_system then
        perform error.raise_31015(old.group_code, old.code);
    end if;

    if new.group_code = 'login_lockout' then
        if new.code = 'lockout_durations_minutes'
            and coalesce(new.text_value, '') !~ '^\s*[1-9][0-9]*(\s*,\s*[1-9][0-9]*)*\s*$' then
            perform error.raise_31016(new.group_code, new.code, new.text_value);
        end if;

        if new.code in ('max_failed_attempts', 'window_minutes', 'lockout_reset_hours')
            and coalesce(new.number_value::text, new.text_value, '') !~ '^\s*[1-9][0-9]*\s*$' then
            perform error.raise_31016(new.group_code, new.code, coalesce(new.number_value::text, new.text_value));
        end if;
    end if;

    -- tenant membership events (v2.27)
    if new.group_code = 'tenant_membership' then
        if new.code = 'leave_strike_limit'
            and coalesce(new.number_value::text, new.text_value, '') !~ '^\s*[1-9][0-9]*\s*$' then
            perform error.raise_31016(new.group_code, new.code, coalesce(new.number_value::text, new.text_value));
        end if;

        if new.code = 'leave_grace_minutes'
            and coalesce(new.number_value::text, new.text_value, '') !~ '^\s*[0-9]+\s*$' then
            perform error.raise_31016(new.group_code, new.code, coalesce(new.number_value::text, new.text_value));
        end if;
    end if;

    return new;
end;
$$;

create or replace function auth.ensure_groups_and_permissions(_created_by text, _user_id bigint, _correlation_id text, _target_user_id bigint, _provider_code text, _provider_groups text[] DEFAULT NULL::text[], _provider_roles text[] DEFAULT NULL::text[], _tenant_id integer DEFAULT 1)
    returns TABLE(__tenant_id integer, __tenant_uuid uuid, __groups text[], __permissions text[], __short_code_permissions text[])
    rows 1
    language plpgsql
as
$$
begin
    perform
        auth.has_permission(_user_id, _correlation_id, 'authentication.ensure_permissions', _tenant_id);

    update auth.user_identity
    set updated_by      = _created_by
      , updated_at      = now()
      , provider_groups = _provider_groups
      , provider_roles  = _provider_roles
    where provider_code = _provider_code
      and user_id = _target_user_id;

    drop table if exists __temp_users_groups;  -- callable more than once per transaction

    create temporary table __temp_users_groups on commit drop as
    select ug.__tenant_id       as tenant_id
         , ug.__user_group_id   as user_group_id
         , ug.__user_group_code as user_group_code
    from unsecure.recalculate_user_groups(_created_by
             , _target_user_id
             , _provider_code
             ) ug;

    -- tenant membership events (v2.27): every login is an observation (on_join / on_leave)
    perform unsecure.reconcile_tenant_memberships(_created_by, _user_id, _correlation_id, array [_target_user_id]);

    -- actions (v2.25): the login, with fresh provider groups and roles; the claims are the event data
    perform unsecure.run_actions(_created_by, _user_id, _correlation_id, 'on_entry', _target_user_id
        , _provider_code
        , _extra_data := (select uid.user_data
                          from auth.user_identity uid
                          where uid.user_id = _target_user_id
                            and uid.provider_code = _provider_code
                          order by uid.updated_at desc
                          limit 1));

    return query
        select up.__tenant_id
             , up.__tenant_uuid
             , up.__groups
             , up.__permissions
             , up.__short_code_permissions
        from unsecure.recalculate_user_permissions(_created_by
                 , _target_user_id, null) up;
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

	-- tenant membership events (v2.27): the members this run removed or kept
	perform unsecure.reconcile_tenant_memberships(_run_by, _user_id, _correlation_id
		, array(select rm.user_id
				from __temp_removed_members rm
				union
				select ugm.user_id
				from auth.user_group_member ugm
				where ugm.mapping_id = _user_group_mapping_id));

	drop table if exists __temp_ensure_users;
	drop table if exists __temp_ensured_users;
	drop table if exists __temp_current_members;
	drop table if exists __temp_members_comparison;
	drop table if exists __temp_removed_members;
end;
$$;

create or replace function unsecure.create_user_group_member(_created_by text, _user_id bigint, _correlation_id text, _user_group_id integer, _target_user_id bigint, _tenant_id integer DEFAULT 1)
    returns TABLE(__user_group_member_id bigint)
    rows 1
    language plpgsql
as
$$
declare
	__is_assignable   bool;
	__is_external     bool;
	__is_active       bool;
	__user_group_code text;
	__user_upn        text;
begin

	select is_assignable, is_external, is_active
	from auth.user_group ug
	where ug.user_group_id = _user_group_id
	into __is_assignable, __is_external, __is_active;

	if __is_active is null then
		perform error.raise_52171(_user_group_id);
	end if;

	if not __is_active then
		perform error.raise_52172(_user_group_id);
	end if;

	if not __is_assignable or __is_external then
		perform error.raise_52173(_user_group_id);
	end if;

	select code
	from auth.user_group
	where user_group_id = _user_group_id
	into __user_group_code;

	select code
	from auth.user_info
	where user_id = _target_user_id
	into __user_upn;

	return query insert into auth.user_group_member (created_by, user_group_id, user_id, member_type_code)
		values (_created_by, _user_group_id, _target_user_id, 'manual')
		returning member_id;

	-- Invalidate permission cache so user picks up group permissions immediately
	perform unsecure.clear_permission_cache(_created_by, _target_user_id, _tenant_id);

	-- tenant membership events (v2.27)
	perform unsecure.reconcile_tenant_memberships(_created_by, _user_id, _correlation_id, array [_target_user_id]);

	perform public.create_journal_message_for_entity(_created_by, _user_id, _correlation_id
			, 13010  -- group_member_added
			, 'group', _user_group_id
			, jsonb_build_object('username', __user_upn, 'group_title', __user_group_code
				, 'target_user_id', _target_user_id)
			, _tenant_id);
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

	perform unsecure.validate_user_group_access(_user_id, _correlation_id, _user_group_id, _tenant_id);
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

	-- tenant membership events (v2.27)
	perform unsecure.reconcile_tenant_memberships(_deleted_by, _user_id, _correlation_id, array [_target_user_id]);

	perform public.create_journal_message_for_entity(_deleted_by, _user_id, _correlation_id
			, 13011  -- group_member_removed
			, 'group', _user_group_id
			, jsonb_build_object('username', __user_upn, 'group_title', __user_group_code
				, 'target_user_id', _target_user_id)
			, _tenant_id);
end;
$$;

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

	-- tenant membership events (v2.27): the user, or the group's members
	perform unsecure.reconcile_tenant_memberships(_created_by, _user_id, _correlation_id
		, case
			when _user_group_id is not null then array(select ugm.user_id
												from auth.user_group_member ugm
												where ugm.user_group_id = _user_group_id)
			else array [_target_user_id] end);
end;
$$;

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

	-- tenant membership events (v2.27): the user, or the group's members
	perform unsecure.reconcile_tenant_memberships(_deleted_by, _user_id, _correlation_id
		, case
			when __user_group_id is not null then array(select ugm.user_id
												from auth.user_group_member ugm
												where ugm.user_group_id = __user_group_id)
			else array [__target_user_id] end);
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
		perform unsecure.validate_user_group_access(_user_id, _correlation_id, _user_group_id, _tenant_id);
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

	-- tenant membership events (v2.27)
	perform unsecure.reconcile_tenant_memberships(_created_by, _user_id, _correlation_id, array [_target_user_id]);
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
		perform unsecure.validate_user_group_access(_user_id, _correlation_id, _user_group_id, _tenant_id);
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

	-- tenant membership events (v2.27)
	perform unsecure.reconcile_tenant_memberships(_deleted_by, _user_id, _correlation_id, array [_target_user_id]);
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

	perform unsecure.validate_user_group_access(_user_id, _correlation_id, _user_group_id, _tenant_id);

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

	-- tenant membership events (v2.27): every member
	perform unsecure.reconcile_tenant_memberships(_updated_by, _user_id, _correlation_id
		, array(select ugm.user_id from auth.user_group_member ugm where ugm.user_group_id = _user_group_id));
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

	perform unsecure.validate_user_group_access(_user_id, _correlation_id, _user_group_id, _tenant_id);

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

	-- tenant membership events (v2.27): every member
	perform unsecure.reconcile_tenant_memberships(_updated_by, _user_id, _correlation_id
		, array(select ugm.user_id from auth.user_group_member ugm where ugm.user_group_id = _user_group_id));
end;
$$;

create or replace function auth.delete_user_group(_deleted_by text, _user_id bigint, _correlation_id text, _user_group_id integer, _tenant_id integer DEFAULT 1)
    returns TABLE(__user_group_id integer)
    rows 1
    language plpgsql
as
$$
declare
	__is_system  bool;
	__member_ids bigint[];
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

	__member_ids := array(select ugm.user_id from auth.user_group_member ugm where ugm.user_group_id = _user_group_id);

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

	-- tenant membership events (v2.27): the members it had
	perform unsecure.reconcile_tenant_memberships(_deleted_by, _user_id, _correlation_id, __member_ids);
end;
$$;

select *
from public.stop_version_update('2.27', _component := 'postgresql_permissionmodel');
