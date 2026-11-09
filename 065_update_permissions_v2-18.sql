/*
 * PostgreSQL Permissions Model — update v2.18
 * ===========================================
 *
 * Pre-provisioned users (follow-up to v2.4 and D-03).
 *
 * An invitation service creates users before their first login with
 * auth.ensure_user_info, and admins add them to groups. Since v2.4 the first
 * provider login of such a user failed with 33024 (no linking by username), so
 * pre-provisioning did not work at all. And auth.ensure_user_info had no
 * permission check: any caller could create users.
 *
 *  - auth.ensure_user_info needs users.register_user in tenant 1 (a service
 *    account permission; svc_registrator and svc_group_syncer hold it). The
 *    logic moves to unsecure.ensure_user_info, which the group member sync
 *    now calls.
 *  - Variant A, pre-provisioned identity: ensure_user_info takes an optional
 *    _provider_oid (with _provider_code). It creates the identity right away
 *    (no uid yet). The first login matches it by the provider's object id and
 *    fills in the uid. The username is never trusted.
 *  - Variant B, claim by username: when only an email is known, a first login
 *    claims an existing user if the user has no identities at all and was
 *    pre-provisioned for exactly this provider (last_used_provider_code). Any
 *    other username clash still returns 33024. The client must pass a
 *    provider-verified username (Azure: UPN / preferred_username, never the
 *    email claim).
 *  - auth.ensure_groups_and_permissions can run more than once per
 *    transaction (its temp table already existed on the second call).
 */

set search_path = public, const, ext, stage, helpers, internal, unsecure, auth, triggers;

select *
from public.start_version_update('2.18', 'Pre-provisioned users',
                                 _component := 'postgresql_permissionmodel',
                                 _description := 'ensure_user_info needs users.register_user in tenant 1 and can pre-create the provider identity by object id; a first login claims a pre-provisioned user without identities for the provider it was pre-provisioned for.');


-- Several pre-provisioned identities of one provider have no uid yet; the
-- index allowed only one null uid per provider
drop index if exists auth.uq_user_identity;
create unique index uq_user_identity
    on auth.user_identity (provider_code, uid)
    where uid is not null;


drop function if exists auth.ensure_user_info(text, bigint, text, text, text, text, text, jsonb);

create or replace function unsecure.ensure_user_info(_created_by text, _user_id bigint, _correlation_id text, _username text, _display_name text, _provider_code text default null, _email text default null, _user_data jsonb default null, _provider_oid text default null)
    returns table(__user_id bigint, __code text, __uuid text, __username text, __email text, __display_name text)
    language plpgsql
as
$$
declare
	__last_id      bigint;
	__username     text;
	__oid_user_id  bigint;
begin

	__username := trim(lower(_username));

	select u.user_id
	from auth.user_info u
	where u.username = __username
	into __last_id;

	if
		__last_id is null then
		select user_id
		from unsecure.create_user_info(_created_by, _user_id, _correlation_id, __username, lower(_email), _display_name,
																	 _provider_code)
		into __last_id;
	end if;

	-- variant A: pre-create the identity by the provider's object id; the first
	-- login matches it by oid and fills in the uid
	if _provider_code is not null and _provider_oid is not null then
		select uid.user_id
		from auth.user_identity uid
		where uid.provider_oid = _provider_oid
		into __oid_user_id;

		if __oid_user_id is not null and __oid_user_id <> __last_id then
			perform error.raise_33007(_provider_oid);
		end if;

		if __oid_user_id is null
			and not exists(select from auth.user_identity
										 where user_id = __last_id and provider_code = _provider_code) then
			perform unsecure.create_user_identity(_created_by, _user_id, _correlation_id, __last_id
				, _provider_code, null, _provider_oid
				, _is_active := true, _is_verified := false);
		end if;
	end if;

	return query
		select ui.user_id
				 , ui.code
				 , ui.uuid::text
				 , ui.username
				 , ui.email
				 , ui.display_name
		from auth.user_info ui
		where ui.user_id = __last_id;
end;
$$;

-- Pre-provisioning is a service-account operation (invitation service, group sync)
create or replace function auth.ensure_user_info(_created_by text, _user_id bigint, _correlation_id text, _username text, _display_name text, _provider_code text default null, _email text default null, _user_data jsonb default null, _provider_oid text default null)
    returns table(__user_id bigint, __code text, __uuid text, __username text, __email text, __display_name text)
    language plpgsql
as
$$
begin
	perform auth.has_permission(_user_id, _correlation_id, 'users.register_user', 1);  -- users are global (D-04)

	return query
		select eu.__user_id, eu.__code, eu.__uuid, eu.__username, eu.__email, eu.__display_name
		from unsecure.ensure_user_info(_created_by, _user_id, _correlation_id, _username, _display_name
			, _provider_code, _email, _user_data, _provider_oid) eu;
end;
$$;


create or replace function auth.process_external_group_member_sync_by_mapping(_run_by text, _user_id bigint, _correlation_id text, _user_group_mapping_id integer)
    returns TABLE(__user_group_id integer, __user_group_mapping_id integer, __state_code text, __user_id bigint, __upn text)
    language plpgsql
as
$$
declare
	__create_missing_users_on_sync bool;
	__user_group_id                int;
	__provider_code                text;
	__to_create_number             bigint;
begin

	--   perform auth.has_permission(_user_id, '');

	select ugm.user_group_id, create_missing_users_on_sync, provider_code
	from auth.user_group_mapping ugm
				 inner join auth.user_group ug on ugm.user_group_id = ug.user_group_id
	where ugm.user_group_mapping_id = _user_group_mapping_id
	into __user_group_id, __create_missing_users_on_sync, __provider_code;

	perform auth.validate_provider_allows_group_sync(__provider_code);

	create temporary table __temp_current_members as
	select ui.user_id, ui.username as upn
	from auth.user_group_member ugm
				 inner join auth.user_info ui on ugm.user_id = ui.user_id
	where ugm.mapping_id = _user_group_mapping_id;

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

	create temporary table __temp_ensured_users as
	select user_group_mapping_id,
				 created_user.__user_id user_id
	from __temp_ensure_users eu,
			 unsecure.ensure_user_info(_run_by, _user_id, _correlation_id, member_upn,
														 member_display_name, __provider_code, member_email) created_user
	where __create_missing_users_on_sync;


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
															from updated_members um)
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


create or replace function auth.ensure_user_from_provider(_created_by text, _user_id bigint, _correlation_id text, _provider_code text, _provider_uid text, _provider_oid text, _username text, _display_name text, _email text DEFAULT NULL::text, _user_data jsonb DEFAULT NULL::jsonb, _request_context jsonb DEFAULT NULL::jsonb)
    returns TABLE(__user_id bigint, __code text, __uuid text, __username text, __email text, __display_name text
		, __event_id integer, __outcome_code text, __user_event_id bigint)
    rows 1
    language plpgsql
as
$$
declare
	__target_user_id   bigint;
	__identity_uid     text;
	___username        text;
	___display_name    text;
	___email           text;
	__identity_data    jsonb;
	__check            record;
	___user_event_id   bigint;
	___claim_user_id   bigint;
begin

	if
		lower(_provider_code) = 'email' then
		perform error.raise_52101(_username);
	end if;

	perform
		auth.validate_provider_is_active(_provider_code);

	select uid.user_id, uid.uid, u.username, u.display_name, u.email, uid.user_data
	from auth.user_identity uid
				 inner join auth.user_info u on uid.user_id = u.user_id
	where uid.provider_code = _provider_code
		and (uid.uid = _provider_uid or uid.provider_oid = _provider_oid)
	into __target_user_id, __identity_uid, ___username, ___display_name, ___email, __identity_data;

	-- variant B: a user pre-provisioned for this provider who has never logged in
	-- (no identities at all) is claimed by the first login with the same username
	if __target_user_id is null then
		select ui.user_id
		from auth.user_info ui
		where ui.username = lower(trim(_username))
			and ui.last_used_provider_code = _provider_code
			and not exists(select from auth.user_identity uid where uid.user_id = ui.user_id)
		into ___claim_user_id;

		if ___claim_user_id is not null then
			perform unsecure.create_user_identity(_created_by, _user_id, _correlation_id, ___claim_user_id
				, _provider_code, _provider_uid, _provider_oid, _user_data := _user_data::text
				, _is_active := true, _is_verified := true);

			perform public.create_journal_message_for_entity(_created_by, _user_id, _correlation_id
				, 10031  -- identity_updated
				, 'user', ___claim_user_id
				, jsonb_build_object('provider_code', _provider_code, 'provider_uid', _provider_uid
					, 'action', 'pre_provisioned_user_claimed')
				, 1);

			select uid.user_id, uid.uid, u.username, u.display_name, u.email, uid.user_data
			from auth.user_identity uid
												 inner join auth.user_info u on uid.user_id = u.user_id
			where uid.provider_code = _provider_code
						and (uid.uid = _provider_uid or uid.provider_oid = _provider_oid)
			into __target_user_id, __identity_uid, ___username, ___display_name, ___email, __identity_data;
		end if;
	end if;

	-- variant A: identity pre-created by object id, first login fills in the uid
	if __target_user_id is not null and __identity_uid is null then
		update auth.user_identity
		set uid         = _provider_uid
			, is_verified = true
			, updated_by  = _created_by
			, updated_at  = now()
		where user_id = __target_user_id
			and provider_code = _provider_code
			and provider_oid = _provider_oid
			and uid is null;

		__identity_uid := _provider_uid;

		perform public.create_journal_message_for_entity(_created_by, _user_id, _correlation_id
			, 10031  -- identity_updated
			, 'user', __target_user_id
			, jsonb_build_object('provider_code', _provider_code, 'provider_uid', _provider_uid
				, 'action', 'pre_provisioned_identity_claimed')
			, 1);
	end if;

	if
		__target_user_id is null then
		-- check blacklist by provider identity (primary check for OAuth users)
		if unsecure.check_user_blacklist(
			_provider_code := _provider_code,
			_provider_uid := _provider_uid,
			_provider_oid := _provider_oid
		) then
			perform error.raise_33019(_provider_code, coalesce(_provider_uid, _provider_oid));
		end if;

		-- never attach a new identity to an existing user by username (v2.4),
		-- except the pre-provisioned claim above (v2.18)
		if exists(select from auth.user_info where username = lower(trim(_username))) then
			select e.__user_event_id
			from unsecure.create_user_event(_created_by, _user_id, _correlation_id, 'user_login_failed', null
				, _request_context := _request_context
				, _event_data := jsonb_build_object('provider', _provider_code, 'provider_uid', _provider_uid
					, 'username', lower(trim(_username)), 'reason', 'username_taken')) e
			into ___user_event_id;

			return query select null::bigint, null::text, null::text, null::text, null::text, null::text
				, 33024, 'err_username_already_exists', ___user_event_id;
			return;
		end if;

		select user_id
		from unsecure.create_user_info(_created_by, _user_id, _correlation_id, lower(_username), lower(_email), _display_name,
																	 _provider_code)
		into __target_user_id;

		perform
			unsecure.create_user_identity(_created_by, _user_id, _correlation_id, __target_user_id
				, _provider_code, _provider_uid, _provider_oid, _user_data := _user_data::text
				, _is_active := true, _is_verified := true);

		perform unsecure.create_user_event(_created_by, _user_id, _correlation_id, 'user_registered',
			__target_user_id,
			_request_context := _request_context,
			_event_data := jsonb_build_object('provider', _provider_code, 'provider_uid', _provider_uid));
	else
		select * from unsecure.check_user_can_login(__target_user_id, _provider_code, __identity_uid) into __check;

		if __check.__event_id is not null then
			select e.__user_event_id
			from unsecure.create_user_event(_created_by, _user_id, _correlation_id, 'user_login_failed', __target_user_id
				, _request_context := _request_context
				, _event_data := jsonb_build_object('provider', _provider_code, 'provider_uid', _provider_uid
					, 'reason', __check.__reason)) e
			into ___user_event_id;

			return query select null::bigint, null::text, null::text, null::text, null::text, null::text
				, __check.__event_id, __check.__outcome_code, ___user_event_id;
			return;
		end if;

		-- update provider_oid
		perform unsecure.update_user_identity_uid_oid(_created_by, _user_id, _correlation_id, __target_user_id
			, _provider_code, _provider_uid
			, _provider_oid);

		-- update basic user data coming from the provider
		if
			(trim(lower(_username)) <> ___username
				or _display_name <> ___display_name
				or lower(trim(_email)) is distinct from ___email) then
			perform unsecure.update_user_info_basic_data(_created_by, _user_id, _correlation_id, __target_user_id, _username, _display_name,
																									 _email);
		end if;

		-- refresh the provider data snapshot; null means the caller sent nothing, keep what is stored
		if _user_data is not null and _user_data is distinct from __identity_data then
			update auth.user_identity
			set user_data  = _user_data
				, updated_by = _created_by
				, updated_at = now()
			where user_id = __target_user_id
				and provider_code = _provider_code
				and uid = _provider_uid;

			perform public.create_journal_message_for_entity(_created_by, _user_id, _correlation_id
				, 10031  -- identity_updated
				, 'user', __target_user_id
				, jsonb_build_object('provider_code', _provider_code
					, 'user_data_keys', case when jsonb_typeof(_user_data) = 'object'
						then (select array_agg(k) from jsonb_object_keys(_user_data) k) end)
				, 1);
		end if;
	end if;

	-- clean all previous uids for the same provider for given user
	delete
	from auth.user_identity
	where user_id = __target_user_id
		and provider_code = _provider_code
		and uid <> _provider_uid;

	perform
		unsecure.update_last_used_provider(__target_user_id, _provider_code);

	select e.__user_event_id
	from unsecure.create_user_event(_created_by, _user_id, _correlation_id, 'user_logged_in', __target_user_id
		, _request_context := _request_context
		, _event_data := jsonb_build_object('provider', _provider_code, 'provider_uid', _provider_uid)) e
	into ___user_event_id;

	return query
		select ui.user_id
				 , ui.code
				 , ui.uuid::text
				 , ui.username
				 , ui.email
				 , ui.display_name
				 , 10010
				 , 'user_logged_in'
				 , ___user_event_id
		from auth.user_identity uid
					 inner join auth.user_info ui on uid.user_id = ui.user_id
		where uid.provider_code = _provider_code
			and uid.uid = _provider_uid;
end;
$$;


select *
from public.stop_version_update('2.18', _component := 'postgresql_permissionmodel');
