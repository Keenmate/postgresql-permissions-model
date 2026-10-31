/*
 * PostgreSQL Permissions Model — update v2.3
 * ==========================================
 *
 *  - auth.ensure_user_from_provider took _user_data jsonb and never used it, so
 *    the provider data passed on login was dropped and user_identity.user_data
 *    stayed empty. It is now stored on the identity:
 *      - first login: the new identity is created with it
 *      - later logins: a non-null _user_data replaces the stored snapshot
 *        (journal 10031 identity_updated when it changed); null leaves it as is
 *    Read it back with auth.get_user_identity / auth.get_user_identity_by_email
 *    (__user_data).
 */

set search_path = public, const, ext, stage, helpers, internal, unsecure, auth, triggers;

select *
from public.start_version_update('2.3', 'Store provider user data on the identity',
                                 _component := 'postgresql_permissionmodel',
                                 _description := 'auth.ensure_user_from_provider stores _user_data in user_identity.user_data on first login and refreshes it on later logins.');


create or replace function auth.ensure_user_from_provider(_created_by text, _user_id bigint, _correlation_id text, _provider_code text, _provider_uid text, _provider_oid text, _username text, _display_name text, _email text DEFAULT NULL::text, _user_data jsonb DEFAULT NULL::jsonb, _request_context jsonb DEFAULT NULL::jsonb)
    returns TABLE(__user_id bigint, __code text, __uuid text, __username text, __email text, __display_name text)
    language plpgsql
as
$$
declare
	__target_user_id     bigint;
	__can_login          bool;
	__is_user_active     bool;
	__is_identity_active bool;
	__username           text;
	__display_name       text;
	__email              text;
	__identity_data      jsonb;
begin

	if
		lower(_provider_code) = 'email' then
		perform error.raise_52101(_username);
	end if;

	perform
		auth.validate_provider_is_active(_provider_code);

	select uid.user_id, u.is_active, uid.is_active, u.can_login, u.username, u.display_name, u.email, uid.user_data
	from auth.user_identity uid
				 inner join auth.user_info u on uid.user_id = u.user_id
	where uid.provider_code = _provider_code
		and (uid.uid = _provider_uid or uid.provider_oid = _provider_oid)
	into __target_user_id, __is_user_active, __is_identity_active, __can_login, __username, __display_name, __email, __identity_data;

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

		-- create user because it does not exists
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
		-- update provider_oid
		perform unsecure.update_user_identity_uid_oid(_created_by, _user_id, _correlation_id, __target_user_id
			, _provider_code, _provider_uid
			, _provider_oid);

		-- update basic user data coming from
		if
			(trim(lower(_username)) <> __username
				or _display_name <> __display_name
				or lower(trim(_email)) is distinct from __email) then
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

		if
			not __can_login then
			perform unsecure.create_user_event(_created_by, _user_id, _correlation_id, 'user_login_failed',
				__target_user_id,
				_request_context := _request_context,
				_event_data := jsonb_build_object('provider', _provider_code, 'provider_uid', _provider_uid, 'reason', 'login_disabled'));
			perform error.raise_52112(__target_user_id);
		end if;

		if
			not __is_user_active then
			perform unsecure.create_user_event(_created_by, _user_id, _correlation_id, 'user_login_failed',
				__target_user_id,
				_request_context := _request_context,
				_event_data := jsonb_build_object('provider', _provider_code, 'provider_uid', _provider_uid, 'reason', 'user_disabled'));
			perform error.raise_52105(__target_user_id);
		end if;

		if
			not __is_identity_active then
			perform unsecure.create_user_event(_created_by, _user_id, _correlation_id, 'user_login_failed',
				__target_user_id,
				_request_context := _request_context,
				_event_data := jsonb_build_object('provider', _provider_code, 'provider_uid', _provider_uid, 'reason', 'identity_disabled'));
			perform error.raise_52110(__target_user_id, _provider_code);
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

	perform unsecure.create_user_event(_created_by, _user_id, _correlation_id, 'user_logged_in',
		__target_user_id,
		_request_context := _request_context,
		_event_data := jsonb_build_object('provider', _provider_code, 'provider_uid', _provider_uid));

	return query
		select ui.user_id
				 , ui.code
				 , ui.uuid::text
				 , ui.username
				 , ui.email
				 , ui.display_name
		from auth.user_identity uid
					 inner join auth.user_info ui on uid.user_id = ui.user_id
		where uid.provider_code = _provider_code
			and uid.uid = _provider_uid;
end;
$$;


select *
from public.stop_version_update('2.3', _component := 'postgresql_permissionmodel');
