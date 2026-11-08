/*
 * PostgreSQL Permissions Model — update v2.9
 * ==========================================
 *
 * Global user state needs the permission in tenant 1 (audit decision D-04,
 * option a). Users are global: their status, password, identities, profile,
 * MFA and the blacklist apply everywhere. These functions checked the caller's
 * permission in whatever _tenant_id was passed, so an admin of any tenant could
 * lock, disable, delete, re-password or reset MFA of any user - tenant-1
 * admins included.
 *
 * The permission is now checked in tenant 1, whatever _tenant_id is passed
 * (_tenant_id is still used for the journal). Self-service stays free where it
 * was: own password, own identity link, own profile data and preferences.
 *
 *  - lock_user, unlock_user, enable_user, disable_user, delete_user_info
 *  - update_user_password, update_user_data, update_user_preferences (others)
 *  - enable_user_identity, disable_user_identity, verify_user_identity,
 *    create_user_identity_link (others)
 *  - enroll_mfa, confirm_mfa_enrollment, disable_mfa, reset_mfa
 *  - create_blacklist_user, delete_blacklist_user
 *
 * Also: unsecure.verify_user_identity called the nonexistent
 * error.raise_52001 for an unknown user; it raises 33001.
 */

set search_path = public, const, ext, stage, helpers, internal, unsecure, auth, triggers;

select *
from public.start_version_update('2.9', 'Global user state needs the permission in tenant 1',
                                 _component := 'postgresql_permissionmodel',
                                 _description := 'Lock/unlock/enable/disable/delete user, password, identities, profile data, MFA and blacklist check the permission in tenant 1 instead of _tenant_id; self-service unchanged.');


/***
 *    ███████╗██╗   ██╗███╗   ██╗ ██████╗████████╗██╗ ██████╗ ███╗   ██╗███████╗
 *    ██╔════╝██║   ██║████╗  ██║██╔════╝╚══██╔══╝██║██╔═══██╗████╗  ██║██╔════╝
 *    █████╗  ██║   ██║██╔██╗ ██║██║        ██║   ██║██║   ██║██╔██╗ ██║███████╗
 *    ██╔══╝  ██║   ██║██║╚██╗██║██║        ██║   ██║██║   ██║██║╚██╗██║╚════██║
 *    ██║     ╚██████╔╝██║ ╚████║╚██████╗   ██║   ██║╚██████╔╝██║  ██║███████║
 *    ╚═╝      ╚═════╝ ╚═╝  ╚═══╝ ╚═════╝   ╚═╝   ╚═╝ ╚═════╝ ╚═╝  ╚═══╝╚══════╝
 *
 */

create or replace function auth.lock_user(_updated_by text, _user_id bigint, _correlation_id text, _target_user_id bigint,
    _request_context jsonb default null, _tenant_id integer default 1)
    returns TABLE(__user_id bigint, __is_active boolean, __is_locked boolean)
    rows 1
    language plpgsql
as
$$
begin
	perform
		auth.has_permission(_user_id, _correlation_id, 'users.lock_user', 1);  -- global user state: permission in tenant 1 (D-04)

	return query
		update auth.user_info
			set updated_by = _updated_by
				, updated_at = now()
				, is_locked = true
			where is_system = false
				and user_id = _target_user_id
			returning user_id
				, is_active
				, is_locked;

	-- Clear permission cache for all tenants to ensure immediate effect
	perform unsecure.clear_permission_cache(_updated_by, _target_user_id, null);

	perform public.create_journal_message_for_entity(_updated_by, _user_id, _correlation_id
			, 10006  -- user_locked
			, 'user', _target_user_id
			, jsonb_build_object('username', _target_user_id::text)
			, 1
			, _request_context);

	perform unsecure.create_user_event(_updated_by, _user_id, _correlation_id,
		'user_locked', _target_user_id, _request_context := _request_context);
end;
$$;

create or replace function auth.unlock_user(_updated_by text, _user_id bigint, _correlation_id text, _target_user_id bigint,
    _request_context jsonb default null, _tenant_id integer default 1)
    returns TABLE(__user_id bigint, __is_active boolean, __is_locked boolean)
    rows 1
    language plpgsql
as
$$
begin
	perform
		auth.has_permission(_user_id, _correlation_id, 'users.unlock_user', 1);  -- global user state: permission in tenant 1 (D-04)

	return query
		update auth.user_info
			set updated_by = _updated_by
				, updated_at = now()
				, is_locked = false
			where is_system = false
				and user_id = _target_user_id
			returning user_id
				, is_active
				, is_locked;

	perform public.create_journal_message_for_entity(_updated_by, _user_id, _correlation_id
			, 10007  -- user_unlocked
			, 'user', _target_user_id
			, jsonb_build_object('username', _target_user_id::text)
			, 1
			, _request_context);

	perform unsecure.create_user_event(_updated_by, _user_id, _correlation_id,
		'user_unlocked', _target_user_id, _request_context := _request_context);
end;
$$;

create or replace function auth.enable_user(_updated_by text, _user_id bigint, _correlation_id text, _target_user_id bigint,
    _request_context jsonb default null, _tenant_id integer default 1)
    returns TABLE(__user_id bigint, __is_active boolean, __is_locked boolean)
    rows 1
    language plpgsql
as
$$
begin
	perform
		auth.has_permission(_user_id, _correlation_id, 'users.enable_user', 1);  -- global user state: permission in tenant 1 (D-04)

	return query
		update auth.user_info
			set updated_by = _updated_by
				, updated_at = now()
				, is_active = true
			where is_system = false
				and user_id = _target_user_id
			returning user_id
				, is_active
				, is_locked;

	perform public.create_journal_message_for_entity(_updated_by, _user_id, _correlation_id
			, 10004  -- user_enabled
			, 'user', _target_user_id
			, jsonb_build_object('username', _target_user_id::text)
			, 1
			, _request_context);

	perform unsecure.create_user_event(_updated_by, _user_id, _correlation_id,
		'user_enabled', _target_user_id, _request_context := _request_context);
end;
$$;

create or replace function auth.disable_user(_updated_by text, _user_id bigint, _correlation_id text, _target_user_id bigint,
    _request_context jsonb default null, _tenant_id integer default 1)
    returns TABLE(__user_id bigint, __is_active boolean, __is_locked boolean)
    rows 1
    language plpgsql
as
$$
begin
	perform
		auth.has_permission(_user_id, _correlation_id, 'users.disable_user', 1);  -- global user state: permission in tenant 1 (D-04)

	return query
		update auth.user_info
			set updated_by = _updated_by
				, updated_at = now()
				, is_active = false
			where is_system = false
				and user_id = _target_user_id
			returning user_id
				, is_active
				, is_locked;

	-- Clear permission cache for all tenants to ensure immediate effect
	perform unsecure.clear_permission_cache(_updated_by, _target_user_id, null);

	perform public.create_journal_message_for_entity(_updated_by, _user_id, _correlation_id
			, 10005  -- user_disabled
			, 'user', _target_user_id
			, jsonb_build_object('username', _target_user_id::text)
			, 1
			, _request_context);

	perform unsecure.create_user_event(_updated_by, _user_id, _correlation_id,
		'user_disabled', _target_user_id, _request_context := _request_context);
end;
$$;

create or replace function auth.delete_user_info(_deleted_by text, _user_id bigint, _correlation_id text, _target_user_id bigint, _tenant_id integer default 1, _blacklist boolean default false)
    returns table(__user_id bigint, __username text)
    rows 1
    language plpgsql
as
$$
declare
    __is_system bool;
begin
    perform
        auth.has_permission(_user_id, _correlation_id, 'users.delete_user_info', 1);  -- global user state: permission in tenant 1 (D-04)

    select is_system
    from auth.user_info ui
    where ui.user_id = _target_user_id
    into __is_system;

    if __is_system is null then
        perform error.raise_33001(_target_user_id);
    end if;

    if __is_system then
        perform error.raise_33002(_target_user_id);
    end if;

    return query
        select *
        from unsecure.delete_user_by_id(_deleted_by, _user_id, _correlation_id, _target_user_id, _blacklist);

    perform public.create_journal_message_for_entity(_deleted_by, _user_id, _correlation_id
        , 10003  -- user_deleted
        , 'user', _target_user_id
        , jsonb_build_object('user_id', _target_user_id::text, 'blacklisted', _blacklist::text)
        , _tenant_id);
end;
$$;

create or replace function auth.update_user_password(_updated_by text, _user_id bigint, _correlation_id text, _target_user_id bigint, _password_hash text, _request_context jsonb, _password_salt text DEFAULT NULL::text, _tenant_id integer default 1)
    returns TABLE(__user_id bigint, __provider_code text, __provider_uid text)
    rows 1
    language plpgsql
as
$$
begin

	if
		_user_id <> _target_user_id then
		perform auth.has_permission(_user_id, _correlation_id, 'users.change_password', 1);  -- global user state: permission in tenant 1 (D-04)
	end if;

	perform unsecure.create_user_event(_updated_by, _user_id, _correlation_id, 'change_password',
		_target_user_id, _request_context := _request_context);

	return query
		select *
		from unsecure.update_user_password(_updated_by, _user_id, _correlation_id, _target_user_id,
																			 _password_hash,
																			 _password_salt);
end;
$$;

create or replace function auth.enable_user_identity(_updated_by text, _user_id bigint, _correlation_id text, _target_user_id bigint, _provider_code text,
    _request_context jsonb default null, _tenant_id integer default 1)
    returns TABLE(__user_identity_id bigint, __is_active boolean)
    rows 1
    language plpgsql
as
$$
declare
	__user_identity_id bigint;
begin
	perform
		auth.has_permission(_user_id, _correlation_id, 'users.enable_user_identity', 1);  -- global user state: permission in tenant 1 (D-04)

	select user_identity_id
	from auth.user_identity uid
				 inner join auth.user_info ui on uid.user_id = ui.user_id
	where not ui.is_system
		and uid.user_id = _target_user_id
		and provider_code = _provider_code
	into __user_identity_id;

	if
		__user_identity_id is null then
		perform error.raise_52111(_target_user_id, _provider_code);
	end if;

	return query
		update auth.user_identity
			set updated_by = _updated_by
				, updated_at = now()
				, is_active = true
			where user_identity_id = __user_identity_id
			returning user_identity_id
				, is_active;

	perform public.create_journal_message_for_entity(_updated_by, _user_id, _correlation_id
			, 10033  -- identity_enabled
			, 'user', _target_user_id
			, jsonb_build_object('username', _target_user_id::text, 'provider_code', _provider_code)
			, 1
			, _request_context);

	perform unsecure.create_user_event(_updated_by, _user_id, _correlation_id,
		'identity_enabled', _target_user_id, _request_context := _request_context);
end;
$$;

create or replace function auth.disable_user_identity(_updated_by text, _user_id bigint, _correlation_id text, _target_user_id bigint, _provider_code text,
    _request_context jsonb default null, _tenant_id integer default 1)
    returns TABLE(__user_identity_id bigint, __is_active boolean)
    rows 1
    language plpgsql
as
$$
declare
	__user_identity_id bigint;
begin
	perform
		auth.has_permission(_user_id, _correlation_id, 'users.disable_user_identity', 1);  -- global user state: permission in tenant 1 (D-04)

	select user_identity_id
	from auth.user_identity uid
				 inner join auth.user_info ui on uid.user_id = ui.user_id
	where not ui.is_system
		and uid.user_id = _target_user_id
		and provider_code = _provider_code
	into __user_identity_id;

	if
		__user_identity_id is null then
		perform error.raise_52111(_target_user_id, _provider_code);
	end if;

	return query
		update auth.user_identity
			set updated_by = _updated_by
				, updated_at = now()
				, is_active = false
			where user_identity_id = __user_identity_id
			returning user_identity_id
				, is_active;

	perform public.create_journal_message_for_entity(_updated_by, _user_id, _correlation_id
			, 10034  -- identity_disabled
			, 'user', _target_user_id
			, jsonb_build_object('username', _target_user_id::text, 'provider_code', _provider_code)
			, 1
			, _request_context);

	perform unsecure.create_user_event(_updated_by, _user_id, _correlation_id,
		'identity_disabled', _target_user_id, _request_context := _request_context);
end;
$$;

create or replace function auth.verify_user_identity(_updated_by text, _user_id bigint, _correlation_id text, _target_user_id bigint, _provider_code text,
    _request_context jsonb default null, _tenant_id integer default 1)
    returns void
    language plpgsql
as
$$
begin
	perform
		auth.has_permission(_user_id, _correlation_id, 'users.verify_user_identity', 1);  -- global user state: permission in tenant 1 (D-04)

	perform
		unsecure.verify_user_identity(_updated_by, _user_id, _correlation_id, _target_user_id, _provider_code);

	perform unsecure.create_user_event(_updated_by, _user_id, _correlation_id,
		'identity_verified', _target_user_id, _request_context := _request_context,
		_event_data := jsonb_build_object('provider_code', _provider_code));
end;
$$;

create or replace function auth.create_user_identity_link(_created_by text, _user_id bigint, _correlation_id text, _target_user_id bigint, _provider_code text, _provider_uid text, _provider_oid text DEFAULT NULL::text, _password_hash text DEFAULT NULL::text, _user_data jsonb DEFAULT NULL::jsonb, _request_context jsonb DEFAULT NULL::jsonb, _tenant_id integer DEFAULT 1)
    returns TABLE(__user_identity_id bigint, __user_id bigint, __provider_code text, __uid text, __is_active boolean, __is_verified boolean)
    rows 1
    language plpgsql
as
$$
declare
	__target   auth.user_info;
	__uid      text;
	__oid      text;
	__is_email boolean;
begin
	if _target_user_id is distinct from _user_id then
		perform
			auth.has_permission(_user_id, _correlation_id, 'users.create_user_identity_link', 1);  -- global user state: permission in tenant 1 (D-04)
	end if;

	perform
		auth.validate_provider_is_active(_provider_code);

	select *
	from auth.user_info
	where user_id = _target_user_id
	into __target;

	if __target.user_id is null then
		perform error.raise_33001(_target_user_id);
	end if;

	-- technical users (service accounts, API keys) never get a login identity
	if __target.user_type_code <> 'normal' or not __target.can_login then
		perform error.raise_33005(_target_user_id);
	end if;

	if not __target.is_active then
		perform error.raise_33003(_target_user_id);
	end if;

	if __target.is_locked then
		perform error.raise_33004(_target_user_id);
	end if;

	__is_email := lower(_provider_code) = 'email';
	__uid := case when __is_email then lower(trim(_provider_uid)) else _provider_uid end;
	-- provider_oid is not null; like register_user, fall back to the uid when the provider has no oid
	__oid := coalesce(_provider_oid, __uid);

	if
		exists(
						select
						from auth.user_identity ui
						where (ui.provider_code = _provider_code and ui.uid = __uid)
							 or ui.provider_oid = __oid
			) then
		perform error.raise_33007(__uid);
	end if;

	perform unsecure.create_user_identity(_created_by, _user_id, _correlation_id, _target_user_id
		, _provider_code, __uid, __oid, _password_hash, _user_data::text
		, _is_active := true, _is_verified := not __is_email);

	perform unsecure.create_user_event(_created_by, _user_id, _correlation_id, 'identity_linked',
		_target_user_id,
		_request_context := _request_context,
		_event_data := jsonb_build_object('provider', _provider_code, 'provider_uid', __uid
			, 'self_link', _target_user_id = _user_id));

	return query
		select ui.user_identity_id
				 , ui.user_id
				 , ui.provider_code
				 , ui.uid
				 , ui.is_active
				 , ui.is_verified
		from auth.user_identity ui
		where ui.provider_code = _provider_code
			and ui.uid = __uid;
end;
$$;

create or replace function auth.update_user_data(
    _updated_by      text,
    _user_id         bigint,
    _correlation_id  text,
    _target_user_id  bigint,
    _first_name      text    default null,
    _middle_name     text    default null,
    _last_name       text    default null,
    _settings        jsonb   default null,
    _preferences     jsonb   default null,
    _custom_data     jsonb   default null,
    _tenant_id       integer default 1
) returns table(
    __created_at   timestamptz,
    __created_by   text,
    __updated_at   timestamptz,
    __updated_by   text,
    __user_data_id bigint,
    __user_id      bigint,
    __first_name   text,
    __middle_name  text,
    __last_name    text,
    __settings     jsonb,
    __preferences  jsonb,
    __custom_data  jsonb
)
    rows 1
    language plpgsql
as
$$
begin
    -- Self-update is free, updating others requires permission
    if _user_id <> _target_user_id then
        perform auth.has_permission(_user_id, _correlation_id, 'users.update_user_data', 1);  -- global user state: permission in tenant 1 (D-04)
    end if;

    -- Ensure user_data row exists (created on first update)
    insert into auth.user_data (created_by, updated_by, user_id)
    values (_updated_by, _updated_by, _target_user_id)
    on conflict (user_id) do nothing;

    return query
        update auth.user_data
        set updated_by  = _updated_by,
            updated_at  = now(),
            first_name  = coalesce(_first_name, first_name),
            middle_name = coalesce(_middle_name, middle_name),
            last_name   = coalesce(_last_name, last_name),
            settings    = case when _settings is not null
                          then jsonb_strip_nulls(coalesce(settings, '{}'::jsonb) || _settings)
                          else settings end,
            preferences = case when _preferences is not null
                          then jsonb_strip_nulls(coalesce(preferences, '{}'::jsonb) || _preferences)
                          else preferences end,
            custom_data = case when _custom_data is not null
                          then jsonb_strip_nulls(coalesce(custom_data, '{}'::jsonb) || _custom_data)
                          else custom_data end
        where user_id = _target_user_id
        returning created_at, created_by, updated_at, updated_by, user_data_id, user_id,
                  first_name, middle_name, last_name, settings, preferences, custom_data;

    perform public.create_journal_message_for_entity(_updated_by, _user_id, _correlation_id
        , 10002  -- user_updated
        , 'user', _target_user_id
        , jsonb_strip_nulls(jsonb_build_object(
            'first_name', _first_name, 'middle_name', _middle_name, 'last_name', _last_name,
            'settings_keys', case when _settings is not null then (select array_agg(k) from jsonb_object_keys(_settings) k) end,
            'preferences_keys', case when _preferences is not null then (select array_agg(k) from jsonb_object_keys(_preferences) k) end,
            'custom_data_keys', case when _custom_data is not null then (select array_agg(k) from jsonb_object_keys(_custom_data) k) end))
        , _tenant_id);
end;
$$;

create or replace function auth.update_user_preferences(_updated_by text, _user_id bigint, _correlation_id text, _target_user_id bigint, _update_data text,
    _tenant_id integer default 1)
    returns TABLE(__updated_at timestamp with time zone, __updated_by text)
    rows 1
    language plpgsql
as
$$
begin
    if _user_id <> _target_user_id
    then
        perform auth.has_permission(_user_id, _correlation_id, 'users.update_user_data', 1);  -- global user state: permission in tenant 1 (D-04)
    end if;

    return query
        update auth.user_info
            set updated_at = now()
                , updated_by = _updated_by
                , user_preferences = user_preferences || _update_data::jsonb
            where user_id = _target_user_id
            returning updated_at
                , updated_by;
end;
$$;

create or replace function auth.enroll_mfa(
    _created_by       text,
    _user_id          bigint,
    _correlation_id   text,
    _target_user_id   bigint,
    _mfa_type_code    text,
    _secret_encrypted text,
    _request_context  jsonb default null,
    _tenant_id        integer default 1
) returns table (
    __user_mfa_id    bigint,
    __mfa_type_code  text,
    __recovery_codes text[],
    __enrolled_at    timestamp with time zone
)
    language plpgsql
as
$$
declare
    __existing_confirmed boolean;
    __plain_codes        text[];
    __hashed_codes       text[];
    __code               text;
    __last_item          auth.user_mfa;
begin
    perform
        auth.has_permission(_user_id, _correlation_id, 'mfa.enroll_mfa', 1);  -- global user state: permission in tenant 1 (D-04)

    -- Validate MFA type exists and is active
    if not exists (select 1 from const.mfa_type where code = _mfa_type_code and is_active) then
        perform error.raise_38006(_mfa_type_code);
    end if;

    -- Check for existing confirmed enrollment
    select um.is_confirmed
    from auth.user_mfa um
    where um.user_id = _target_user_id
      and um.mfa_type_code = _mfa_type_code
    into __existing_confirmed;

    if __existing_confirmed is true then
        perform error.raise_38001(_target_user_id, _mfa_type_code);
    end if;

    -- Delete any unconfirmed pending enrollment
    delete from auth.user_mfa
    where user_id = _target_user_id
      and mfa_type_code = _mfa_type_code
      and is_confirmed = false;

    -- Generate 10 recovery codes
    __plain_codes := array[]::text[];
    __hashed_codes := array[]::text[];
    for __i in 1..10 loop
        __code := helpers.random_string(20);
        __plain_codes := array_append(__plain_codes, __code);
        __hashed_codes := array_append(__hashed_codes, encode(ext.digest(__code, 'sha256'), 'hex'));
    end loop;

    -- Insert new enrollment
    insert into auth.user_mfa (created_by, updated_by, user_id, mfa_type_code, secret_encrypted,
                               is_enabled, is_confirmed, recovery_codes, enrolled_at)
    values (_created_by, _created_by, _target_user_id, _mfa_type_code, _secret_encrypted,
            false, false, __hashed_codes, now())
    returning *
        into __last_item;

    -- Log enrollment event
    perform unsecure.create_user_event(
        _created_by, _user_id, _correlation_id, 'mfa_enrolled',
        _target_user_id,
        _request_context := _request_context,
        _event_data := jsonb_build_object('mfa_type', _mfa_type_code, 'user_mfa_id', __last_item.user_mfa_id)
    );

    return query
        select __last_item.user_mfa_id, __last_item.mfa_type_code, __plain_codes, __last_item.enrolled_at;
end;
$$;

create or replace function auth.confirm_mfa_enrollment(
    _updated_by      text,
    _user_id         bigint,
    _correlation_id  text,
    _target_user_id  bigint,
    _mfa_type_code   text,
    _code_is_valid   boolean,
    _request_context jsonb default null,
    _tenant_id       integer default 1
) returns void
    language plpgsql
as
$$
declare
    __user_mfa_id bigint;
begin
    perform
        auth.has_permission(_user_id, _correlation_id, 'mfa.confirm_mfa_enrollment', 1);  -- global user state: permission in tenant 1 (D-04)

    -- Verify enrollment exists and is pending
    select um.user_mfa_id
    from auth.user_mfa um
    where um.user_id = _target_user_id
      and um.mfa_type_code = _mfa_type_code
      and um.is_confirmed = false
    into __user_mfa_id;

    if __user_mfa_id is null then
        perform error.raise_38002(_target_user_id, _mfa_type_code);
    end if;

    -- Check if app says code is valid
    if not _code_is_valid then
        perform error.raise_38004();
    end if;

    -- Confirm the enrollment
    update auth.user_mfa
    set is_enabled    = true,
        is_confirmed  = true,
        confirmed_at  = now(),
        updated_at    = now(),
        updated_by    = _updated_by
    where user_mfa_id = __user_mfa_id;

    -- Log confirmation event
    perform unsecure.create_user_event(
        _updated_by, _user_id, _correlation_id, 'mfa_enrollment_confirmed',
        _target_user_id,
        _request_context := _request_context,
        _event_data := jsonb_build_object('mfa_type', _mfa_type_code, 'user_mfa_id', __user_mfa_id)
    );
end;
$$;

create or replace function auth.disable_mfa(
    _updated_by      text,
    _user_id         bigint,
    _correlation_id  text,
    _target_user_id  bigint,
    _mfa_type_code   text,
    _request_context jsonb default null,
    _tenant_id       integer default 1
) returns void
    language plpgsql
as
$$
declare
    __user_mfa_id bigint;
begin
    perform
        auth.has_permission(_user_id, _correlation_id, 'mfa.disable_mfa', 1);  -- global user state: permission in tenant 1 (D-04)

    -- Verify enrollment exists
    select um.user_mfa_id
    from auth.user_mfa um
    where um.user_id = _target_user_id
      and um.mfa_type_code = _mfa_type_code
    into __user_mfa_id;

    if __user_mfa_id is null then
        perform error.raise_38002(_target_user_id, _mfa_type_code);
    end if;

    -- Delete the enrollment
    delete from auth.user_mfa
    where user_mfa_id = __user_mfa_id;

    -- Log disable event (existing event code 10051: mfa_disabled)
    perform unsecure.create_user_event(
        _updated_by, _user_id, _correlation_id, 'mfa_disabled',
        _target_user_id,
        _request_context := _request_context,
        _event_data := jsonb_build_object('mfa_type', _mfa_type_code, 'user_mfa_id', __user_mfa_id)
    );
end;
$$;

create or replace function auth.reset_mfa(
    _updated_by      text,
    _user_id         bigint,
    _correlation_id  text,
    _target_user_id  bigint,
    _mfa_type_code   text,
    _request_context jsonb default null,
    _tenant_id       integer default 1
) returns table (
    __user_mfa_id    bigint,
    __recovery_codes text[]
)
    language plpgsql
as
$$
declare
    __mfa_record     auth.user_mfa;
    __plain_codes    text[];
    __hashed_codes   text[];
    __code           text;
begin
    perform
        auth.has_permission(_user_id, _correlation_id, 'mfa.reset_mfa', 1);  -- global user state: permission in tenant 1 (D-04)

    -- Verify enrollment exists
    select um.*
    from auth.user_mfa um
    where um.user_id = _target_user_id
      and um.mfa_type_code = _mfa_type_code
    into __mfa_record;

    if __mfa_record.user_mfa_id is null then
        perform error.raise_38002(_target_user_id, _mfa_type_code);
    end if;

    -- Must be confirmed
    if not __mfa_record.is_confirmed then
        perform error.raise_38003(_target_user_id, _mfa_type_code);
    end if;

    -- Generate 10 new recovery codes
    __plain_codes  := array[]::text[];
    __hashed_codes := array[]::text[];
    for __i in 1..10 loop
        __code := helpers.random_string(20);
        __plain_codes  := array_append(__plain_codes, __code);
        __hashed_codes := array_append(__hashed_codes, encode(ext.digest(__code, 'sha256'), 'hex'));
    end loop;

    -- Replace recovery codes
    update auth.user_mfa
    set recovery_codes = __hashed_codes,
        updated_at     = now(),
        updated_by     = _updated_by
    where user_mfa_id = __mfa_record.user_mfa_id;

    -- Log event
    perform unsecure.create_user_event(
        _updated_by, _user_id, _correlation_id, 'mfa_recovery_reset',
        _target_user_id,
        _request_context := _request_context,
        _event_data := jsonb_build_object('mfa_type', _mfa_type_code, 'user_mfa_id', __mfa_record.user_mfa_id)
    );

    return query
        select __mfa_record.user_mfa_id, __plain_codes;
end;
$$;

create or replace function auth.create_blacklist_user(
    _created_by text,
    _user_id bigint,
    _correlation_id text,
    _username text default null,
    _provider_code text default null,
    _provider_uid text default null,
    _provider_oid text default null,
    _reason text default 'manual',
    _notes text default null,
    _tenant_id integer default 1
) returns table(__blacklist_id bigint)
    rows 1
    language plpgsql
as
$$
declare
    __last_id bigint;
    __system_user_id bigint;
begin
    perform auth.has_permission(_user_id, _correlation_id, 'users.manage_blacklist', 1);  -- global user state: permission in tenant 1 (D-04)

    -- prevent blacklisting system users by username
    if _username is not null then
        select ui.user_id from auth.user_info ui
        where ui.username = lower(trim(_username)) and ui.is_system
        into __system_user_id;

        if __system_user_id is not null then
            perform error.raise_33002(__system_user_id);
        end if;
    end if;

    -- prevent blacklisting system users by provider identity
    if _provider_uid is not null or _provider_oid is not null then
        select ui.user_id from auth.user_identity uid
            inner join auth.user_info ui on ui.user_id = uid.user_id
        where ui.is_system
          and (_provider_code is null or uid.provider_code = _provider_code)
          and (_provider_uid is null or uid.uid = _provider_uid)
          and (_provider_oid is null or uid.provider_oid = _provider_oid)
        into __system_user_id;

        if __system_user_id is not null then
            perform error.raise_33002(__system_user_id);
        end if;
    end if;

    insert into auth.user_blacklist (created_by, username, provider_code, provider_uid, provider_oid,
                                     reason, notes)
    values (_created_by, lower(trim(_username)), _provider_code, _provider_uid, _provider_oid,
            _reason, _notes)
    returning blacklist_id into __last_id;

    perform public.create_journal_message_for_entity(_created_by, _user_id, _correlation_id
        , 10080  -- user_blacklisted
        , 'user', 0
        , jsonb_build_object('username', _username, 'provider_code', _provider_code,
                             'provider_uid', _provider_uid, 'provider_oid', _provider_oid,
                             'reason', _reason, 'notes', _notes)
        , _tenant_id);

    return query select __last_id;
end;
$$;

create or replace function auth.delete_blacklist_user(
    _deleted_by text,
    _user_id bigint,
    _correlation_id text,
    _blacklist_id bigint,
    _tenant_id integer default 1
) returns table(__removed_blacklist_id bigint, __username text, __provider_code text)
    rows 1
    language plpgsql
as
$$
declare
    __item auth.user_blacklist;
begin
    perform auth.has_permission(_user_id, _correlation_id, 'users.manage_blacklist', 1);  -- global user state: permission in tenant 1 (D-04)

    delete from auth.user_blacklist
    where blacklist_id = _blacklist_id
    returning * into __item;

    if __item.blacklist_id is null then
        raise exception 'Blacklist entry (id: %) does not exist', _blacklist_id
            using errcode = '33018';
    end if;

    perform public.create_journal_message_for_entity(_deleted_by, _user_id, _correlation_id
        , 10081  -- user_unblacklisted
        , 'user', coalesce(__item.original_user_id, 0)
        , jsonb_build_object('username', __item.username, 'provider_code', __item.provider_code,
                             'provider_uid', __item.provider_uid, 'provider_oid', __item.provider_oid,
                             'blacklist_id', _blacklist_id)
        , _tenant_id);

    return query
        select __item.blacklist_id, __item.username, __item.provider_code;
end;
$$;

create or replace function unsecure.verify_user_identity(_updated_by text, _user_id bigint, _correlation_id text, _target_user_id bigint, _provider_code text)
    returns void
    language plpgsql
as
$$
declare
	__username text;
begin
	select username from auth.user_info where user_id = _target_user_id into __username;

	if __username is null then
		perform error.raise_33001(_target_user_id);
	end if;

	if not exists(select from auth.user_identity where user_id = _target_user_id and provider_code = _provider_code) then
		perform error.raise_33009(_target_user_id, _provider_code);
	end if;

	update auth.user_identity
	set is_verified = true, updated_by = _updated_by, updated_at = now()
	where user_id = _target_user_id
		and provider_code = _provider_code
		and not is_verified;

	perform public.create_journal_message_for_entity('system', _user_id, _correlation_id
		, 10035  -- identity_verified
		, 'user', _target_user_id
		, jsonb_build_object('username', __username, 'provider_code', _provider_code)
		, 1);
end;
$$;


select *
from public.stop_version_update('2.9', _component := 'postgresql_permissionmodel');
