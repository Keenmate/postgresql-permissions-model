/*
 * PostgreSQL Permissions Model — update v2.6
 * ==========================================
 *
 * Authentication outcomes instead of exceptions (audit design D-01,
 * audit/design-d01-auth-outcomes.md).
 *
 * Login, MFA and API-key functions wrote the failure event, the auto-lock and
 * the token's `failed` state and then raised, so all of it was rolled back:
 * auto-lockout never triggered, MFA brute-force protection did nothing and
 * failed logins were missing from the audit trail. Expected outcomes are now
 * returned as (__event_id, __outcome_code, __user_event_id) and commit with the
 * caller's transaction; exceptions remain for faults only.
 *
 *  - auth.get_user_by_email_for_authentication: read only. Returns the user's
 *    login state; the password hash only when the user may log in now. It no
 *    longer logs user_logged_in before the password is checked.
 *  - auth.create_user_login_attempt (new, replaces auth.record_login_failure):
 *    every email login decision, counters and lockout.
 *  - auth.ensure_user_from_provider: returns the outcome instead of raising for
 *    disabled / locked / login-disabled users (now also checks is_locked and the
 *    temporary lock) and for a username taken by another user (33024).
 *  - auth.create_mfa_challenge_attempt (new, replaces auth.verify_mfa_challenge).
 *  - auth.create_api_key_validation_attempt (new, replaces auth.validate_api_key):
 *    expired keys (30006) and disabled / locked technical users are rejected;
 *    permissions are no longer returned, ask auth.has_permission.
 *  - Lockout is temporary and escalating: auth.user_login_state holds the
 *    counters, sys_param login_lockout.lockout_durations_minutes the steps and
 *    login_lockout.lockout_reset_hours the decay. The admin lock (is_locked)
 *    is unchanged.
 *  - const.sys_param.is_system: system parameters can be updated but not deleted.
 *
 * Removed: auth.record_login_failure, auth.verify_user_by_email (hash comparison
 * in the database cannot work with salted hashes), auth.verify_mfa_challenge,
 * auth.validate_api_key, unsecure.check_and_auto_lock_user.
 *
 * New error codes: 30006, 31015, 31016.
 * New permission: authentication.create_user_login_attempt. The Svc authenticator
 * perm set gets it plus mfa.create_mfa_challenge / mfa.verify_mfa_challenge and
 * tokens.create_token (create_mfa_challenge creates a token) - the MFA step runs
 * before the user is logged in, so the authenticator calls it.
 */

set search_path = public, const, ext, stage, helpers, internal, unsecure, auth, triggers;

select *
from public.start_version_update('2.6', 'Authentication outcomes instead of exceptions',
                                 _component := 'postgresql_permissionmodel',
                                 _description := 'Login, MFA and API-key functions return outcomes so failure events, counters and locks persist; temporary escalating lockout in auth.user_login_state; system sys_params cannot be deleted.');


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
values (30006, 'err_api_key_expired', 'security_error', true, 'core')
     , (31015, 'err_sys_param_is_system', 'validation_error', true, 'core')
     , (31016, 'err_sys_param_invalid_value', 'validation_error', true, 'core')
on conflict do nothing;

insert into const.event_message (event_id, language_code, message_template)
values (30006, 'en', 'API key (key: {api_key}) has expired')
     , (31015, 'en', 'System parameter (group: {group_code}, code: {code}) is a system parameter and cannot be deleted')
     , (31016, 'en', 'System parameter (group: {group_code}, code: {code}) has an invalid value ({value})')
on conflict do nothing;

-- 30006: API key expired
create or replace function error.raise_30006(_api_key text) returns void
    language plpgsql
as
$$
begin
    raise exception 'API key (key: %) has expired', _api_key
        using errcode = '30006';
end;
$$;

-- 31015: System parameter cannot be deleted
create or replace function error.raise_31015(_group_code text, _code text) returns void
    language plpgsql
as
$$
begin
    raise exception 'System parameter (group: %, code: %) is a system parameter and cannot be deleted', _group_code, _code
        using errcode = '31015';
end;
$$;

-- 31016: System parameter has an invalid value
create or replace function error.raise_31016(_group_code text, _code text, _value text) returns void
    language plpgsql
as
$$
begin
    raise exception 'System parameter (group: %, code: %) has an invalid value (%)', _group_code, _code, _value
        using errcode = '31016';
end;
$$;


/***
 *    ███████╗██╗   ██╗███████╗    ██████╗  █████╗ ██████╗  █████╗ ███╗   ███╗
 *    ██╔════╝╚██╗ ██╔╝██╔════╝    ██╔══██╗██╔══██╗██╔══██╗██╔══██╗████╗ ████║
 *    ███████╗ ╚████╔╝ ███████╗    ██████╔╝███████║██████╔╝███████║██╔████╔██║
 *    ╚════██║  ╚██╔╝  ╚════██║    ██╔═══╝ ██╔══██║██╔══██╗██╔══██║██║╚██╔╝██║
 *    ███████║   ██║   ███████║    ██║     ██║  ██║██║  ██║██║  ██║██║ ╚═╝ ██║
 *    ╚══════╝   ╚═╝   ╚══════╝    ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝
 *
 */

alter table const.sys_param
    add column if not exists is_system boolean default false not null;

insert into const.sys_param (group_code, code, text_value, number_value, created_by, updated_by)
values ('login_lockout', 'lockout_durations_minutes', '15,60,240,960,1440', null, 'update_v2.6', 'update_v2.6')
     , ('login_lockout', 'lockout_reset_hours', '24', 24, 'update_v2.6', 'update_v2.6')
on conflict (group_code, code) do nothing;

-- every parameter the core reads is a system parameter
update const.sys_param
set is_system = true
where group_code in ('journal', 'user_event', 'partition', 'login_lockout');

-- System parameters can be updated but never deleted, and the login_lockout
-- values must stay usable - a typo there would break every login.
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

    return new;
end;
$$;

drop trigger if exists trg_const_sys_param_validate on const.sys_param;
create trigger trg_const_sys_param_validate
    before insert or update or delete
    on const.sys_param
    for each row
execute function triggers.validate_sys_param();


/***
 *    ████████╗ █████╗ ██████╗ ██╗     ███████╗███████╗
 *    ╚══██╔══╝██╔══██╗██╔══██╗██║     ██╔════╝██╔════╝
 *       ██║   ███████║██████╔╝██║     █████╗  ███████╗
 *       ██║   ██╔══██║██╔══██╗██║     ██╔══╝  ╚════██║
 *       ██║   ██║  ██║██████╔╝███████╗███████╗███████║
 *       ╚═╝   ╚═╝  ╚═╝╚═════╝ ╚══════╝╚══════╝╚══════╝
 *
 */

-- Login failure counters, kept out of auth.user_info: every user_info update
-- recomputes the search text and fires two after-triggers.
create table if not exists auth.user_login_state
(
    created_at           timestamp with time zone default now()           not null,
    created_by           text                     default 'unknown'::text not null,
    updated_at           timestamp with time zone default now()           not null,
    updated_by           text                     default 'unknown'::text not null,
    user_id              bigint                                            not null primary key
        references auth.user_info on delete cascade,
    failed_login_count   integer                  default 0                not null,
    last_failed_login_at timestamp with time zone,
    lockout_count        integer                  default 0                not null,
    locked_until         timestamp with time zone,
    constraint user_login_state_created_by_check check (length(created_by) <= 250),
    constraint user_login_state_updated_by_check check (length(updated_by) <= 250)
);

comment on column auth.user_login_state.failed_login_count is 'Failed logins / MFA codes inside the current login_lockout.window_minutes';
comment on column auth.user_login_state.lockout_count is 'Consecutive automatic lockouts; picks the step in login_lockout.lockout_durations_minutes, reset by a successful login or after login_lockout.lockout_reset_hours without a failure';
comment on column auth.user_login_state.locked_until is 'Temporary automatic lock; independent of the permanent admin lock auth.user_info.is_locked';


/***
 *    ██████╗ ███████╗██████╗ ███╗   ███╗██╗███████╗███████╗██╗ ██████╗ ███╗   ██╗███████╗
 *    ██╔══██╗██╔════╝██╔══██╗████╗ ████║██║██╔════╝██╔════╝██║██╔═══██╗████╗  ██║██╔════╝
 *    ██████╔╝█████╗  ██████╔╝██╔████╔██║██║███████╗███████╗██║██║   ██║██╔██╗ ██║███████╗
 *    ██╔═══╝ ██╔══╝  ██╔══██╗██║╚██╔╝██║██║╚════██║╚════██║██║██║   ██║██║╚██╗██║╚════██║
 *    ██║     ███████╗██║  ██║██║ ╚═╝ ██║██║███████║███████║██║╚██████╔╝██║ ╚████║███████║
 *    ╚═╝     ╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝╚═╝╚══════╝╚══════╝╚═╝ ╚═════╝ ╚═╝  ╚═══╝╚══════╝
 *
 */

select unsecure.create_permission_as_system('Create user login attempt', 'authentication', _source := 'core')
where not exists(select from auth.permission where full_code = 'authentication.create_user_login_attempt');

select unsecure.create_perm_set_permissions('update_v2.6', 1, null, ps.perm_set_id
    , array ['authentication.create_user_login_attempt', 'mfa.create_mfa_challenge', 'mfa.verify_mfa_challenge', 'tokens.create_token'], 1)
from auth.perm_set ps
where ps.code = 'svc_authenticator_permissions'
  and ps.tenant_id = 1;

-- caches built before this script lack the new permission for holders of the `authentication` node
update auth.user_permission_cache
set expiration_date = now()
  , updated_by      = 'update_v2.6'
  , updated_at      = now()
where expiration_date > now();


/***
 *    ██████╗ ██████╗  ██████╗ ██████╗ ███████╗
 *    ██╔══██╗██╔══██╗██╔═══██╗██╔══██╗██╔════╝
 *    ██║  ██║██████╔╝██║   ██║██████╔╝███████╗
 *    ██║  ██║██╔══██╗██║   ██║██╔═══╝ ╚════██║
 *    ██████╔╝██║  ██║╚██████╔╝██║     ███████║
 *    ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚═╝     ╚══════╝
 *
 */

drop function if exists auth.record_login_failure(bigint, text, bigint, text, jsonb, integer);
drop function if exists auth.verify_user_by_email(bigint, text, text, text, jsonb, integer);
drop function if exists auth.verify_mfa_challenge(text, bigint, text, bigint, text, boolean, text, jsonb, integer);
drop function if exists auth.validate_api_key(text, bigint, text, text, text, jsonb, integer);
drop function if exists unsecure.check_and_auto_lock_user(text, text, bigint, jsonb);

-- return types change
drop function if exists auth.get_user_by_email_for_authentication(bigint, text, text, jsonb, integer);
drop function if exists auth.ensure_user_from_provider(text, bigint, text, text, text, text, text, text, text, jsonb, jsonb);


/***
 *    ███████╗██╗   ██╗███╗   ██╗ ██████╗████████╗██╗ ██████╗ ███╗   ██╗███████╗
 *    ██╔════╝██║   ██║████╗  ██║██╔════╝╚══██╔══╝██║██╔═══██╗████╗  ██║██╔════╝
 *    █████╗  ██║   ██║██╔██╗ ██║██║        ██║   ██║██║   ██║██╔██╗ ██║███████╗
 *    ██╔══╝  ██║   ██║██║╚██╗██║██║        ██║   ██║██║   ██║██║╚██╗██║╚════██║
 *    ██║     ╚██████╔╝██║ ╚████║╚██████╗   ██║   ██║╚██████╔╝██║ ╚████║███████║
 *    ╚═╝      ╚═════╝ ╚═╝  ╚═══╝ ╚═════╝   ╚═╝   ╚═╝ ╚═════╝ ╚═╝  ╚═══╝╚══════╝
 *
 */

-- ---------------------------------------------------------------------------
-- unsecure.get_login_lockout_settings - the login_lockout sys_params, with the
-- built-in defaults when a row is missing.
-- ---------------------------------------------------------------------------
create or replace function unsecure.get_login_lockout_settings()
    returns table(__max_failed_attempts integer, __window_minutes integer, __lockout_reset_hours integer, __lockout_durations_minutes integer[])
    rows 1
    stable
    language sql
as
$$
select coalesce((select coalesce(sp.number_value, sp.text_value::bigint)::integer
                 from const.sys_param sp
                 where sp.group_code = 'login_lockout' and sp.code = 'max_failed_attempts'), 5)
     , coalesce((select coalesce(sp.number_value, sp.text_value::bigint)::integer
                 from const.sys_param sp
                 where sp.group_code = 'login_lockout' and sp.code = 'window_minutes'), 15)
     , coalesce((select coalesce(sp.number_value, sp.text_value::bigint)::integer
                 from const.sys_param sp
                 where sp.group_code = 'login_lockout' and sp.code = 'lockout_reset_hours'), 24)
     , coalesce((select string_to_array(regexp_replace(sp.text_value, '\s', '', 'g'), ',')::integer[]
                  from const.sys_param sp
                  where sp.group_code = 'login_lockout' and sp.code = 'lockout_durations_minutes'),
                array [15, 60, 240, 960, 1440]);
$$;

-- ---------------------------------------------------------------------------
-- unsecure.check_user_can_login - read-only verdict on whether a user may log
-- in right now. Always returns one row; __event_id is null when the user may
-- log in. With _provider_code null the identity is not checked (MFA step).
-- ---------------------------------------------------------------------------
create or replace function unsecure.check_user_can_login(_target_user_id bigint, _provider_code text DEFAULT NULL::text, _provider_uid text DEFAULT NULL::text)
    returns table(__event_id integer, __outcome_code text, __reason text, __locked_until timestamp with time zone)
    rows 1
    stable
    language plpgsql
as
$$
declare
	__can_login          boolean;
	__is_active          boolean;
	__is_locked          boolean;
	__is_identity_active boolean;
	___locked_until      timestamp with time zone;
begin
	select ui.can_login, ui.is_active, ui.is_locked, uid.is_active, ls.locked_until
	from auth.user_info ui
				 left join auth.user_identity uid
									 on uid.user_id = ui.user_id
										 and uid.provider_code = _provider_code
										 and uid.uid = _provider_uid
				 left join auth.user_login_state ls on ls.user_id = ui.user_id
	where ui.user_id = _target_user_id
	into __can_login, __is_active, __is_locked, __is_identity_active, ___locked_until;

	if __is_active is null or (_provider_code is not null and __is_identity_active is null) then
		return query select 33001, 'err_user_not_found', 'user_not_found', null::timestamptz;
	elsif not __can_login then
		return query select 33005, 'err_user_cannot_login', 'login_disabled', null::timestamptz;
	elsif not __is_active then
		return query select 33003, 'err_user_not_active', 'user_disabled', null::timestamptz;
	elsif _provider_code is not null and not __is_identity_active then
		return query select 33008, 'err_identity_not_active', 'identity_disabled', null::timestamptz;
	elsif __is_locked then
		return query select 33004, 'err_user_locked', 'user_locked', null::timestamptz;
	elsif ___locked_until > now() then
		return query select 33004, 'err_user_locked', 'user_temporarily_locked', ___locked_until;
	else
		return query select null::integer, null::text, null::text, null::timestamptz;
	end if;
end;
$$;

-- ---------------------------------------------------------------------------
-- unsecure.update_user_login_state - count one failure (with window reset,
-- escalation decay and lockout) or clear the counters after a success.
-- Row-locked, so concurrent failures of one user are counted one by one.
-- ---------------------------------------------------------------------------
create or replace function unsecure.update_user_login_state(_updated_by text, _target_user_id bigint, _is_success boolean)
    returns table(__failed_login_count integer, __max_failed_attempts integer, __locked_until timestamp with time zone, __is_lockout_triggered boolean)
    rows 1
    language plpgsql
as
$$
declare
	__settings    record;
	__state       auth.user_login_state;
	__attempts    integer;
	__is_triggered boolean := false;
begin
	select * from unsecure.get_login_lockout_settings() into __settings;

	if _is_success then
		update auth.user_login_state
		set failed_login_count = 0
			, lockout_count      = 0
			, locked_until       = null
			, updated_by         = _updated_by
			, updated_at         = now()
		where user_id = _target_user_id
			and (failed_login_count <> 0 or lockout_count <> 0 or locked_until is not null);

		return query select 0, __settings.__max_failed_attempts, null::timestamptz, false;
		return;
	end if;

	insert into auth.user_login_state (created_by, updated_by, user_id)
	values (_updated_by, _updated_by, _target_user_id)
	on conflict (user_id) do nothing;

	select *
	from auth.user_login_state
	where user_id = _target_user_id
	for update
	into __state;

	-- escalation decays after a quiet period, the counter after the window
	if __state.last_failed_login_at is null
		or __state.last_failed_login_at < now() - make_interval(hours => __settings.__lockout_reset_hours) then
		__state.lockout_count := 0;
	end if;

	if __state.last_failed_login_at is null
		or __state.last_failed_login_at < now() - make_interval(mins => __settings.__window_minutes) then
		__state.failed_login_count := 0;
	end if;

	__attempts := __state.failed_login_count + 1;
	__state.failed_login_count := __attempts;
	__state.last_failed_login_at := now();

	if __attempts >= __settings.__max_failed_attempts then
		__state.lockout_count := __state.lockout_count + 1;
		__state.locked_until := now() + make_interval(mins => __settings.__lockout_durations_minutes[
			least(__state.lockout_count, array_length(__settings.__lockout_durations_minutes, 1))]);
		__state.failed_login_count := 0;
		__is_triggered := true;
	end if;

	update auth.user_login_state
	set failed_login_count   = __state.failed_login_count
		, last_failed_login_at = __state.last_failed_login_at
		, lockout_count        = __state.lockout_count
		, locked_until         = __state.locked_until
		, updated_by           = _updated_by
		, updated_at           = now()
	where user_id = _target_user_id;

	return query select __attempts, __settings.__max_failed_attempts, __state.locked_until, __is_triggered;
end;
$$;

-- ---------------------------------------------------------------------------
-- auth.get_user_by_email_for_authentication - read only. Step 1 of an email
-- login: returns the user and their login state, and the password hash only
-- when the user may log in now. No row for an unknown email. Always follow up
-- with auth.create_user_login_attempt, also when no row came back.
-- ---------------------------------------------------------------------------
create function auth.get_user_by_email_for_authentication(_user_id bigint, _correlation_id text, _email text, _request_context jsonb DEFAULT NULL::jsonb, _tenant_id integer default 1)
    returns TABLE(__user_id bigint, __code text, __uuid text, __username text, __email text, __display_name text, __provider text
		, __can_login boolean, __is_active boolean, __is_locked boolean, __locked_until timestamp with time zone, __is_identity_active boolean
		, __password_hash text, __password_salt text)
    rows 1
    language plpgsql
as
$$
begin
	perform
		auth.has_permission(_user_id, _correlation_id, 'authentication.get_data', _tenant_id);

	perform
		auth.validate_provider_is_active('email');

	return query
		select ui.user_id
				 , ui.code
				 , ui.uuid::text
				 , ui.username
				 , ui.email
				 , ui.display_name
				 , 'email'
				 , ui.can_login
				 , ui.is_active
				 , ui.is_locked
				 , ls.locked_until
				 , uid.is_active
				 , case when m.__may_log_in then uid.password_hash end
				 , case when m.__may_log_in then uid.password_salt end
		from auth.user_identity uid
					 inner join auth.user_info ui on uid.user_id = ui.user_id
					 left join auth.user_login_state ls on ls.user_id = ui.user_id
					 cross join lateral (select ui.can_login and ui.is_active and not ui.is_locked and uid.is_active
																				and (ls.locked_until is null or ls.locked_until <= now()) as __may_log_in) m
		where uid.provider_code = 'email'
			and uid.uid = lower(trim(_email));
end;
$$;

-- ---------------------------------------------------------------------------
-- auth.create_user_login_attempt - step 2 of an email login, called for every
-- attempt (also for an unknown email, with _target_user_id null). Decides the
-- outcome, writes the user_event, counts failures and locks temporarily.
--
-- Outcomes (__event_id / __outcome_code):
--   10010 user_logged_in, 33001 err_user_not_found (also for a wrong password),
--   33003 err_user_not_active, 33004 err_user_locked, 33005 err_user_cannot_login,
--   33008 err_identity_not_active
-- Show the user one generic message for every failure; only 33004 may differ.
-- Do not roll back the surrounding transaction on a failure outcome - that would
-- undo the counters and the audit row.
-- ---------------------------------------------------------------------------
create or replace function auth.create_user_login_attempt(_created_by text, _user_id bigint, _correlation_id text, _provider_code text, _provider_uid text, _target_user_id bigint, _is_credential_valid boolean, _request_context jsonb DEFAULT NULL::jsonb, _tenant_id integer default 1)
    returns TABLE(__event_id integer, __outcome_code text, __user_event_id bigint, __failed_login_count integer, __max_failed_attempts integer, __locked_until timestamp with time zone)
    rows 1
    language plpgsql
as
$$
declare
	__uid            text;
	__check          record;
	__state          record;
	___user_event_id bigint;
begin
	perform
		auth.has_permission(_user_id, _correlation_id, 'authentication.create_user_login_attempt', _tenant_id);

	__uid := case when lower(_provider_code) = 'email' then lower(trim(_provider_uid)) else _provider_uid end;

	if _target_user_id is null then
		select e.__user_event_id
		from unsecure.create_user_event(_created_by, _user_id, _correlation_id, 'user_login_failed', null
			, _request_context := _request_context
			, _event_data := jsonb_build_object('provider', _provider_code, 'provider_uid', __uid, 'reason', 'user_not_found')) e
		into ___user_event_id;

		return query select 33001, 'err_user_not_found', ___user_event_id, null::integer, null::integer, null::timestamptz;
		return;
	end if;

	select * from unsecure.check_user_can_login(_target_user_id, _provider_code, __uid) into __check;

	if __check.__event_id is not null then
		-- attempts while locked are logged but not counted, so a lock cannot escalate while it runs
		select e.__user_event_id
		from unsecure.create_user_event(_created_by, _user_id, _correlation_id, 'user_login_failed', _target_user_id
			, _request_context := _request_context
			, _event_data := jsonb_build_object('provider', _provider_code, 'provider_uid', __uid, 'reason', __check.__reason)) e
		into ___user_event_id;

		return query select __check.__event_id, __check.__outcome_code, ___user_event_id, null::integer, null::integer, __check.__locked_until;
		return;
	end if;

	if _is_credential_valid is distinct from true then
		select e.__user_event_id
		from unsecure.create_user_event(_created_by, _user_id, _correlation_id, 'user_login_failed', _target_user_id
			, _request_context := _request_context
			, _event_data := jsonb_build_object('provider', _provider_code, 'provider_uid', __uid
				, 'reason', case when _is_credential_valid is null then 'credential_missing' else 'wrong_password' end)) e
		into ___user_event_id;

		select * from unsecure.update_user_login_state(_created_by, _target_user_id, false) into __state;

		if __state.__is_lockout_triggered then
			perform unsecure.create_user_event(_created_by, _user_id, _correlation_id, 'user_auto_locked', _target_user_id
				, _request_context := _request_context
				, _event_data := jsonb_build_object('failed_login_count', __state.__failed_login_count
					, 'locked_until', __state.__locked_until));

			return query select 33004, 'err_user_locked', ___user_event_id, __state.__failed_login_count
				, __state.__max_failed_attempts, __state.__locked_until;
			return;
		end if;

		return query select 33001, 'err_user_not_found', ___user_event_id, __state.__failed_login_count
			, __state.__max_failed_attempts, null::timestamptz;
		return;
	end if;

	select * from unsecure.update_user_login_state(_created_by, _target_user_id, true) into __state;

	perform
		unsecure.update_last_used_provider(_target_user_id, _provider_code);

	select e.__user_event_id
	from unsecure.create_user_event(_created_by, _user_id, _correlation_id, 'user_logged_in', _target_user_id
		, _request_context := _request_context
		, _event_data := jsonb_build_object('provider', _provider_code, 'provider_uid', __uid)) e
	into ___user_event_id;

	return query select 10010, 'user_logged_in', ___user_event_id, 0, __state.__max_failed_attempts, null::timestamptz;
end;
$$;

-- ---------------------------------------------------------------------------
-- auth.ensure_user_from_provider - login (and first-login provisioning) through
-- an external provider. Returns the outcome instead of raising: on a failure
-- the user columns are null. The provider checked the credential, so provider
-- logins never count toward the lockout, but a locked user cannot log in.
--
-- Outcomes: 10010 user_logged_in, 33003, 33004, 33005, 33008 (see
-- create_user_login_attempt), 33024 err_username_already_exists (first login
-- with a username another user has - link with auth.create_user_identity_link).
-- Still raises for faults: email provider (52101), inactive provider,
-- blacklisted identity (33019) or username (33018).
-- ---------------------------------------------------------------------------
create function auth.ensure_user_from_provider(_created_by text, _user_id bigint, _correlation_id text, _provider_code text, _provider_uid text, _provider_oid text, _username text, _display_name text, _email text DEFAULT NULL::text, _user_data jsonb DEFAULT NULL::jsonb, _request_context jsonb DEFAULT NULL::jsonb)
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

		-- never attach a new identity to an existing user by username (v2.4)
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

-- ---------------------------------------------------------------------------
-- auth.create_mfa_challenge_attempt - the user answered an MFA challenge. The
-- app verifies the TOTP code (the secret never reaches the database) and
-- passes _is_code_valid; a recovery code is checked here. Wrong codes count
-- toward the same lockout as wrong passwords, and the token stays failed.
--
-- Outcomes: 10093 mfa_challenge_passed, 10094 mfa_recovery_used,
-- 38004 err_mfa_invalid_code, 33004 err_user_locked (also 33003/33005),
-- 30002 err_token_invalid, 30003 err_token_wrong_user,
-- 30004 err_token_already_used, 30005 err_token_not_found
-- ---------------------------------------------------------------------------
create or replace function auth.create_mfa_challenge_attempt(_created_by text, _user_id bigint, _correlation_id text, _target_user_id bigint, _token_uid text, _is_code_valid boolean, _recovery_code text DEFAULT NULL::text, _request_context jsonb DEFAULT NULL::jsonb, _tenant_id integer DEFAULT 1)
    returns TABLE(__event_id integer, __outcome_code text, __user_event_id bigint, __recovery_codes_remaining integer, __failed_login_count integer, __locked_until timestamp with time zone)
    rows 1
    language plpgsql
as
$$
declare
	__token          auth.token;
	__user_mfa_id    bigint;
	__recovery_hash  text;
	__recovery_codes text[];
	__check          record;
	__state          record;
	__failure_event_id     integer;
	__failure_outcome_code text;
	__failure_reason       text;
	___user_event_id bigint;
begin
	perform
		auth.has_permission(_user_id, _correlation_id, 'mfa.verify_mfa_challenge', _tenant_id);

	select t.*
	from auth.token t
	where t.uid = _token_uid
		and t.token_type_code = 'mfa'
	into __token;

	-- token problems: logged, not counted toward the lockout
	if __token.token_id is null then
		__failure_event_id := 30005; __failure_outcome_code := 'err_token_not_found'; __failure_reason := 'token_not_found';
	elsif __token.token_state_code = 'used' then
		__failure_event_id := 30004; __failure_outcome_code := 'err_token_already_used'; __failure_reason := 'token_already_used';
	elsif __token.token_state_code <> 'valid' then
		__failure_event_id := 30002; __failure_outcome_code := 'err_token_invalid'; __failure_reason := 'token_' || __token.token_state_code;
	elsif __token.expires_at < now() then
		update auth.token
		set token_state_code = 'expired'
			, updated_at       = now()
			, updated_by       = _created_by
		where token_id = __token.token_id;

		__failure_event_id := 30002; __failure_outcome_code := 'err_token_invalid'; __failure_reason := 'token_expired';
	elsif __token.user_id <> _target_user_id then
		__failure_event_id := 30003; __failure_outcome_code := 'err_token_wrong_user'; __failure_reason := 'token_wrong_user';
	end if;

	if __failure_event_id is not null then
		select e.__user_event_id
		from unsecure.create_user_event(_created_by, _user_id, _correlation_id, 'mfa_challenge_failed', _target_user_id
			, _request_context := _request_context
			, _event_data := jsonb_build_object('token_uid', _token_uid, 'reason', __failure_reason)) e
		into ___user_event_id;

		return query select __failure_event_id, __failure_outcome_code, ___user_event_id, null::integer, null::integer, null::timestamptz;
		return;
	end if;

	select * from unsecure.check_user_can_login(_target_user_id) into __check;

	if __check.__event_id is not null then
		select e.__user_event_id
		from unsecure.create_user_event(_created_by, _user_id, _correlation_id, 'mfa_challenge_failed', _target_user_id
			, _request_context := _request_context
			, _event_data := jsonb_build_object('token_uid', _token_uid, 'reason', __check.__reason)) e
		into ___user_event_id;

		return query select __check.__event_id, __check.__outcome_code, ___user_event_id, null::integer, null::integer, __check.__locked_until;
		return;
	end if;

	__user_mfa_id := (__token.token_data ->> 'user_mfa_id')::bigint;

	select um.recovery_codes
	from auth.user_mfa um
	where um.user_mfa_id = __user_mfa_id
	into __recovery_codes;

	-- TOTP code
	if _is_code_valid then
		update auth.token
		set token_state_code = 'used'
			, used_at          = now()
			, updated_at       = now()
			, updated_by       = _created_by
		where token_id = __token.token_id;

		select * from unsecure.update_user_login_state(_created_by, _target_user_id, true) into __state;

		select e.__user_event_id
		from unsecure.create_user_event(_created_by, _user_id, _correlation_id, 'mfa_challenge_passed', _target_user_id
			, _request_context := _request_context
			, _event_data := jsonb_build_object('mfa_type', __token.token_data ->> 'mfa_type'
				, 'token_uid', _token_uid, 'method', 'totp')) e
		into ___user_event_id;

		return query select 10093, 'mfa_challenge_passed', ___user_event_id
			, coalesce(array_length(__recovery_codes, 1), 0), 0, null::timestamptz;
		return;
	end if;

	-- recovery code
	if _recovery_code is not null then
		__recovery_hash := encode(ext.digest(_recovery_code, 'sha256'), 'hex');

		if array_position(__recovery_codes, __recovery_hash) is not null then
			__recovery_codes := array_remove(__recovery_codes, __recovery_hash);

			update auth.user_mfa
			set recovery_codes = __recovery_codes
				, updated_at     = now()
				, updated_by     = _created_by
			where user_mfa_id = __user_mfa_id;

			update auth.token
			set token_state_code = 'used'
				, used_at          = now()
				, updated_at       = now()
				, updated_by       = _created_by
			where token_id = __token.token_id;

			select * from unsecure.update_user_login_state(_created_by, _target_user_id, true) into __state;

			select e.__user_event_id
			from unsecure.create_user_event(_created_by, _user_id, _correlation_id, 'mfa_recovery_used', _target_user_id
				, _request_context := _request_context
				, _event_data := jsonb_build_object('mfa_type', __token.token_data ->> 'mfa_type'
					, 'token_uid', _token_uid
					, 'recovery_codes_remaining', coalesce(array_length(__recovery_codes, 1), 0))) e
			into ___user_event_id;

			return query select 10094, 'mfa_recovery_used', ___user_event_id
				, coalesce(array_length(__recovery_codes, 1), 0), 0, null::timestamptz;
			return;
		end if;
	end if;

	-- neither valid: the token is spent, the failure counts toward the lockout
	update auth.token
	set token_state_code = 'failed'
		, updated_at       = now()
		, updated_by       = _created_by
	where token_id = __token.token_id;

	select e.__user_event_id
	from unsecure.create_user_event(_created_by, _user_id, _correlation_id, 'mfa_challenge_failed', _target_user_id
		, _request_context := _request_context
		, _event_data := jsonb_build_object('mfa_type', __token.token_data ->> 'mfa_type'
			, 'token_uid', _token_uid, 'reason', 'invalid_code')) e
	into ___user_event_id;

	select * from unsecure.update_user_login_state(_created_by, _target_user_id, false) into __state;

	if __state.__is_lockout_triggered then
		perform unsecure.create_user_event(_created_by, _user_id, _correlation_id, 'user_auto_locked', _target_user_id
			, _request_context := _request_context
			, _event_data := jsonb_build_object('failed_login_count', __state.__failed_login_count
				, 'locked_until', __state.__locked_until));

		return query select 33004, 'err_user_locked', ___user_event_id
			, coalesce(array_length(__recovery_codes, 1), 0), __state.__failed_login_count, __state.__locked_until;
		return;
	end if;

	return query select 38004, 'err_mfa_invalid_code', ___user_event_id
		, coalesce(array_length(__recovery_codes, 1), 0), __state.__failed_login_count, null::timestamptz;
end;
$$;

-- ---------------------------------------------------------------------------
-- auth.create_api_key_validation_attempt - authenticate a service by API key
-- and secret. Returns the technical user on success; the user columns are null
-- on a failure. Permissions are not returned - ask auth.has_permission with
-- __user_id. No lockout for API keys; every failure is logged.
--
-- Outcomes: 14010 apikey_validated, 30001 err_api_key_invalid (unknown key or
-- wrong secret), 30006 err_api_key_expired, 33003 err_user_not_active,
-- 33004 err_user_locked
-- ---------------------------------------------------------------------------
create or replace function auth.create_api_key_validation_attempt(_created_by text, _user_id bigint, _correlation_id text, _api_key text, _api_secret text, _request_context jsonb DEFAULT NULL::jsonb, _tenant_id integer DEFAULT 1)
    returns TABLE(__user_id bigint, __username text, __user_display_name text, __event_id integer, __outcome_code text, __user_event_id bigint)
    rows 1
    language plpgsql
as
$$
declare
	__key            record;
	__failure_event_id     integer;
	__failure_outcome_code text;
	__failure_reason       text;
	___user_event_id bigint;
begin
	perform auth.has_permission(_user_id, _correlation_id, 'api_keys.validate_api_key', _tenant_id);

	select ak.api_key_id, ak.secret_hash, ak.expire_at
			 , ui.user_id as technical_user_id, ui.username, ui.display_name, ui.is_active, ui.is_locked
	from auth.api_key ak
				 left join auth.user_info ui on ui.code = auth.generate_api_key_username(ak.api_key)
	where ak.api_key = _api_key
		and ak.tenant_id = _tenant_id
	into __key;

	if __key.api_key_id is null then
		__failure_event_id := 30001; __failure_outcome_code := 'err_api_key_invalid'; __failure_reason := 'unknown_key';
	elsif __key.secret_hash is distinct from auth.generate_api_secret_hash(_api_secret) then
		__failure_event_id := 30001; __failure_outcome_code := 'err_api_key_invalid'; __failure_reason := 'wrong_secret';
	elsif __key.expire_at is not null and __key.expire_at <= now() then
		__failure_event_id := 30006; __failure_outcome_code := 'err_api_key_expired'; __failure_reason := 'expired';
	elsif __key.technical_user_id is null or not __key.is_active then
		__failure_event_id := 33003; __failure_outcome_code := 'err_user_not_active'; __failure_reason := 'user_disabled';
	elsif __key.is_locked then
		__failure_event_id := 33004; __failure_outcome_code := 'err_user_locked'; __failure_reason := 'user_locked';
	end if;

	if __failure_event_id is not null then
		select e.__user_event_id
		from unsecure.create_user_event(_created_by, _user_id, _correlation_id, 'apikey_validation_failed', __key.technical_user_id
			, _request_context := _request_context
			, _event_data := jsonb_build_object('api_key', _api_key, 'reason', __failure_reason)) e
		into ___user_event_id;

		return query select null::bigint, null::text, null::text, __failure_event_id, __failure_outcome_code, ___user_event_id;
		return;
	end if;

	select e.__user_event_id
	from unsecure.create_user_event(_created_by, _user_id, _correlation_id, 'apikey_validated', __key.technical_user_id
		, _request_context := _request_context
		, _event_data := jsonb_build_object('api_key', _api_key)) e
	into ___user_event_id;

	return query select __key.technical_user_id, __key.username, __key.display_name, 14010, 'apikey_validated', ___user_event_id;
end;
$$;


select *
from public.stop_version_update('2.6', _component := 'postgresql_permissionmodel');
