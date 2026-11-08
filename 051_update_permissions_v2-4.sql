/*
 * PostgreSQL Permissions Model — update v2.4
 * ==========================================
 *
 * Account takeover by username (audit finding, domain 01):
 *
 *  - unsecure.create_user_info returned the EXISTING user when the username was
 *    taken. auth.register_user and the first-login branch of
 *    auth.ensure_user_from_provider then attached a new identity to that user:
 *      - register_user('jane@corp.com', <attacker hash>) put a password login on
 *        an SSO-only user whose username is jane@corp.com
 *      - a first login from a second provider whose username claim matched an
 *        existing username was linked to that user
 *    create_user_info now raises 33024 when the username exists, and
 *    register_user checks the username up front and raises 33007, the same
 *    error as for an email identity already in use.
 *  - Linking a second identity to an existing user is now explicit:
 *    auth.create_user_identity_link. A user may link to their own account
 *    without a permission; linking to another user's account requires
 *    users.create_user_identity_link. A linked email identity starts unverified.
 *
 * New error code: 33024 (username already exists).
 * New event code: 10036 identity_linked.
 * New permission: users.create_user_identity_link.
 */

set search_path = public, const, ext, stage, helpers, internal, unsecure, auth, triggers;

select *
from public.start_version_update('2.4', 'No identity linking by username',
                                 _component := 'postgresql_permissionmodel',
                                 _description := 'create_user_info raises 33024 for an existing username; register_user raises 33007; new auth.create_user_identity_link for explicit linking.');


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
values (10036, 'identity_linked', 'user_event', true, 'core')
     , (33024, 'err_username_already_exists', 'user_error', true, 'core')
on conflict do nothing;

insert into const.event_message (event_id, language_code, message_template)
values (10036, 'en', 'Identity "{provider_code}" was linked to user "{username}" by {actor}')
     , (33024, 'en', 'User (username: {username}) already exists; link the identity explicitly with auth.create_user_identity_link')
on conflict do nothing;

-- 33024: Username already exists
create or replace function error.raise_33024(_username text) returns void
    language plpgsql
as
$$
begin
    raise exception 'User (username: %) already exists; link the identity explicitly with auth.create_user_identity_link', _username
        using errcode = '33024';
end;
$$;


/***
 *    ██████╗ ███████╗██████╗ ███╗   ███╗██╗███████╗███████╗██╗ ██████╗ ███╗   ██╗███████╗
 *    ██╔══██╗██╔════╝██╔══██╗████╗ ████║██║██╔════╝██╔════╝██║██╔═══██╗████╗  ██║██╔════╝
 *    ██████╔╝█████╗  ██████╔╝██╔████╔██║██║███████╗███████╗██║██║   ██║██╔██╗ ██║███████╗
 *    ██╔═══╝ ██╔══╝  ██╔══██╗██║╚██╔╝██║██║╚════██║╚════██║██║██║   ██║██║╚██╗██║╚════██║
 *    ██║     ███████╗██║  ██║██║ ╚═╝ ██║██║███████║███████║██║╚██████╔╝██║ ╚████║███████║
 *    ╚═╝     ╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝╚═╝╚══════╝╚══════╝╚═╝ ╚═════╝ ╚═╝  ╚═══╝╚══════╝
 *
 */

select unsecure.create_permission_as_system('Create user identity link', 'users', _source := 'core')
where not exists(select from auth.permission where full_code = 'users.create_user_identity_link');

-- Perm sets that hold the `users` node pick up the new child at calculation time, but
-- caches built before this script do not contain it. Expire them once.
update auth.user_permission_cache
set expiration_date = now()
  , updated_by      = 'update_v2.4'
  , updated_at      = now()
where expiration_date > now();


/***
 *    ███████╗██╗   ██╗███╗   ██╗ ██████╗████████╗██╗ ██████╗ ███╗   ██╗███████╗
 *    ██╔════╝██║   ██║████╗  ██║██╔════╝╚══██╔══╝██║██╔═══██╗████╗  ██║██╔════╝
 *    █████╗  ██║   ██║██╔██╗ ██║██║        ██║   ██║██║   ██║██╔██╗ ██║███████╗
 *    ██╔══╝  ██║   ██║██║╚██╗██║██║        ██║   ██║██║   ██║██║╚██╗██║╚════██║
 *    ██║     ╚██████╔╝██║ ╚████║╚██████╗   ██║   ██║╚██████╔╝██║ ╚████║███████║
 *    ╚═╝      ╚═════╝ ╚═╝  ╚═══╝ ╚═════╝   ╚═╝   ╚═╝ ╚═════╝ ╚═╝  ╚═══╝╚══════╝
 *
 */

-- Creates a new user. An existing username raises 33024 - it never returns the
-- existing user, because every caller attaches an identity to the returned user.
create or replace function unsecure.create_user_info(_created_by text, _user_id bigint, _correlation_id text, _username text, _email text, _display_name text, _last_provider_code text) returns SETOF auth.user_info
    rows 1
    language plpgsql
as
$$
declare
	__last_id             bigint;
	__normalized_username text;
	__normalized_email    text;
begin
	__normalized_username := lower(trim(_username));
	__normalized_email := lower(trim(_email));

	-- check blacklist before creating user
	if unsecure.check_user_blacklist(_username := __normalized_username) then
		perform error.raise_33018(__normalized_username);
	end if;

	if exists(select from auth.user_info where username = __normalized_username) then
		perform error.raise_33024(__normalized_username);
	end if;

	insert into auth.user_info ( created_by, updated_by, user_type_code, username, original_username, email, original_email
														 , display_name, last_used_provider_code)
	values ( _created_by, _created_by, 'normal', __normalized_username, trim(_username), __normalized_email, trim(_email)
				 , _display_name, _last_provider_code)
	returning user_id into __last_id;

	return query
		select *
		from auth.user_info
		where user_id = __last_id;

	perform public.create_journal_message_for_entity('system', _user_id, _correlation_id
			, 10001  -- user_created
			, 'user', __last_id
			, jsonb_build_object('username', __normalized_username, 'email', __normalized_email
				, 'display_name', _display_name)
			, 1);
end;
$$;

create or replace function auth.register_user(_created_by text, _user_id bigint, _correlation_id text, _email text, _password_hash text, _display_name text, _user_data jsonb DEFAULT NULL::jsonb, _request_context jsonb DEFAULT NULL::jsonb, _tenant_id integer default 1)
    returns TABLE(__user_id bigint, __code text, __uuid text, __username text, __email text, __display_name text)
    rows 1
    language plpgsql
as
$$
declare
	__normalized_email text;
	__new_user         auth.user_info;
begin

	perform
		auth.has_permission(_user_id, _correlation_id, 'users.register_user', _tenant_id);

	__normalized_email := lower(trim(_email));

	perform
		auth.validate_provider_is_active('email');

	-- An email identity with this address, or any user with this username, means the
	-- address is taken. Both raise 33007 so the caller cannot tell which one it was.
	if
		exists(
						select
						from auth.user_identity ui
						where ui.provider_code = 'email'
							and ui.uid = __normalized_email
			)
		or exists(
						select
						from auth.user_info u
						where u.username = __normalized_email
			) then
		perform error.raise_52102(__normalized_email);
	end if;

	select *
	from unsecure.create_user_info(_created_by, _user_id, _correlation_id, _email, _email, _display_name,
																 'email')
	into __new_user;

	perform unsecure.create_user_identity(_created_by, _user_id, _correlation_id, __new_user.user_id
		, 'email', __normalized_email, __normalized_email, _password_hash, _is_active := true);

	perform
		auth.update_user_data(_created_by, _user_id, _correlation_id, __new_user.user_id, 'email', _user_data);

	perform unsecure.create_user_event(_created_by, _user_id, _correlation_id, 'user_registered',
		__new_user.user_id,
		_request_context := _request_context,
		_event_data := jsonb_build_object('email', __normalized_email, 'provider', 'email'));

	return query
		select __new_user.user_id
				 , __new_user.code
				 , __new_user.uuid::text
				 , __new_user.username
				 , __new_user.email
				 , __new_user.display_name;
end;
$$;

-- Links an additional identity to an existing user.
--
-- The caller (the app) is responsible for having authenticated BOTH sides: the
-- user's current session (_user_id) and the new identity (the provider callback,
-- or the password the user just chose). The database cannot verify either.
--   * _target_user_id = _user_id : self-link, no permission needed
--   * otherwise                  : users.create_user_identity_link in _tenant_id
-- A linked email identity starts unverified; run the email verification flow
-- (auth.verify_user_identity) before trusting the address.
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
			auth.has_permission(_user_id, _correlation_id, 'users.create_user_identity_link', _tenant_id);
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


select *
from public.stop_version_update('2.4', _component := 'postgresql_permissionmodel');
