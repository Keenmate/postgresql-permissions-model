/*
 * PostgreSQL Permissions Model — update v2.10
 * ===========================================
 *
 * Two read functions with wrong scoping (audit follow-ups to D-02).
 *
 *  - auth.get_invitations: a tenant-1 caller filtering by _target_tenant_id was
 *    checked for invitations.get_all_invitations in the target tenant instead of
 *    tenant 1, so an admin of tenant N could list N's invitations through the
 *    admin console path. The permission is checked in tenant 1.
 *  - auth.get_api_key_permissions had no permission check of its own and called
 *    auth.get_user_permissions (auth -> auth), which defaulted to tenant 1 and
 *    demanded users.get_all_permissions there, so tenant admins could not use it
 *    and the key's tenant was never compared. It now checks api_keys.search in
 *    _tenant_id, validates the key belongs to _tenant_id (30007) and returns the
 *    key's assignments in _tenant_id.
 */

set search_path = public, const, ext, stage, helpers, internal, unsecure, auth, triggers;

select *
from public.start_version_update('2.10', 'get_invitations and get_api_key_permissions scoping',
                                 _component := 'postgresql_permissionmodel',
                                 _description := 'get_invitations checks get_all_invitations in tenant 1; get_api_key_permissions checks api_keys.search in _tenant_id, validates the key tenant and stops calling auth.get_user_permissions.');


create or replace function auth.get_invitations(
    _requested_by    text,
    _user_id         bigint,
    _correlation_id  text,
    _tenant_id       integer default 1,
    _target_tenant_id integer default null,
    _status_code     text default null,
    _target_email    text default null,
    _inviter_user_id bigint default null
) returns table(
    __invitation_id   bigint,
    __uuid            uuid,
    __tenant_id       integer,
    __inviter_user_id bigint,
    __target_email    text,
    __target_user_id  bigint,
    __status_code     text,
    __message         text,
    __template_code   text,
    __expires_at      timestamptz,
    __accepted_at     timestamptz,
    __rejected_at     timestamptz,
    __revoked_at      timestamptz,
    __created_at      timestamptz,
    __created_by      text,
    __action_count    bigint,
    __pending_actions  bigint
)
    language plpgsql
as
$$
declare
    __effective_tenant_id int;
begin
    if _target_tenant_id is not null then
        -- filtering by specific tenant - only allowed from admin console
        if _tenant_id <> 1 then
            perform error.raise_34002(_tenant_id);
        end if;
        perform auth.has_permission(_user_id, _correlation_id, 'invitations.get_all_invitations', _tenant_id);
        __effective_tenant_id := _target_tenant_id;
    elsif _tenant_id = 1 then
        -- admin console without target tenant - show all
        perform auth.has_permission(_user_id, _correlation_id, 'invitations.get_all_invitations', _tenant_id);
        __effective_tenant_id := null;
    else
        -- regular tenant - filter by own tenant
        perform auth.has_permission(_user_id, _correlation_id, 'invitations.get_invitations', _tenant_id);
        __effective_tenant_id := _tenant_id;
    end if;

    return query select * from unsecure.get_invitations(
        _requested_by, _user_id, _correlation_id, __effective_tenant_id,
        _status_code, _target_email, _inviter_user_id
    );
end;
$$;

create or replace function auth.get_api_key_permissions(_user_id bigint, _correlation_id text, _api_key_id integer, _tenant_id integer)
    returns TABLE(__assignment_id bigint, __perm_set_code text, __perm_set_title text, __user_group_member_id bigint, __user_group_title text, __permission_inheritance_type text, __permission_full_code text, __permission_title text, __tenant_id integer, __tenant_code text, __tenant_title text)
    stable
    language plpgsql
as
$$
begin
	perform auth.has_permission(_user_id, _correlation_id, 'api_keys.search', _tenant_id);

	perform unsecure.validate_api_key_in_tenant(_api_key_id, _tenant_id);

	-- the key's technical user, its assignments in _tenant_id only
	return query
		select pa.assignment_id
				 , ps.code
				 , coalesce((select mv.values->>'title' from public.mv_translation mv where mv.data_group = 'perm_set' and mv.data_object_code = ps.code and mv.language_code = 'en'), ps.code)
				 , null::bigint
				 , null::text
				 , case when ps.perm_set_id is not null then 'perm_set' else 'assignment' end
				 , p.full_code::text
				 , coalesce((select mv.values->>'title' from public.mv_translation mv where mv.data_group = 'permission' and mv.data_object_code = p.code and mv.language_code = 'en'), p.code)
				 , t.tenant_id
				 , t.code
				 , t.title
		from auth.api_key ak
					 inner join auth.user_info ui on ui.user_type_code = 'api' and ui.code = auth.generate_api_key_username(ak.api_key)
					 inner join auth.permission_assignment pa on pa.user_id = ui.user_id and pa.tenant_id = _tenant_id
					 left join auth.perm_set ps on ps.perm_set_id = pa.perm_set_id
					 left join auth.perm_set_perm psp on psp.perm_set_id = ps.perm_set_id
					 inner join auth.permission p on p.permission_id = pa.permission_id
			or p.permission_id = psp.permission_id
					 inner join auth.tenant t on t.tenant_id = pa.tenant_id
		where ak.api_key_id = _api_key_id
		order by ps.code nulls last, p.full_code;
end;
$$;


select *
from public.stop_version_update('2.10', _component := 'postgresql_permissionmodel');
