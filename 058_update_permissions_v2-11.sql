/*
 * PostgreSQL Permissions Model — update v2.11
 * ===========================================
 *
 * Invitations are accepted and rejected by uuid.
 *
 * auth.accept_invitation / auth.reject_invitation took the sequential
 * invitation id. Anyone holding invitations.accept_invitation could accept any
 * pending invitation of their tenant for any user - for example accept an
 * "add to tenant_admins" invitation meant for someone else, for themselves.
 *
 * Both now take _invitation_uuid: the unguessable uuid that is sent to the
 * recipient in the email / SMS link. Only someone who received the link (or
 * the backend acting on their behalf) can accept or reject. This works for
 * email and phone targets alike and needs no address matching. The permission
 * check and the tenant check (v2.8) stay; an unknown uuid, or one of another
 * tenant, raises 39001.
 *
 * Revoke and get_invitation_actions are admin operations and stay id-based.
 *
 * Breaking: the id-based overloads are dropped.
 */

set search_path = public, const, ext, stage, helpers, internal, unsecure, auth, triggers;

select *
from public.start_version_update('2.11', 'Invitations are accepted and rejected by uuid',
                                 _component := 'postgresql_permissionmodel',
                                 _description := 'accept_invitation and reject_invitation take the invitation uuid (the secret sent to the recipient) instead of the sequential id; the id-based overloads are dropped.');


/***
 *    ███████╗██╗   ██╗███╗   ██╗ ██████╗████████╗██╗ ██████╗ ███╗   ██╗███████╗
 *    ██╔════╝██║   ██║████╗  ██║██╔════╝╚══██╔══╝██║██╔═══██╗████╗  ██║██╔════╝
 *    █████╗  ██║   ██║██╔██╗ ██║██║        ██║   ██║██║   ██║██╔██╗ ██║███████╗
 *    ██╔══╝  ██║   ██║██║╚██╗██║██║        ██║   ██║██║   ██║██║╚██╗██║╚════██║
 *    ██║     ╚██████╔╝██║ ╚████║╚██████╗   ██║   ██║╚██████╔╝██║  ██║███████║
 *    ╚═╝      ╚═════╝ ╚═╝  ╚═══╝ ╚═════╝   ╚═╝   ╚═╝ ╚═════╝ ╚═╝  ╚═══╝╚══════╝
 *
 */

drop function if exists auth.accept_invitation(text, bigint, text, bigint, bigint, jsonb, integer);
drop function if exists auth.reject_invitation(text, bigint, text, bigint, jsonb, integer);

-- Returns the id of the invitation with _invitation_uuid in _tenant_id; raises 39001
-- when there is none, also when the uuid belongs to another tenant.
create or replace function unsecure.validate_invitation_uuid_in_tenant(_invitation_uuid uuid, _tenant_id integer) returns bigint
    stable
    language plpgsql
as
$$
declare
    __invitation_id bigint;
begin
    select i.invitation_id
    from auth.invitation i
    where i.uuid = _invitation_uuid
      and i.tenant_id = _tenant_id
    into __invitation_id;

    if __invitation_id is null then
        perform error.raise_39001(null);
    end if;

    return __invitation_id;
end;
$$;

create or replace function auth.accept_invitation(
    _updated_by      text,
    _user_id         bigint,
    _correlation_id  text,
    _invitation_uuid uuid,
    _target_user_id  bigint,
    _request_context jsonb default null,
    _tenant_id       integer default 1
) returns table(
    __invitation_action_id bigint,
    __action_type_code     text,
    __executor_code        text,
    __sequence             integer,
    __payload              jsonb
)
    language plpgsql
as
$$
declare
    __invitation_id bigint;
begin
    perform auth.has_permission(_user_id, _correlation_id, 'invitations.accept_invitation', _tenant_id);

    __invitation_id := unsecure.validate_invitation_uuid_in_tenant(_invitation_uuid, _tenant_id);

    perform unsecure.accept_invitation(
        _updated_by, _user_id, _correlation_id, __invitation_id, _target_user_id
    );

    perform unsecure.create_user_event(_updated_by, _user_id, _correlation_id,
        'invitation_accepted', _target_user_id, _request_context := _request_context,
        _event_data := jsonb_build_object('invitation_id', __invitation_id));

    -- Process on_accept phase actions
    return query select * from unsecure.process_invitation_actions(
        _updated_by, _user_id, _correlation_id, __invitation_id, 'on_accept'
    );
end;
$$;

create or replace function auth.reject_invitation(
    _updated_by      text,
    _user_id         bigint,
    _correlation_id  text,
    _invitation_uuid uuid,
    _request_context jsonb default null,
    _tenant_id       integer default 1
) returns table(
    __invitation_action_id bigint,
    __action_type_code     text,
    __executor_code        text,
    __sequence             integer,
    __payload              jsonb
)
    language plpgsql
as
$$
declare
    __invitation_id bigint;
begin
    perform auth.has_permission(_user_id, _correlation_id, 'invitations.reject_invitation', _tenant_id);

    __invitation_id := unsecure.validate_invitation_uuid_in_tenant(_invitation_uuid, _tenant_id);

    perform unsecure.reject_invitation(
        _updated_by, _user_id, _correlation_id, __invitation_id
    );

    perform unsecure.create_user_event(_updated_by, _user_id, _correlation_id,
        'invitation_rejected', null, _request_context := _request_context,
        _event_data := jsonb_build_object('invitation_id', __invitation_id));

    -- Process on_reject phase actions (e.g. notify inviter of rejection)
    return query select * from unsecure.process_invitation_actions(
        _updated_by, _user_id, _correlation_id, __invitation_id, 'on_reject'
    );
end;
$$;


select *
from public.stop_version_update('2.11', _component := 'postgresql_permissionmodel');
