set search_path = public, const, ext, stage, helpers, internal, unsecure, auth, triggers;

-- ============================================================================
-- Invitation action add_tenant_user adds the user to T's Tenant Members group;
-- condition user_not_in_tenant uses the computed membership.
-- ============================================================================
do $$
declare
    __t        int    := (select val from _d03 where key = 't');
    __admin    bigint := (select val from _d03 where key = 'admin');
    __invitee  bigint := (select val from _d03 where key = 'invitee');
    __direct   bigint := (select val from _d03 where key = 'direct');
    __members  int    := (select user_group_id from auth.user_group where tenant_id = __t and code = 'tenant_members');
    __actions  jsonb  := '[{"action_type_code": "add_tenant_user", "phase_code": "on_accept", "sequence": 0, "condition_code": "user_not_in_tenant"}]';
    __uuid     uuid;
    __status   text;
begin
    raise notice '';
    raise notice '--- 003: invitations ---';

    select i.__uuid from auth.create_invitation('d03', __admin, 'd03', __t, 'd03_invitee@test.com', __actions) i into __uuid;
    perform auth.accept_invitation('d03', __admin, 'd03', __uuid, __invitee, _tenant_id := __t);

    if exists(select from auth.user_group_member where user_group_id = __members and user_id = __invitee) then
        raise notice 'PASS: add_tenant_user put the invitee into Tenant Members of T';
    else
        raise notice 'FAIL: invitee is not in Tenant Members of T';
    end if;

    if exists(select from auth.search_users(__admin, 'd03', null, 1, 1000, __t) s where s.__user_id = __invitee) then
        raise notice 'PASS: the invitee is listed as a member of T';
    else
        raise notice 'FAIL: the invitee is not listed in T';
    end if;

    -- already a member (direct grant): the condition skips the action
    select i.__uuid from auth.create_invitation('d03', __admin, 'd03', __t, 'd03_direct@test.com', __actions) i into __uuid;
    perform auth.accept_invitation('d03', __admin, 'd03', __uuid, __direct, _tenant_id := __t);

    select ia.status_code from auth.invitation_action ia
    inner join auth.invitation i on i.invitation_id = ia.invitation_id
    where i.uuid = __uuid
    into __status;
    if __status = 'skipped'
       and not exists(select from auth.user_group_member where user_group_id = __members and user_id = __direct) then
        raise notice 'PASS: user_not_in_tenant skips a member who only has a direct grant';
    else
        raise notice 'FAIL: expected skipped and no group membership, got status %', __status;
    end if;
end $$;
