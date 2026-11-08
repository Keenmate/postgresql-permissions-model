set search_path = public, const, ext, stage, helpers, internal, unsecure, auth, triggers;

-- ============================================================================
-- Invitations, invitation templates and MFA policies of tenant A, called by
-- admin_b with _tenant_id = B. Global templates and policies (tenant_id null)
-- are managed from tenant 1 only.
-- ============================================================================
do $$
begin
    raise notice '';
    raise notice '--- 003: invitations, templates and MFA policies of tenant A, called with _tenant_id = B ---';

    perform pg_temp.a02_expect('get_invitation_actions',
        'select * from auth.get_invitation_actions(''t'', {admin_b_id}, ''c'', {inv_a_id}, {b_id})', '39001');
    perform pg_temp.a02_expect('accept_invitation',
        'select * from auth.accept_invitation(''t'', {admin_b_id}, ''c'', ''{inv_a_uuid}''::uuid, {admin_b_id}, null, {b_id})', '39001');
    perform pg_temp.a02_expect('reject_invitation',
        'select * from auth.reject_invitation(''t'', {admin_b_id}, ''c'', ''{inv_a_uuid}''::uuid, null, {b_id})', '39001');
    perform pg_temp.a02_expect('revoke_invitation',
        'select auth.revoke_invitation(''t'', {admin_b_id}, ''c'', {inv_a_id}, null, {b_id})', '39001');

    perform pg_temp.a02_expect('update_invitation_template (A)',
        'select auth.update_invitation_template(''t'', {admin_b_id}, ''c'', {tmpl_a_id}, ''hijacked'', _tenant_id := {b_id})', '39006');
    perform pg_temp.a02_expect('update_invitation_template (global)',
        'select auth.update_invitation_template(''t'', {admin_b_id}, ''c'', {tmpl_g_id}, ''hijacked'', _tenant_id := {b_id})', '39006');
    perform pg_temp.a02_expect('delete_invitation_template (A)',
        'select auth.delete_invitation_template(''t'', {admin_b_id}, ''c'', {tmpl_a_id}, null, {b_id})', '39006');
    perform pg_temp.a02_expect('delete_invitation_template (global)',
        'select auth.delete_invitation_template(''t'', {admin_b_id}, ''c'', {tmpl_g_id}, null, {b_id})', '39006');

    perform pg_temp.a02_expect('delete_mfa_policy',
        'select auth.delete_mfa_policy(''t'', {admin_b_id}, ''c'', {mfa_a_id}, null, {b_id})', '38007');
    perform pg_temp.a02_expect('create_mfa_policy (A''s group)',
        'select * from auth.create_mfa_policy(''t'', {admin_b_id}, ''c'', {b_id}, {ga_id}, null, true)', '33011');
    perform pg_temp.a02_expect('create_mfa_policy (global, from B)',
        'select * from auth.create_mfa_policy(''t'', {admin_b_id}, ''c'', null, null, null, true)', '32001');
end $$;

do $$
declare
    __inv_status text;
begin
    select status_code from auth.invitation where invitation_id = pg_temp.a02('inv_a_id')::bigint into __inv_status;
    if __inv_status = 'pending' then
        raise notice 'PASS: A''s invitation is still pending';
    else
        raise notice 'FAIL: A''s invitation status is %', __inv_status;
    end if;

    if (select count(*) from auth.invitation_template
        where template_id in (pg_temp.a02('tmpl_a_id')::int, pg_temp.a02('tmpl_g_id')::int)
          and title <> 'hijacked') = 2 then
        raise notice 'PASS: A''s and the global template are unchanged';
    else
        raise notice 'FAIL: a template was changed or deleted';
    end if;

    if exists(select from auth.mfa_policy where mfa_policy_id = pg_temp.a02('mfa_a_id')::bigint) then
        raise notice 'PASS: A''s MFA policy still exists';
    else
        raise notice 'FAIL: A''s MFA policy was deleted';
    end if;

    if exists(select from auth.mfa_policy where user_group_id = pg_temp.a02('ga_id')::int)
        or exists(select from auth.mfa_policy where tenant_id is null and created_by = 't') then
        raise notice 'FAIL: admin_b created an MFA policy for A''s group or a global one';
    else
        raise notice 'PASS: no MFA policy created for A''s group or globally';
    end if;
end $$;

-- Own tenant still works: admin_b revokes an invitation of B
do $$
declare
    __b     int    := pg_temp.a02('b_id')::int;
    __admin bigint := pg_temp.a02('admin_b_id')::bigint;
    __inv   bigint;
begin
    select i.__invitation_id from auth.create_invitation('t', __admin, 'c', __b, 'audit02_b_target@example.com') i into __inv;
    perform auth.revoke_invitation('t', __admin, 'c', __inv, null, __b);
    if (select status_code from auth.invitation where invitation_id = __inv) = 'revoked' then
        raise notice 'PASS: own tenant: invitation created and revoked';
    else
        raise notice 'FAIL: own tenant: invitation not revoked';
    end if;
end $$;
