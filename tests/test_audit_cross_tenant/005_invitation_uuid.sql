set search_path = public, const, ext, stage, helpers, internal, unsecure, auth, triggers;

-- ============================================================================
-- accept_invitation / reject_invitation take the invitation uuid (the secret
-- sent to the recipient), not the guessable sequential id. The id-based
-- overloads are gone; an unknown uuid, or one of another tenant, raises 39001.
-- ============================================================================
do $$
begin
    raise notice '';
    raise notice '--- 005: invitations are accepted and rejected by uuid ---';

    if exists(select
              from pg_proc p
                       inner join pg_namespace n on n.oid = p.pronamespace
              where n.nspname = 'auth'
                and p.proname in ('accept_invitation', 'reject_invitation')
                and 'bigint'::regtype = p.proargtypes[3]) then
        raise notice 'FAIL: an id-based accept_invitation / reject_invitation still exists';
    else
        raise notice 'PASS: no id-based accept_invitation / reject_invitation';
    end if;

    perform pg_temp.a02_expect('accept_invitation with an unknown uuid',
        'select * from auth.accept_invitation(''t'', {admin_b_id}, ''c'', gen_random_uuid(), {admin_b_id}, null, {b_id})', '39001');
    perform pg_temp.a02_expect('reject_invitation with an unknown uuid',
        'select * from auth.reject_invitation(''t'', {admin_b_id}, ''c'', gen_random_uuid(), null, {b_id})', '39001');
    perform pg_temp.a02_expect('accept_invitation with A''s uuid from B',
        'select * from auth.accept_invitation(''t'', {admin_b_id}, ''c'', ''{inv_a_uuid}''::uuid, {admin_b_id}, null, {b_id})', '39001');
end $$;

-- Own tenant: accept by uuid
do $$
declare
    __b      int    := pg_temp.a02('b_id')::int;
    __admin  bigint := pg_temp.a02('admin_b_id')::bigint;
    __member bigint := pg_temp.a02('member_id')::bigint;
    __inv    bigint;
    __uuid   uuid;
begin
    select i.__invitation_id, i.__uuid
    from auth.create_invitation('t', __admin, 'c', __b, 'audit02_uuid@example.com') i
    into __inv, __uuid;

    perform auth.accept_invitation('t', __admin, 'c', __uuid, __member, null, __b);

    if (select target_user_id from auth.invitation where invitation_id = __inv) = __member then
        raise notice 'PASS: own tenant: invitation accepted by uuid';
    else
        raise notice 'FAIL: own tenant: invitation not accepted by uuid';
    end if;
end $$;
