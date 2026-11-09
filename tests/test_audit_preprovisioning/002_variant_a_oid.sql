set search_path = public, const, ext, stage, helpers, internal, unsecure, auth, triggers;

-- ============================================================================
-- Variant A: identity pre-created by object id, the first login fills the uid
-- ============================================================================
do $$
declare
    __dan   bigint;
    __ivy   bigint;
    __r     record;
    __state text;
begin
    raise notice '';
    raise notice '--- 002: pre-provisioned identity (object id) ---';

    -- invitation service: Dan and Ivy from the directory, Dan becomes CDE admin
    select u.__user_id from auth.ensure_user_info('p18', 2, 'p18', 'dan@p18.com', 'Dan', 'p18_aad', 'dan@p18.com'
        , _provider_oid := 'oid-dan') u into __dan;
    select u.__user_id from auth.ensure_user_info('p18', 2, 'p18', 'ivy@p18.com', 'Ivy', 'p18_aad', 'ivy@p18.com'
        , _provider_oid := 'oid-ivy') u into __ivy;
    perform pg_temp.p18_is('two identities of one provider pre-created without uid',
        (select count(*)::text from auth.user_identity where user_id in (__dan, __ivy) and provider_code = 'p18_aad' and uid is null), '2');

    perform auth.create_user_group_member('p18', 1, 'p18', (select val::int from _p18 where key = 'cde_admins'), __dan
        , (select val::int from _p18 where key = 'cde'));

    -- the same object id cannot be pre-provisioned for someone else
    begin
        perform auth.ensure_user_info('p18', 2, 'p18', 'mallory@p18.com', 'Mallory', 'p18_aad', null, _provider_oid := 'oid-dan');
        raise notice 'FAIL: an object id was pre-provisioned for two users';
    exception when others then
        get stacked diagnostics __state = returned_sqlstate;
        perform pg_temp.p18_is('object id of another user rejected (33007)', __state, '33007');
    end;

    -- someone with Dan's username but another object id: Dan has an identity, no claim
    select * from pg_temp.p18_login('dan', null, _uid := 'uid-fake', _oid := 'oid-fake') into __r;
    perform pg_temp.p18_is('same username, other object id: 33024', __r.__outcome_code, 'err_username_already_exists');

    -- Dan's first login
    select * from pg_temp.p18_login('dan', array[]::text[]) into __r;
    perform pg_temp.p18_is('Dan logs in as the pre-provisioned user', __r.__outcome_code || ':' || (__r.__user_id = __dan), 'user_logged_in:true');
    perform pg_temp.p18_is('uid filled in and verified',
        (select uid || ':' || is_verified from auth.user_identity where user_id = __dan and provider_code = 'p18_aad'), 'uid-dan:true');
    perform pg_temp.p18_is('Dan: CDE in the combobox, admin of CDE', pg_temp.p18_tenants('dan'), 'p18_cde / admin: p18_cde');

    -- second login is an ordinary one
    select * from pg_temp.p18_login('dan', array[]::text[]) into __r;
    perform pg_temp.p18_is('Dan logs in again', __r.__outcome_code || ':' || (__r.__user_id = __dan), 'user_logged_in:true');
end $$;
