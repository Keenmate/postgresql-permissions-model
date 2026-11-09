set search_path = public, const, ext, stage, helpers, internal, unsecure, auth, triggers;

-- ============================================================================
-- Variant B: a user pre-provisioned for a provider, without identities, is
-- claimed by the first login of that provider with the same username
-- ============================================================================
do $$
declare
    __eve   bigint;
    __frank bigint;
    __gina  bigint;
    __hank  bigint;
    __r     record;
begin
    raise notice '';
    raise notice '--- 003: claim by username ---';

    -- Eve: pre-provisioned for p18_aad (email only), individual admin of CDE and FGH
    select u.__user_id from auth.ensure_user_info('p18', 2, 'p18', 'eve@p18.com', 'Eve', 'p18_aad', 'eve@p18.com') u into __eve;
    perform auth.create_user_group_member('p18', 1, 'p18', (select val::int from _p18 where key = 'cde_admins'), __eve
        , (select val::int from _p18 where key = 'cde'));
    perform auth.create_user_group_member('p18', 1, 'p18', (select val::int from _p18 where key = 'fgh_admins'), __eve
        , (select val::int from _p18 where key = 'fgh'));

    select * from pg_temp.p18_login('eve', array['abc']) into __r;
    perform pg_temp.p18_is('Eve claims her pre-provisioned user', __r.__outcome_code || ':' || (__r.__user_id = __eve), 'user_logged_in:true');
    perform pg_temp.p18_is('Eve: ABC (Azure), CDE and FGH (individual admin)', pg_temp.p18_tenants('eve'),
        'p18_abc,p18_cde,p18_fgh / admin: p18_cde,p18_fgh');

    -- Frank: pre-provisioned for p18_aad, someone arrives through p18_google
    select u.__user_id from auth.ensure_user_info('p18', 2, 'p18', 'frank@p18.com', 'Frank', 'p18_aad', 'frank@p18.com') u into __frank;
    select * from pg_temp.p18_login('frank', null, _provider := 'p18_google') into __r;
    perform pg_temp.p18_is('another provider cannot claim (33024)', __r.__outcome_code, 'err_username_already_exists');
    perform pg_temp.p18_is('Frank still has no identity', (select count(*)::text from auth.user_identity where user_id = __frank), '0');

    -- Gina: pre-provisioned without a provider
    select u.__user_id from auth.ensure_user_info('p18', 2, 'p18', 'gina@p18.com', 'Gina') u into __gina;
    select * from pg_temp.p18_login('gina', array[]::text[]) into __r;
    perform pg_temp.p18_is('pre-provisioned without a provider: no claim (33024)', __r.__outcome_code, 'err_username_already_exists');

    -- Hank: has logged in before; a second account with his username cannot take over
    select l.__user_id from pg_temp.p18_login('hank', array[]::text[]) l into __hank;
    select * from pg_temp.p18_login('hank', array[]::text[], _uid := 'uid-other', _oid := 'oid-other') into __r;
    perform pg_temp.p18_is('user with an identity: no claim (33024)', __r.__outcome_code, 'err_username_already_exists');
    perform pg_temp.p18_is('Hank keeps one identity', (select count(*)::text from auth.user_identity where user_id = __hank), '1');
end $$;
