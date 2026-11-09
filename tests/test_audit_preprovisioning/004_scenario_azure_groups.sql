set search_path = public, const, ext, stage, helpers, internal, unsecure, auth, triggers;

-- ============================================================================
-- Membership follows the provider groups (several logins in one transaction)
-- ============================================================================
do $$
begin
    raise notice '';
    raise notice '--- 004: tenants follow the Azure groups ---';

    perform pg_temp.p18_login('alice', array['abc']);
    perform pg_temp.p18_login('bob',   array['fgh']);
    perform pg_temp.p18_login('carol', array['fghadmins']);
    perform pg_temp.p18_login('nora',  array[]::text[]);

    perform pg_temp.p18_is('Alice (Azure ABC): ABC and FGH', pg_temp.p18_tenants('alice'), 'p18_abc,p18_fgh / admin: -');
    perform pg_temp.p18_is('Bob (Azure FGH): FGH',           pg_temp.p18_tenants('bob'),   'p18_fgh / admin: -');
    perform pg_temp.p18_is('Carol (Azure FGHAdmins): FGH admin', pg_temp.p18_tenants('carol'), 'p18_fgh / admin: p18_fgh');
    perform pg_temp.p18_is('Nora (no Azure groups): no tenants', pg_temp.p18_tenants('nora'), '- / admin: -');
    perform pg_temp.p18_is('none of them is in tenant 1',
        (select count(*)::text from auth.tenant_members tm inner join auth.user_info ui on ui.user_id = tm.user_id
         where tm.tenant_id = 1 and ui.username like '%@p18.com'), '0');

    -- Alice leaves Azure ABC
    perform pg_temp.p18_login('alice', array[]::text[]);
    perform pg_temp.p18_is('Alice after leaving Azure ABC: no tenants', pg_temp.p18_tenants('alice'), '- / admin: -');
end $$;
