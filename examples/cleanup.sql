/*
 * examples/cleanup.sql — remove all demo data created by examples 01–07
 * =====================================================================
 *
 * Deletes the Twin Peaks demo users (@twinpeaks.com), the API-key technical
 * user, and the demo tenants / groups / permission sets / permissions created
 * by the example scripts — including the groups, assignments and owner that
 * create_tenant auto-seeds inside a new tenant, and the tenant_identity ledger
 * row that otherwise permanently reserves the tenant code.
 *
 * Runs as a single transaction (all-or-nothing). Safe to run repeatedly; run it
 * before re-running any example (the create_* calls are not idempotent).
 *
 * Does NOT touch the shared 'aad' provider (harmless to leave; other examples
 * reuse it).
 */

set search_path = public, const, ext, stage, helpers, internal, unsecure, auth, triggers;

do $$
declare
    __group_titles  text[] := array['Sheriff Department', 'Bookhouse Boys (AAD)', 'Order Desk', 'Order Managers (AAD)'];
    __perm_set_codes text[] := array[helpers.get_code('Order Manager'), helpers.get_code('Reporting')];
    __api_titles    text[] := array['Blue Rose Export'];
    __tenant_codes  text[] := array['great_northern'];
    __api_username  text   := auth.generate_api_key_username('blue-rose-key');
    __user_ids      bigint[];
    __tenant_ids    integer[];
    __group_ids     integer[];
    __perm_set_ids  integer[];
begin
    select coalesce(array_agg(user_id), '{}') into __user_ids
    from auth.user_info
    where email like '%@twinpeaks.com'
       or username like '%@twinpeaks.com'   -- service users store the email under username
       or username = __api_username;

    select coalesce(array_agg(tenant_id), '{}') into __tenant_ids
    from auth.tenant where code = any(__tenant_codes);

    -- demo groups in tenant 1 PLUS every group create_tenant seeded in demo tenants
    select coalesce(array_agg(user_group_id), '{}') into __group_ids
    from auth.user_group
    where (title = any(__group_titles) and tenant_id = 1)
       or tenant_id = any(__tenant_ids);

    select coalesce(array_agg(perm_set_id), '{}') into __perm_set_ids
    from auth.perm_set where code = any(__perm_set_codes) and tenant_id = 1;

    -- Permission assignments (by user, by group, by demo perm set, or by demo tenant)
    delete from auth.permission_assignment
    where user_id = any(__user_ids)
       or user_group_id = any(__group_ids)
       or perm_set_id = any(__perm_set_ids)
       or tenant_id = any(__tenant_ids);

    -- API keys
    delete from auth.api_key where title = any(__api_titles) and tenant_id = 1;

    -- Groups: members, mappings, then the groups themselves
    delete from auth.user_group_member  where user_group_id = any(__group_ids) or user_id = any(__user_ids);
    delete from auth.user_group_mapping where user_group_id = any(__group_ids);
    delete from auth.user_group         where user_group_id = any(__group_ids);

    -- Tenant-1 demo permission sets (tenant-scoped perm sets cascade on tenant delete)
    delete from auth.perm_set_perm where perm_set_id = any(__perm_set_ids);
    delete from auth.perm_set      where perm_set_id = any(__perm_set_ids);

    -- Demo permissions
    delete from auth.permission
    where full_code::text like 'business%' or full_code::text like 'reports%';

    -- Per-user dependents (none of these FKs cascade), then per-tenant dependents
    delete from auth.user_permission_cache  where user_id = any(__user_ids) or tenant_id = any(__tenant_ids);
    delete from auth.token                  where user_id = any(__user_ids);
    delete from auth.user_event             where target_user_id = any(__user_ids);
    delete from auth.user_identity          where user_id = any(__user_ids);
    delete from auth.user_data              where user_id = any(__user_ids);
    delete from auth.user_tenant_preference where user_id = any(__user_ids) or tenant_id = any(__tenant_ids);
    delete from auth.owner                  where user_id = any(__user_ids) or tenant_id = any(__tenant_ids);

    -- Audit journal rows scoped to the demo tenants (create_tenant writes these)
    delete from public.journal where tenant_id = any(__tenant_ids);

    -- Users, then tenants, then release the reserved tenant codes
    delete from auth.user_info      where user_id = any(__user_ids);
    delete from auth.tenant         where tenant_id = any(__tenant_ids);
    delete from auth.tenant_identity where code = any(__tenant_codes);

    raise notice 'cleanup: removed % users, % groups, % perm sets, % tenants',
        coalesce(array_length(__user_ids, 1), 0), coalesce(array_length(__group_ids, 1), 0),
        coalesce(array_length(__perm_set_ids, 1), 0), coalesce(array_length(__tenant_ids, 1), 0);
end $$;
