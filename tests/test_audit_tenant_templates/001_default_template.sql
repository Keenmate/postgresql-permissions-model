set search_path = public, const, ext, stage, helpers, internal, unsecure, auth, triggers;

-- ============================================================================
-- The default template reproduces what create_tenant always created
-- ============================================================================
do $$
declare
    __full bigint := pg_temp.tt('full')::bigint;
    __t    int;
begin
    raise notice 'TEST 1: the default template';

    perform pg_temp.tt_is('one default template, no code'
        , (select string_agg(coalesce(t.__code, 'null') || ':' || t.__is_active, ',')
           from auth.get_tenant_templates(__full, 'tt') t where t.__is_default)
        , 'null:true');

    perform pg_temp.tt_is('its groups'
        , (select string_agg((g ->> 'code') || ':' || (g ->> 'title') || ':' || (g -> 'perm_set_codes')::text, ' | ' order by g ->> 'code')
           from auth.get_tenant_templates(__full, 'tt') t
                    cross join jsonb_array_elements(t.__groups) g
           where t.__is_default)
        , 'tenant_admins:Tenant Admins:["tenant_admin"] | tenant_members:Tenant Members:["tenant_member"]');

    perform pg_temp.tt_is('a tenant created without a template looks as before'
        , pg_temp.tt_groups(pg_temp.tt('abc')::int)
        , 'tenant_admins:Tenant Admins:false:true:[tenant_admin] | tenant_members:Tenant Members:false:true:[tenant_member]');
    perform pg_temp.tt_is('its perm sets', pg_temp.tt_perm_sets(pg_temp.tt('abc')::int), 'tenant_admin,tenant_member,tenant_owner');
    perform pg_temp.tt_is('no mappings', pg_temp.tt_mappings(pg_temp.tt('abc')::int), '');

    perform pg_temp.tt_is('the tenant_created notification trigger'
        , (select count(*)::text from pg_trigger where tgname = 'trg_notify_tenant_created' and tgrelid = 'auth.tenant'::regclass), '1');

    -- the default template can be edited
    perform auth.create_tenant_template_group('tt', __full, 'tt'
        , (select t.__tenant_template_id from auth.get_tenant_templates(__full, 'tt') t where t.__is_default)
        , 'Auditors', array['tt_finance']);
    select t.__tenant_id from auth.create_tenant('tt', __full, 'tt', 'TT Default', 'tt_default') t into __t;
    insert into _tt values ('default', __t);
    perform pg_temp.tt_is('an edited default template'
        , pg_temp.tt_groups(__t)
        , 'auditors:Auditors:false:false:[tt_finance] | tenant_admins:Tenant Admins:false:true:[tenant_admin] | tenant_members:Tenant Members:false:true:[tenant_member]');
    perform pg_temp.tt_is('copies the perm sets it needs', pg_temp.tt_perm_sets(__t), 'tenant_admin,tenant_member,tenant_owner,tt_finance');
    perform pg_temp.tt_is('the journal names the template'
        , (select coalesce(j.data_payload ->> 'template_code', 'default') from public.journal j
           where j.event_id = 11001 and j.keys ->> 'tenant' = __t::text)
        , 'default');
end $$;

select pg_temp.tt_expect('the default template can''t be deleted'
    , 'select auth.delete_tenant_template(''tt'', {full}, ''tt'', (select tenant_template_id from auth.tenant_template where code is null))', '34010');
select pg_temp.tt_expect('the default template can''t be disabled'
    , 'select auth.update_tenant_template(''tt'', {full}, ''tt'', (select tenant_template_id from auth.tenant_template where code is null), ''Default'', null, false)', '34010');
select pg_temp.tt_expect('a second default template'
    , 'insert into auth.tenant_template (title) values (''Another default'')', '23505');
