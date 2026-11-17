set search_path = public, const, ext, stage, helpers, internal, unsecure, auth, triggers;

-- ============================================================================
-- Who may manage templates (tenant 1)
-- ============================================================================
do $$
begin
    raise notice 'TEST 2: who manages templates';
end $$;

select pg_temp.tt_expect('a tenant admin creates a template'
    , 'select * from auth.create_tenant_template(''tt'', {abc_admin}, ''tt'', ''X'')', '32001');
select pg_temp.tt_expect('a tenant admin reads templates'
    , 'select * from auth.get_tenant_templates({abc_admin}, ''tt'')', '32001');
select pg_temp.tt_expect('the tenant creator reads templates'
    , 'select * from auth.get_tenant_templates({creator}, ''tt'')', '32001');

-- ============================================================================
-- A named template: "Granular"
--   {tenant.code} Admins : tenant_admin, Azure group {data.admin_group.id}
--   Finance              : TT Finance, the global rule tt_fin
--   Readers              : tenant_member, Azure role reader (external)
-- ============================================================================
do $$
declare
    __full bigint := pg_temp.tt('full')::bigint;
    __tpl  int;
    __g    int;
begin
    raise notice 'TEST 3: building a named template';

    select t.__tenant_template_id from auth.create_tenant_template('tt', __full, 'tt', 'Granular', _description := 'admins from Azure') t into __tpl;
    insert into _tt values ('tpl', __tpl);

    select g.__tenant_template_group_id from auth.create_tenant_template_group('tt', __full, 'tt', __tpl
        , '{tenant.code} Admins', array['tenant_admin']) g into __g;
    insert into _tt values ('tg_admins', __g);
    perform auth.create_tenant_template_group_mapping('tt', __full, 'tt', __g, 'tt_aad'
        , _mapped_object_id := '{data.admin_group.id}', _mapped_object_name := '{data.admin_group.name}');

    select g.__tenant_template_group_id from auth.create_tenant_template_group('tt', __full, 'tt', __tpl
        , 'Finance', array['tt_finance']) g into __g;
    insert into _tt values ('tg_finance', __g);
    perform auth.create_tenant_template_group_mapping('tt', __full, 'tt', __g, _rule_id := pg_temp.tt('rule_fin')::int);

    select g.__tenant_template_group_id from auth.create_tenant_template_group('tt', __full, 'tt', __tpl
        , 'Readers', array['tenant_member'], _is_external := true) g into __g;
    insert into _tt values ('tg_readers', __g);
    perform auth.create_tenant_template_group_mapping('tt', __full, 'tt', __g, 'tt_aad', _mapped_role := 'Reader');

    perform pg_temp.tt_is('get_tenant_templates shows it'
        , (select t.__code || ':' || t.__title || ':' || t.__is_default || ':' || jsonb_array_length(t.__groups)
               || ':' || (select sum(jsonb_array_length(g -> 'mappings')) from jsonb_array_elements(t.__groups) g)
           from auth.get_tenant_templates(__full, 'tt') t where t.__tenant_template_id = __tpl)
        , 'granular:Granular:false:3:3');
    perform pg_temp.tt_is('the creation is journaled'
        , (select count(*)::text from public.journal j where j.event_id = 11013 and j.keys ->> 'tenant_template' = __tpl::text), '1');
    perform pg_temp.tt_is('system_admin reads templates'
        , (select count(*)::text from auth.get_tenant_templates(pg_temp.tt('sys')::bigint, 'tt') t where t.__tenant_template_id = __tpl), '1');
end $$;

-- ============================================================================
-- Validation when saving
-- ============================================================================
do $$
begin
    raise notice 'TEST 4: validation';
end $$;

select pg_temp.tt_expect('the code is taken'
    , 'select * from auth.create_tenant_template(''tt'', {full}, ''tt'', ''Granular'')', '34013');
select pg_temp.tt_expect('an unknown perm set'
    , 'select * from auth.create_tenant_template_group(''tt'', {full}, ''tt'', {tpl}, ''X'', array[''nope''])', '32004');
select pg_temp.tt_expect('an unknown placeholder'
    , 'select * from auth.create_tenant_template_group(''tt'', {full}, ''tt'', {tpl}, ''{tenant.title} X'')', '34012');
select pg_temp.tt_expect('a placeholder with an empty path'
    , 'select * from auth.create_tenant_template_group_mapping(''tt'', {full}, ''tt'', {tg_admins}, ''tt_aad'', _mapped_object_id := ''{data.}'')', '34012');
select pg_temp.tt_expect('a mapping with neither provider nor rule'
    , 'select * from auth.create_tenant_template_group_mapping(''tt'', {full}, ''tt'', {tg_admins})', '34015');
select pg_temp.tt_expect('a mapping with both provider and rule'
    , 'select * from auth.create_tenant_template_group_mapping(''tt'', {full}, ''tt'', {tg_admins}, ''tt_aad'', ''x'', _rule_id := {rule_fin})', '34015');
select pg_temp.tt_expect('a provider mapping without object or role'
    , 'select * from auth.create_tenant_template_group_mapping(''tt'', {full}, ''tt'', {tg_admins}, ''tt_aad'')', '31004');
select pg_temp.tt_expect('a provider without group mapping'
    , 'select * from auth.create_tenant_template_group_mapping(''tt'', {full}, ''tt'', {tg_admins}, ''tt_nomap'', ''x'')', '33016');
select pg_temp.tt_expect('a tenant rule (not global)'
    , 'select * from auth.create_tenant_template_group_mapping(''tt'', {full}, ''tt'', {tg_admins}, _rule_id := {rule_local})', '40002');
select pg_temp.tt_expect('an unknown template'
    , 'select * from auth.create_tenant_template_group(''tt'', {full}, ''tt'', -1, ''X'')', '34009');
select pg_temp.tt_expect('an unknown template group'
    , 'select * from auth.create_tenant_template_group_mapping(''tt'', {full}, ''tt'', -1, ''tt_aad'', ''x'')', '34014');
select pg_temp.tt_expect('the global rule is used by a template'
    , 'select auth.delete_rule(''tt'', {full}, ''tt'', {rule_fin}, 1)', '40003');

-- D-19: a template hands out its perm sets in every new tenant
select pg_temp.tt_expect('tt_lim puts tenant_admin into a template'
    , 'select * from auth.create_tenant_template_group(''tt'', {lim}, ''tt'', {tpl}, ''X'', array[''tenant_admin''])', '32010');
select pg_temp.tt_expect('tt_lim puts tenant_admin into an existing group'
    , 'select auth.update_tenant_template_group(''tt'', {lim}, ''tt'', {tg_finance}, ''Finance'', array[''tenant_admin''])', '32010');

do $$
declare
    __lim bigint := pg_temp.tt('lim')::bigint;
    __tpl int;
begin
    select t.__tenant_template_id from auth.create_tenant_template('tt', __lim, 'tt', 'Bare') t into __tpl;
    perform auth.create_tenant_template_group('tt', __lim, 'tt', __tpl, 'Everyone');
    perform pg_temp.tt_is('tt_lim builds a template without perm sets'
        , (select jsonb_array_length(t.__groups)::text from auth.get_tenant_templates(__lim, 'tt') t where t.__tenant_template_id = __tpl), '1');
end $$;

-- ============================================================================
-- Creating a tenant from the template
-- ============================================================================
do $$
declare
    __creator bigint := pg_temp.tt('creator')::bigint;
    __t       int;
    __r       record;
    __kate    bigint;
begin
    raise notice 'TEST 5: create_tenant from a named template';

    select t.__tenant_id from auth.create_tenant('tt', __creator, 'tt', 'TT X', 'tt_x'
        , _template_code := 'granular'
        , _extra_data := '{"admin_group": {"id": "OID-123", "name": "X Admins"}}') t into __t;
    insert into _tt values ('x', __t);

    perform pg_temp.tt_is('the groups'
        , pg_temp.tt_groups(__t)
        , 'finance:Finance:false:false:[tt_finance] | readers:Readers:true:false:[tenant_member] | tt_x_admins:tt_x Admins:false:false:[tenant_admin]');
    perform pg_temp.tt_is('the perm sets (tenant_owner always)', pg_temp.tt_perm_sets(__t), 'tenant_admin,tenant_member,tenant_owner,tt_finance');
    perform pg_temp.tt_is('the mappings, placeholders filled in'
        , pg_temp.tt_mappings(__t)
        , 'finance:-:-:-:-:tt_fin | readers:tt_aad:-:-:reader:- | tt_x_admins:tt_aad:oid-123:X Admins:-:-');
    perform pg_temp.tt_is('the journal names the template'
        , (select (j.data_payload ->> 'template_code') || ':' || (j.data_payload -> 'extra_data' -> 'admin_group' ->> 'id')
           from public.journal j where j.event_id = 11001 and j.keys ->> 'tenant' = __t::text)
        , 'granular:OID-123');

    -- kate signs in with the Azure admin group and the finance group
    select * from auth.ensure_user_from_provider('tt', 3, 'tt', 'tt_aad', 'uid-kate', 'oid-kate'
        , 'tt_kate', 'Kate', 'kate@tt.com', null) into __r;
    __kate := __r.__user_id;
    perform auth.ensure_groups_and_permissions('tt', 3, 'tt', __kate, 'tt_aad', array['oid-123', 'tt-finance'], null);
    perform pg_temp.tt_is('the Azure admin group makes kate an admin of X'
        , auth.has_permission(__kate, 'tt', 'tenants.update_tenant', __t, _throw_err := false)::text, 'true');
    perform pg_temp.tt_is('the Azure group and the global rule make kate a member'
        , (select string_agg(g.code, ',' order by g.code) from auth.user_group_member m
               inner join auth.user_group g on g.user_group_id = m.user_group_id
           where m.user_id = __kate and g.tenant_id = __t)
        , 'finance,tt_x_admins');
end $$;

select pg_temp.tt_expect('a missing value fails create_tenant'
    , 'select * from auth.create_tenant(''tt'', {creator}, ''tt'', ''TT Y'', ''tt_y'', _template_code := ''granular'', _extra_data := ''{"admin_group": {"id": "OID-9"}}'')', '34011');
select pg_temp.tt_expect('no extra data at all'
    , 'select * from auth.create_tenant(''tt'', {creator}, ''tt'', ''TT Y'', ''tt_y'', _template_code := ''granular'')', '34011');
select pg_temp.tt_expect('an object is no value'
    , 'select * from auth.create_tenant(''tt'', {creator}, ''tt'', ''TT Y'', ''tt_y'', _template_code := ''granular'', _extra_data := ''{"admin_group": {"id": {"a": 1}, "name": "Y"}}'')', '34011');
select pg_temp.tt_expect('an unknown template code'
    , 'select * from auth.create_tenant(''tt'', {creator}, ''tt'', ''TT Y'', ''tt_y'', _template_code := ''nope'')', '34009');

do $$
declare
    __full bigint := pg_temp.tt('full')::bigint;
begin
    perform pg_temp.tt_is('nothing of tt_y was left behind'
        , (select count(*)::text from auth.tenant_identity where code = 'tt_y'), '0');

    raise notice 'TEST 6: editing and deleting';
    perform auth.update_tenant_template('tt', __full, 'tt', pg_temp.tt('tpl')::int, 'Granular', 'off for now', false);
end $$;

select pg_temp.tt_expect('an inactive template'
    , 'select * from auth.create_tenant(''tt'', {creator}, ''tt'', ''TT Y'', ''tt_y'', _template_code := ''granular'', _extra_data := ''{"admin_group": {"id": "a", "name": "b"}}'')', '34009');

do $$
declare
    __full bigint := pg_temp.tt('full')::bigint;
    __tpl  int := pg_temp.tt('tpl')::int;
begin
    perform auth.update_tenant_template('tt', __full, 'tt', __tpl, 'Granular', null, true);
    perform auth.update_tenant_template_group('tt', __full, 'tt', pg_temp.tt('tg_readers')::int, 'Viewers', array['tt_finance'], _is_external := false);
    perform auth.delete_tenant_template_group_mapping('tt', __full, 'tt'
        , (select m.tenant_template_group_mapping_id from auth.tenant_template_group_mapping m
           where m.tenant_template_group_id = pg_temp.tt('tg_readers')::int));
    perform auth.delete_tenant_template_group('tt', __full, 'tt', pg_temp.tt('tg_admins')::int);
    perform auth.delete_tenant_template_group('tt', __full, 'tt', pg_temp.tt('tg_finance')::int);

    perform pg_temp.tt_is('the edited template'
        , (select string_agg((g ->> 'code') || ':' || (g ->> 'title') || ':' || (g ->> 'is_external') || ':' || (g -> 'perm_set_codes')::text
                                 || ':' || jsonb_array_length(g -> 'mappings'), ' | ')
           from auth.get_tenant_templates(__full, 'tt') t cross join jsonb_array_elements(t.__groups) g
           where t.__tenant_template_id = __tpl)
        , 'viewers:Viewers:false:["tt_finance"]:0');
    perform pg_temp.tt_is('the edits are journaled'
        , (select count(*)::text from public.journal j where j.event_id = 11014 and j.keys ->> 'tenant_template' = __tpl::text), '12');

    -- tenant X's own mapping uses the rule as well
    delete from auth.user_group_mapping where rule_id = pg_temp.tt('rule_fin')::int;
    perform auth.delete_rule('tt', __full, 'tt', pg_temp.tt('rule_fin')::int, 1);
    perform pg_temp.tt_is('the rule is free once the template no longer uses it'
        , (select count(*)::text from auth.rule where rule_id = pg_temp.tt('rule_fin')::int), '0');

    perform auth.delete_tenant_template('tt', __full, 'tt', __tpl);
    perform pg_temp.tt_is('the template is gone, its groups too'
        , (select count(*)::text from auth.tenant_template_group where tenant_template_id = __tpl), '0');
    perform pg_temp.tt_is('tenant X keeps everything'
        , pg_temp.tt_groups(pg_temp.tt('x')::int)
        , 'finance:Finance:false:false:[tt_finance] | readers:Readers:true:false:[tenant_member] | tt_x_admins:tt_x Admins:false:false:[tenant_admin]');
end $$;

select pg_temp.tt_expect('a deleted template'
    , 'select * from auth.create_tenant(''tt'', {creator}, ''tt'', ''TT Y'', ''tt_y'', _template_code := ''granular'')', '34009');

do $$
begin
    raise notice '';
    raise notice '=================================================================';
    raise notice 'Audit D-13: tenant templates - Finished';
    raise notice '=================================================================';
end $$;
