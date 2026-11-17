set search_path = public, const, ext, stage, helpers, internal, unsecure, auth, triggers;

-- ============================================================================
-- Rule mappings on groups
--   FGH Admins : ordinary mapping to Azure "fghadmins"
--                + inline rule: provider_groups includes FGH and Finance Leads
--   FGH Members: shared tenant rule "FGH staff": email_domain is fgh.com
-- ============================================================================
do $$
declare
    __fgh     int := pg_temp.ru('fgh')::int;
    __admin   bigint := pg_temp.ru('fgh_admin')::bigint;
    __rule_id int;
    __m       int;
begin
    raise notice 'TEST 5: the tenant admin creates rule mappings';

    perform auth.create_user_group_mapping('ru', __admin, 'ru', pg_temp.ru('g_admins')::int, 'ru_aad', 'fghadmins'
        , 'Azure FGH Admins', _tenant_id := __fgh);

    select m.__user_group_mapping_id
    from auth.create_user_group_rule_mapping('ru', __admin, 'ru', pg_temp.ru('g_admins')::int
        , _rule := '{"mode": "conditional", "combinator": "and", "conditions": [
                      {"field": "provider_groups", "op": "includes", "values": ["FGH", "Finance Leads"]}]}'
        , _tenant_id := __fgh) m
    into __m;
    insert into _ru values ('m_admins_rule', __m);

    select r.__rule_id
    from auth.create_rule('ru', __admin, 'ru', 'FGH staff'
        , '{"mode": "conditional", "conditions": [{"field": "email_domain", "op": "is", "values": ["fgh.com"]}]}'
        , _tenant_id := __fgh) r
    into __rule_id;
    insert into _ru values ('rule_staff', __rule_id);

    select m.__user_group_mapping_id
    from auth.create_user_group_rule_mapping('ru', __admin, 'ru', pg_temp.ru('g_members')::int
        , _rule_id := __rule_id, _tenant_id := __fgh) m
    into __m;
    insert into _ru values ('m_members_rule', __m);

    perform pg_temp.ru_is('get_user_group_mappings shows the inline rule'
        , (select (m.__rule -> 'conditions' -> 0 ->> 'op') from auth.get_user_group_mappings('ru', __admin, 'ru'
            , pg_temp.ru('g_admins')::int, __fgh) m where m.__user_group_mapping_id = pg_temp.ru('m_admins_rule')::int)
        , 'includes');
    perform pg_temp.ru_is('get_user_group_mappings shows the shared rule'
        , (select m.__rule_id::text || ' ' || (m.__rule -> 'conditions' -> 0 ->> 'field')
           from auth.get_user_group_mappings('ru', __admin, 'ru', pg_temp.ru('g_members')::int, __fgh) m)
        , __rule_id::text || ' email_domain');
end $$;

do $$
declare
    __anna bigint;
    __bob  bigint;
    __carl bigint;
    __dan  bigint;
begin
    raise notice 'TEST 6: login adds the users the rules match';

    __anna := pg_temp.ru_login('anna', 'ru_aad', array['FGH', 'Finance Leads']);
    __bob  := pg_temp.ru_login('bob', 'ru_aad', array['FGH']);
    __carl := pg_temp.ru_login('carl', 'ru_pwd', null);
    __dan  := pg_temp.ru_login('dan', 'ru_aad', array['fghadmins'], _email := 'dan@abc.com');
    insert into _ru values ('anna', __anna), ('bob', __bob), ('carl', __carl), ('dan', __dan);

    perform pg_temp.ru_is('anna: both rules', pg_temp.ru_groups(__anna), 'fgh_admins,fgh_members');
    perform pg_temp.ru_is('bob: only the email rule', pg_temp.ru_groups(__bob), 'fgh_members');
    perform pg_temp.ru_is('carl (provider without group mapping): the email rule', pg_temp.ru_groups(__carl), 'fgh_members');
    perform pg_temp.ru_is('dan: the ordinary mapping only', pg_temp.ru_groups(__dan), 'fgh_admins');

    perform pg_temp.ru_is('rule membership: type rule, the rule mapping'
        , (select m.member_type_code || ' ' || (m.mapping_id = pg_temp.ru('m_admins_rule')::int)::text
           from auth.user_group_member m where m.user_id = __anna and m.user_group_id = pg_temp.ru('g_admins')::int)
        , 'rule true');

    perform pg_temp.ru_is('anna holds tenant_admin permissions in FGH'
        , auth.has_permission(__anna, 'ru', 'tenants.update_tenant', pg_temp.ru('fgh')::int, _throw_err := false)::text, 'true');
    perform pg_temp.ru_is('carl is a member of FGH'
        , exists(select from auth.tenant_memberships where tenant_id = pg_temp.ru('fgh')::int and user_id = __carl)::text, 'true');
    perform pg_temp.ru_is('carl gets tenant_member groups in FGH'
        , (select array_to_string(p.__groups, ',') from unsecure.recalculate_user_permissions('ru', __carl, pg_temp.ru('fgh')::int) p)
        , 'fgh_members');
end $$;

do $$
declare
    __anna bigint := pg_temp.ru('anna')::bigint;
    __bob  bigint := pg_temp.ru('bob')::bigint;
    __carl bigint := pg_temp.ru('carl')::bigint;
begin
    raise notice 'TEST 7: users who stop matching are removed';

    perform pg_temp.ru_login('anna', 'ru_aad', array['FGH']);
    perform pg_temp.ru_is('anna left Finance Leads: admins gone', pg_temp.ru_groups(__anna), 'fgh_members');
    perform pg_temp.ru_is('anna lost tenant_admin permissions'
        , auth.has_permission(__anna, 'ru', 'tenants.update_tenant', pg_temp.ru('fgh')::int, _throw_err := false)::text, 'false');

    -- the shared rule changes; the members follow at their next rebuild
    perform auth.update_rule('ru', pg_temp.ru('fgh_admin')::bigint, 'ru', pg_temp.ru('rule_staff')::int, 'FGH staff'
        , '{"mode": "conditional", "conditions": [{"field": "email_domain", "op": "is", "values": ["fgh.cz"]}]}'
        , _tenant_id := pg_temp.ru('fgh')::int);

    perform unsecure.recalculate_user_groups('ru', __bob, 'ru_aad');
    perform unsecure.recalculate_user_groups('ru', __carl, 'ru_pwd');
    perform pg_temp.ru_is('bob no longer matches the edited rule', pg_temp.ru_groups(__bob), '');
    perform pg_temp.ru_is('carl no longer matches the edited rule', pg_temp.ru_groups(__carl), '');
    perform pg_temp.ru_is('carl is no longer a member of FGH'
        , exists(select from auth.tenant_memberships where tenant_id = pg_temp.ru('fgh')::int and user_id = __carl)::text, 'false');
end $$;

do $$
declare
    __fgh   int := pg_temp.ru('fgh')::int;
    __cde_rule int;
    __global   int;
    __m        int;
begin
    raise notice 'TEST 8: rule mapping errors';

    select r.__rule_id from auth.create_rule('ru', pg_temp.ru('cde_admin')::bigint, 'ru', 'CDE staff'
        , '{"mode": "always"}', _tenant_id := pg_temp.ru('cde')::int) r into __cde_rule;
    insert into _ru values ('rule_cde', __cde_rule);

    select r.__rule_id from auth.create_rule('ru', pg_temp.ru('full')::bigint, 'ru', 'Platform staff'
        , '{"mode": "conditional", "conditions": [{"field": "email_domain", "op": "is", "values": ["platform.com"]}]}'
        , _is_global := true, _tenant_id := 1) r into __global;
    insert into _ru values ('rule_global', __global);
end $$;

select pg_temp.ru_expect('a synced group takes no rule mapping'
    , 'select * from auth.create_user_group_rule_mapping(''ru'', {fgh_admin}, ''ru'', {g_synced}, _rule := ''{"mode": "always"}'', _tenant_id := {fgh})', '33026');
select pg_temp.ru_expect('a rule of another tenant'
    , 'select * from auth.create_user_group_rule_mapping(''ru'', {fgh_admin}, ''ru'', {g_members}, _rule_id := {rule_cde}, _tenant_id := {fgh})', '40002');
select pg_temp.ru_expect('both a rule and a rule id'
    , 'select * from auth.create_user_group_rule_mapping(''ru'', {fgh_admin}, ''ru'', {g_members}, _rule := ''{"mode": "always"}'', _rule_id := {rule_staff}, _tenant_id := {fgh})', '40001');
select pg_temp.ru_expect('neither a rule nor a rule id'
    , 'select * from auth.create_user_group_rule_mapping(''ru'', {fgh_admin}, ''ru'', {g_members}, _tenant_id := {fgh})', '40001');
select pg_temp.ru_expect('an invalid inline rule'
    , 'select * from auth.create_user_group_rule_mapping(''ru'', {fgh_admin}, ''ru'', {g_members}, _rule := ''{"mode": "conditional"}'', _tenant_id := {fgh})', '40001');
select pg_temp.ru_expect('CDE admin on an FGH group'
    , 'select * from auth.create_user_group_rule_mapping(''ru'', {cde_admin}, ''ru'', {g_members}, _rule := ''{"mode": "always"}'', _tenant_id := {cde})', '33011');
select pg_temp.ru_expect('CDE admin with FGH as tenant'
    , 'select * from auth.create_user_group_rule_mapping(''ru'', {cde_admin}, ''ru'', {g_members}, _rule := ''{"mode": "always"}'', _tenant_id := {fgh})', '32001');

do $$
declare
    __fgh int := pg_temp.ru('fgh')::int;
    __m   int;
    __pat bigint;
begin
    raise notice 'TEST 9: a global rule can be used in a tenant';

    select m.__user_group_mapping_id
    from auth.create_user_group_rule_mapping('ru', pg_temp.ru('fgh_admin')::bigint, 'ru', pg_temp.ru('g_admins')::int
        , _rule_id := pg_temp.ru('rule_global')::int, _tenant_id := __fgh) m
    into __m;

    __pat := pg_temp.ru_login('pat', 'ru_pwd', null, _email := 'pat@platform.com');
    perform pg_temp.ru_is('pat matches the global rule', pg_temp.ru_groups(__pat), 'fgh_admins');

    raise notice 'TEST 10: deleting the rule mapping removes its members';
    perform auth.delete_user_group_mapping('ru', pg_temp.ru('fgh_admin')::bigint, 'ru', __m, __fgh);
    perform pg_temp.ru_is('pat is gone', pg_temp.ru_groups(__pat), '');
    perform pg_temp.ru_login('pat', 'ru_pwd', null, _email := 'pat@platform.com');
    perform pg_temp.ru_is('pat stays out after the next login', pg_temp.ru_groups(__pat), '');
end $$;
