set search_path = public, const, ext, stage, helpers, internal, unsecure, auth, triggers;

-- ============================================================================
-- Shared rules: who may create, edit, delete and read them
-- ============================================================================
do $$
begin
    raise notice 'TEST 11: rule permissions';
end $$;

select pg_temp.ru_expect('a user without rules permissions'
    , 'select * from auth.create_rule(''ru'', {bob}, ''ru'', ''x'', ''{"mode": "always"}'', _tenant_id := {fgh})', '32001');
select pg_temp.ru_expect('a tenant admin creating a global rule'
    , 'select * from auth.create_rule(''ru'', {fgh_admin}, ''ru'', ''x'', ''{"mode": "always"}'', _is_global := true, _tenant_id := 1)', '32001');
select pg_temp.ru_expect('a tenant admin creating a global rule from their tenant'
    , 'select * from auth.create_rule(''ru'', {fgh_admin}, ''ru'', ''x'', ''{"mode": "always"}'', _is_global := true, _tenant_id := {fgh})', '32001');
select pg_temp.ru_expect('system_admin creating a global rule (full_admin only)'
    , 'select * from auth.create_rule(''ru'', {sys}, ''ru'', ''x'', ''{"mode": "always"}'', _is_global := true, _tenant_id := 1)', '32001');
select pg_temp.ru_expect('a tenant admin editing a global rule'
    , 'select * from auth.update_rule(''ru'', {fgh_admin}, ''ru'', {rule_global}, ''x'', ''{"mode": "always"}'', _tenant_id := {fgh})', '32001');
select pg_temp.ru_expect('a tenant admin deleting a global rule'
    , 'select auth.delete_rule(''ru'', {fgh_admin}, ''ru'', {rule_global}, _tenant_id := {fgh})', '32001');
select pg_temp.ru_expect('CDE admin editing an FGH rule from CDE'
    , 'select * from auth.update_rule(''ru'', {cde_admin}, ''ru'', {rule_staff}, ''x'', ''{"mode": "always"}'', _tenant_id := {cde})', '40002');
select pg_temp.ru_expect('CDE admin editing an FGH rule as FGH'
    , 'select * from auth.update_rule(''ru'', {cde_admin}, ''ru'', {rule_staff}, ''x'', ''{"mode": "always"}'', _tenant_id := {fgh})', '32001');
select pg_temp.ru_expect('CDE admin deleting an FGH rule from CDE'
    , 'select auth.delete_rule(''ru'', {cde_admin}, ''ru'', {rule_staff}, _tenant_id := {cde})', '40002');
select pg_temp.ru_expect('an invalid edit'
    , 'select * from auth.update_rule(''ru'', {fgh_admin}, ''ru'', {rule_staff}, ''x'', ''{"mode": "conditional"}'', _tenant_id := {fgh})', '40001');
select pg_temp.ru_expect('a rule in use cannot be deleted'
    , 'select auth.delete_rule(''ru'', {fgh_admin}, ''ru'', {rule_staff}, _tenant_id := {fgh})', '40003');
select pg_temp.ru_expect('a code used twice in the tenant'
    , 'select * from auth.create_rule(''ru'', {fgh_admin}, ''ru'', ''FGH staff'', ''{"mode": "always"}'', _tenant_id := {fgh})', '40004');

do $$
declare
    __fgh   int := pg_temp.ru('fgh')::int;
    __admin bigint := pg_temp.ru('fgh_admin')::bigint;
    __full  bigint := pg_temp.ru('full')::bigint;
    __id    int;
    __codes text;
    __j     record;
begin
    raise notice 'TEST 12: allowed changes';

    select r.__rule_id from auth.create_rule('ru', __admin, 'ru', 'FGH temp', '{"mode": "never"}', 'temp rule', _tenant_id := __fgh) r into __id;
    perform pg_temp.ru_is('created with code and description'
        , (select code || ' ' || description || ' ' || tenant_id::text || ' ' || is_global::text from auth.rule where rule_id = __id)
        , 'fgh_temp temp rule ' || __fgh || ' false');
    perform auth.delete_rule('ru', __admin, 'ru', __id, _tenant_id := __fgh);
    perform pg_temp.ru_is('an unused tenant rule can be deleted', exists(select from auth.rule where rule_id = __id)::text, 'false');

    perform auth.update_rule('ru', __full, 'ru', pg_temp.ru('rule_global')::int, 'Platform staff'
        , '{"mode": "conditional", "conditions": [{"field": "email_domain", "op": "is_one_of", "values": ["platform.com", "platform.cz"]}]}'
        , 'all platform staff', _tenant_id := 1);
    perform pg_temp.ru_is('full_admin edits the global rule'
        , (select rule -> 'conditions' -> 0 ->> 'op' from auth.rule where rule_id = pg_temp.ru('rule_global')::int), 'is_one_of');

    raise notice 'TEST 13: the journal keeps the old and the new rule';
    select j.data_payload
    from public.journal j
    where j.event_id = 23002
      and j.keys ->> 'rule' = pg_temp.ru('rule_staff')
    order by j.journal_id desc
    limit 1
    into __j;
    perform pg_temp.ru_is('old rule', __j.data_payload -> 'old_rule' -> 'conditions' -> 0 -> 'values' ->> 0, 'fgh.com');
    perform pg_temp.ru_is('new rule', __j.data_payload -> 'new_rule' -> 'conditions' -> 0 -> 'values' ->> 0, 'fgh.cz');

    raise notice 'TEST 14: get_rules lists the tenant''s rules and the global ones';
    select string_agg(r.__code || ':' || r.__is_global::text || ':' || r.__mapping_count::text, ',' order by r.__code)
    from auth.get_rules(__admin, 'ru', __fgh) r
    where r.__code in ('fgh_staff', 'cde_staff', 'platform_staff')
    into __codes;
    perform pg_temp.ru_is('FGH sees its rule and the global one, not CDE''s', __codes, 'fgh_staff:false:1,platform_staff:true:0');
end $$;

select pg_temp.ru_expect('get_rules needs rules.read_rules'
    , 'select * from auth.get_rules({bob}, ''ru'', {fgh})', '32001');

do $$
begin
    raise notice 'TEST 15: who holds the rules permissions';
end $$;

select pg_temp.ru_is(ps.label
    , (select string_agg(p.full_code::text, ',' order by p.full_code::text)
       from auth.perm_set s
                inner join auth.perm_set_perm psp on psp.perm_set_id = s.perm_set_id
                inner join auth.permission p on p.permission_id = psp.permission_id
       where s.tenant_id = ps.tenant_id and s.code = ps.code and p.full_code <@ 'rules'::ext.ltree)
    , ps.expected)
from (values
    ('tenant_admin in FGH', pg_temp.ru('fgh')::int, 'tenant_admin', 'rules.create_rule,rules.delete_rule,rules.read_rules,rules.update_rule'),
    ('tenant_owner in FGH', pg_temp.ru('fgh')::int, 'tenant_owner', 'rules.create_rule,rules.delete_rule,rules.read_rules,rules.update_rule'),
    ('system_admin in 1', 1, 'system_admin', 'rules.create_rule,rules.delete_rule,rules.read_rules,rules.update_rule'),
    ('full_admin in 1', 1, 'full_admin', 'rules.create_rule,rules.delete_rule,rules.manage_global_rules,rules.read_rules,rules.update_rule')
) ps(label, tenant_id, code, expected);
