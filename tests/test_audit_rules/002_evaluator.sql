set search_path = public, const, ext, stage, helpers, internal, unsecure, auth, triggers;

-- ============================================================================
-- The evaluator, against a user who signed in through ru_aad:
--   email Eva.Novak@FGH.com, username ru_eva,
--   provider groups FGH, Finance Leads; claims {country CZ, address {city Brno}, tags [a, B]}
-- ============================================================================
do $$
declare
    __eva bigint;
begin
    raise notice 'TEST 3: the evaluator';
    __eva := pg_temp.ru_login('eva', 'ru_aad', array['FGH', 'Finance Leads']
        , '{"country": "CZ", "address": {"city": "Brno"}, "tags": ["a", "B"]}', 'Eva.Novak@FGH.com');
    insert into _ru values ('eva', __eva);
end $$;

select pg_temp.ru_is(label
    , unsecure.evaluate_rule(rule::jsonb, unsecure.get_rule_subject(pg_temp.ru('eva')::bigint, 'ru_aad'))::text
    , expected)
from (values
    ('always', '{"mode": "always"}', 'true'),
    ('never', '{"mode": "never"}', 'false'),
    ('null rule never matches', null, 'false'),
    ('email is (case-insensitive)', '{"mode": "conditional", "conditions": [{"field": "email", "op": "is", "values": ["eva.novak@fgh.com"]}]}', 'true'),
    ('email is_not', '{"mode": "conditional", "conditions": [{"field": "email", "op": "is_not", "values": ["eva.novak@fgh.com"]}]}', 'false'),
    ('email_domain is_one_of', '{"mode": "conditional", "conditions": [{"field": "email_domain", "op": "is_one_of", "values": ["abc.com", "FGH.com"]}]}', 'true'),
    ('email_domain is_not_one_of', '{"mode": "conditional", "conditions": [{"field": "email_domain", "op": "is_not_one_of", "values": ["abc.com", "cde.com"]}]}', 'true'),
    ('email ends_with', '{"mode": "conditional", "conditions": [{"field": "email", "op": "ends_with", "values": ["@abc.com", "@fgh.com"]}]}', 'true'),
    ('email ends_with no match', '{"mode": "conditional", "conditions": [{"field": "email", "op": "ends_with", "values": ["@fgh.cz"]}]}', 'false'),
    ('username regex', '{"mode": "conditional", "conditions": [{"field": "username", "op": "regex", "values": ["^RU_E"]}]}', 'true'),
    ('provider_code is', '{"mode": "conditional", "conditions": [{"field": "provider_code", "op": "is", "values": ["ru_aad"]}]}', 'true'),
    ('provider_groups includes one', '{"mode": "conditional", "conditions": [{"field": "provider_groups", "op": "includes", "values": ["fgh"]}]}', 'true'),
    ('provider_groups includes both', '{"mode": "conditional", "conditions": [{"field": "provider_groups", "op": "includes", "values": ["FGH", "Finance Leads"]}]}', 'true'),
    ('provider_groups includes a missing one', '{"mode": "conditional", "conditions": [{"field": "provider_groups", "op": "includes", "values": ["FGH", "FGH Admins"]}]}', 'false'),
    ('provider_groups is_one_of', '{"mode": "conditional", "conditions": [{"field": "provider_groups", "op": "is_one_of", "values": ["ABC", "Finance Leads"]}]}', 'true'),
    ('provider_groups is_not_one_of', '{"mode": "conditional", "conditions": [{"field": "provider_groups", "op": "is_not_one_of", "values": ["FGH"]}]}', 'false'),
    ('provider_roles empty includes', '{"mode": "conditional", "conditions": [{"field": "provider_roles", "op": "includes", "values": ["admin"]}]}', 'false'),
    ('provider_roles empty is_not_one_of', '{"mode": "conditional", "conditions": [{"field": "provider_roles", "op": "is_not_one_of", "values": ["guest"]}]}', 'true'),
    ('labelled value', '{"mode": "conditional", "conditions": [{"field": "provider_groups", "op": "includes", "values": [{"value": "FGH", "label": "Azure FGH"}]}]}', 'true'),
    ('claim', '{"mode": "conditional", "conditions": [{"field": "claims.country", "op": "is", "values": ["cz"]}]}', 'true'),
    ('nested claim', '{"mode": "conditional", "conditions": [{"field": "claims.address.city", "op": "is_one_of", "values": ["Praha", "Brno"]}]}', 'true'),
    ('array claim includes', '{"mode": "conditional", "conditions": [{"field": "claims.tags", "op": "includes", "values": ["b", "A"]}]}', 'true'),
    ('missing claim is', '{"mode": "conditional", "conditions": [{"field": "claims.department", "op": "is", "values": ["finance"]}]}', 'false'),
    ('missing claim is_not', '{"mode": "conditional", "conditions": [{"field": "claims.department", "op": "is_not", "values": ["finance"]}]}', 'true'),
    ('and: one false', '{"mode": "conditional", "combinator": "and", "conditions": [
        {"field": "email_domain", "op": "is", "values": ["fgh.com"]},
        {"field": "claims.country", "op": "is", "values": ["SK"]}]}', 'false'),
    ('or: one true', '{"mode": "conditional", "combinator": "or", "conditions": [
        {"field": "email_domain", "op": "is", "values": ["abc.com"]},
        {"field": "claims.country", "op": "is", "values": ["CZ"]}]}', 'true'),
    ('default combinator is and', '{"mode": "conditional", "conditions": [
        {"field": "email_domain", "op": "is", "values": ["fgh.com"]},
        {"field": "claims.country", "op": "is", "values": ["SK"]}]}', 'false'),
    ('nested groups', '{"mode": "conditional", "combinator": "and", "conditions": [
        {"field": "provider_groups", "op": "includes", "values": ["FGH"]},
        {"combinator": "or", "conditions": [
            {"field": "provider_code", "op": "is", "values": ["google"]},
            {"combinator": "and", "conditions": [
                {"field": "claims.country", "op": "is", "values": ["CZ"]},
                {"field": "claims.address.city", "op": "is", "values": ["Brno"]}]}]}]}', 'true')
) v(label, rule, expected);

do $$
begin
    raise notice 'TEST 4: the subject comes from the given provider identity only';
    perform pg_temp.ru_is('another provider sees no groups'
        , unsecure.evaluate_rule('{"mode": "conditional", "conditions": [{"field": "provider_groups", "op": "includes", "values": ["FGH"]}]}'
            , unsecure.get_rule_subject(pg_temp.ru('eva')::bigint, 'ru_pwd'))::text
        , 'false');
    perform pg_temp.ru_is('no provider still has the email'
        , unsecure.evaluate_rule('{"mode": "conditional", "conditions": [{"field": "email_domain", "op": "is", "values": ["fgh.com"]}]}'
            , unsecure.get_rule_subject(pg_temp.ru('eva')::bigint, null))::text
        , 'true');
end $$;
