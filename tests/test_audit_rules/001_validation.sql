set search_path = public, const, ext, stage, helpers, internal, unsecure, auth, triggers;

-- ============================================================================
-- Rules are validated on save, against the const vocabulary (40001)
-- ============================================================================
do $$
begin
    raise notice 'TEST 1: invalid rules are rejected when saving';
end $$;

select pg_temp.ru_expect(label, format('select * from auth.create_rule(''ru'', {fgh_admin}, ''ru'', %L, %L::jsonb, _tenant_id := {fgh})', label, rule), '40001')
from (values
    ('missing rule', null),
    ('not an object', '"always"'),
    ('missing mode', '{"combinator": "and", "conditions": [{"field": "email", "op": "is", "values": ["a@b.c"]}]}'),
    ('unknown mode', '{"mode": "sometimes"}'),
    ('conditional without conditions', '{"mode": "conditional", "combinator": "and", "conditions": []}'),
    ('unknown combinator', '{"mode": "conditional", "combinator": "xor", "conditions": [{"field": "email", "op": "is", "values": ["a@b.c"]}]}'),
    ('unknown field', '{"mode": "conditional", "conditions": [{"field": "phone", "op": "is", "values": ["1"]}]}'),
    ('unknown op', '{"mode": "conditional", "conditions": [{"field": "email", "op": "like", "values": ["a%"]}]}'),
    ('no values', '{"mode": "conditional", "conditions": [{"field": "email", "op": "is_one_of", "values": []}]}'),
    ('values not an array', '{"mode": "conditional", "conditions": [{"field": "email", "op": "is", "values": "a@b.c"}]}'),
    ('is with two values', '{"mode": "conditional", "conditions": [{"field": "email", "op": "is", "values": ["a@b.c", "d@e.f"]}]}'),
    ('empty value', '{"mode": "conditional", "conditions": [{"field": "email", "op": "is_one_of", "values": ["a@b.c", ""]}]}'),
    ('includes on a single-value field', '{"mode": "conditional", "conditions": [{"field": "email", "op": "includes", "values": ["a@b.c"]}]}'),
    ('invalid regex', '{"mode": "conditional", "conditions": [{"field": "username", "op": "regex", "values": ["(abc"]}]}'),
    ('claims without a path', '{"mode": "conditional", "conditions": [{"field": "claims.", "op": "is", "values": ["CZ"]}]}'),
    ('invalid nested group', '{"mode": "conditional", "combinator": "or", "conditions": [{"field": "email", "op": "is", "values": ["a@b.c"]}, {"combinator": "and", "conditions": [{"field": "email", "op": "nope", "values": ["x"]}]}]}'),
    ('condition without field', '{"mode": "conditional", "conditions": [{"op": "is", "values": ["x"]}]}')
) v(label, rule);

do $$
declare
    __fgh   int := pg_temp.ru('fgh')::int;
    __admin bigint := pg_temp.ru('fgh_admin')::bigint;
    __id    int;
    __rule  jsonb;
begin
    raise notice 'TEST 2: valid rules are saved as written';

    foreach __rule in array array[
        '{"mode": "always"}',
        '{"mode": "never"}',
        '{"mode": "conditional", "conditions": [{"field": "email_domain", "op": "is_one_of", "values": ["fgh.com", "fgh.cz"]}]}',
        '{"mode": "conditional", "combinator": "and", "conditions": [
            {"field": "provider_groups", "op": "includes", "values": [{"value": "8f1c-fgh", "label": "Azure FGH"}]},
            {"combinator": "or", "conditions": [
                {"field": "provider_code", "op": "is", "values": ["ru_aad"]},
                {"field": "claims.address.country", "op": "is", "values": ["CZ"]}]}]}',
        '{"mode": "conditional", "combinator": "or", "conditions": [
            {"field": "username", "op": "regex", "values": ["^ru_[a-z]+$"]},
            {"field": "email", "op": "ends_with", "values": ["@fgh.com"]},
            {"field": "provider_roles", "op": "is_not_one_of", "values": ["guest"]},
            {"field": "email", "op": "is_not", "values": ["x@y.z"]}]}'
        ]::jsonb[]
    loop
        select r.__rule_id from auth.create_rule('ru', __admin, 'ru', 'RU valid ' || md5(__rule::text), __rule, _tenant_id := __fgh) r into __id;
        perform pg_temp.ru_is('saved ' || left(__rule::text, 60), (select (rule = __rule)::text from auth.rule where rule_id = __id), 'true');
    end loop;
end $$;
