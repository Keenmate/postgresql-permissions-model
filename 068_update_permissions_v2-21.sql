/*
 * PostgreSQL Permissions Model — update v2.21
 * ===========================================
 *
 * Rules, rule mappings and shared rules (D-13, step 2 of
 * audit/design-d13-tenant-actions.md).
 *
 * A rule is jsonb in our own format:
 *
 *   { "mode": "conditional", "combinator": "and", "conditions": [
 *       { "field": "email_domain",    "op": "is_one_of", "values": ["abc.com", "abc.cz"] },
 *       { "field": "provider_groups", "op": "includes",  "values": [{"value": "8f1c...", "label": "FGH Admins"}] },
 *       { "combinator": "or", "conditions": [ ... ] } ] }
 *
 *  - modes always / never / conditional; "always" has to be written, a
 *    missing rule never matches
 *  - combinators and / or (default and), nested groups
 *  - ops: is, is_not, is_one_of, is_not_one_of, ends_with, regex
 *    (case-insensitive), includes (a list field has every value)
 *  - fields from the user and the identity of the provider they signed in
 *    with: email, email_domain, username, provider_code, provider_groups,
 *    provider_roles, claims.<path> (user_identity.user_data)
 *  - values are strings or {"value": ..., "label": ...}; all comparisons
 *    ignore case
 *  - the vocabulary lives in const.rule_mode / rule_combinator /
 *    rule_operator / rule_field; a rule is validated when saved (40001)
 *
 * Rule mappings: a group mapping can carry an inline rule or a shared rule
 * (auth.create_user_group_rule_mapping). Login and the permission rebuild
 * (unsecure.recalculate_user_groups) add the users the rule matches and
 * remove those it no longer matches, also for providers without group
 * mapping (an email-domain rule works for password users). Members join with
 * member_type_code 'rule'. Synced groups take no rule mappings (33026).
 *
 * Shared rules (auth.rule): tenant rules need rules.create_rule /
 * update_rule / delete_rule / read_rules in the tenant (tenant_admin,
 * tenant_owner, system_admin, full_admin). Global rules are owned by tenant 1,
 * usable in every tenant, and need rules.manage_global_rules in tenant 1
 * (full_admin only). A rule in use can't be deleted (40003). Every change is
 * journaled with the old and the new rule (23001-23003). An edit reaches the
 * members at their next login or permission rebuild (within the cache
 * timeout).
 *
 * Also fixed: recalculate_user_groups cleared the permission cache of only
 * one of the tenants whose groups changed.
 */

set search_path = public, const, ext, stage, helpers, internal, unsecure, auth, triggers;

select *
from public.start_version_update('2.21', 'Rules, rule mappings and shared rules',
                                 _component := 'postgresql_permissionmodel',
                                 _description := 'jsonb rules (validated on save, one evaluator); group mappings with an inline or shared rule, evaluated at login and rebuild; shared tenant rules and global rules (rules.manage_global_rules in tenant 1).');


/***
 *    ██╗   ██╗ ██████╗  ██████╗ █████╗ ██████╗ ██╗   ██╗██╗      █████╗ ██████╗ ██╗   ██╗
 *    vocabulary
 */

create table if not exists const.rule_mode
(
    code text not null primary key
);

create table if not exists const.rule_combinator
(
    code text not null primary key
);

create table if not exists const.rule_operator
(
    code            text    not null primary key,
    is_single_value boolean default false not null,  -- takes exactly one value
    is_array_only   boolean default false not null   -- only for list fields
);

create table if not exists const.rule_field
(
    code      text    not null primary key,
    is_array  boolean default false not null,  -- a list (provider_groups) or possibly one (claims)
    is_prefix boolean default false not null   -- used as <code>.<path>
);

insert into const.rule_mode (code)
values ('always'), ('never'), ('conditional')
on conflict do nothing;

insert into const.rule_combinator (code)
values ('and'), ('or')
on conflict do nothing;

insert into const.rule_operator (code, is_single_value, is_array_only)
values ('is', true, false),
       ('is_not', true, false),
       ('is_one_of', false, false),
       ('is_not_one_of', false, false),
       ('ends_with', false, false),
       ('regex', false, false),
       ('includes', false, true)
on conflict do nothing;

insert into const.rule_field (code, is_array, is_prefix)
values ('email', false, false),
       ('email_domain', false, false),
       ('username', false, false),
       ('provider_code', false, false),
       ('provider_groups', true, false),
       ('provider_roles', true, false),
       ('claims', true, true)
on conflict do nothing;

insert into const.user_group_member_type (code)
values ('rule')
on conflict do nothing;


/***
 *    tables
 */

create table if not exists auth.rule
(
    created_at  timestamp with time zone default now()           not null,
    created_by  text                     default 'unknown'::text not null,
    updated_at  timestamp with time zone default now()           not null,
    updated_by  text                     default 'unknown'::text not null,
    rule_id     integer generated always as identity
        primary key,
    tenant_id   integer                                          not null
        references auth.tenant
            on delete cascade,
    code        text                                             not null,
    title       text                                             not null,
    description text,
    rule        jsonb                                            not null,
    is_global   boolean                  default false           not null,
    constraint rule_created_by_check
        check (length(created_by) <= 250),
    constraint rule_updated_by_check
        check (length(updated_by) <= 250),
    -- global rules are owned by tenant 1
    constraint rule_global_in_admin_tenant
        check ((not is_global) or tenant_id = 1)
);

create unique index if not exists uq_rule
    on auth.rule (tenant_id, code);

alter table auth.user_group_mapping
    alter column provider_code drop not null,
    add column if not exists rule    jsonb,
    add column if not exists rule_id integer
        references auth.rule;  -- auth.delete_rule refuses a rule in use

-- a mapping maps a provider object/role, or carries a rule (inline or shared), never both
alter table auth.user_group_mapping
    drop constraint if exists user_group_mapping_rule_or_provider;
alter table auth.user_group_mapping
    add constraint user_group_mapping_rule_or_provider
        check ((rule is null and rule_id is null and provider_code is not null)
            or (provider_code is null and mapped_object_id is null and mapped_role is null
                and (rule is null) <> (rule_id is null)));

create index if not exists ix_user_group_mapping_rule
    on auth.user_group_mapping (user_group_mapping_id)
    where rule is not null or rule_id is not null;


/***
 *    event codes and errors
 */

insert into const.event_category (category_code, range_start, range_end, is_error, source)
values ('rule_event', 23001, 23999, false, 'core'),
       ('rule_error', 40001, 40999, true, 'core')
on conflict do nothing;

insert into const.event_code (event_id, code, category_code, is_system, source)
values (23001, 'rule_created', 'rule_event', true, 'core'),
       (23002, 'rule_updated', 'rule_event', true, 'core'),
       (23003, 'rule_deleted', 'rule_event', true, 'core'),
       (40001, 'err_rule_invalid', 'rule_error', true, 'core'),
       (40002, 'err_rule_not_found', 'rule_error', true, 'core'),
       (40003, 'err_rule_in_use', 'rule_error', true, 'core'),
       (40004, 'err_rule_already_exists', 'rule_error', true, 'core'),
       (33026, 'err_group_synced_no_rule_mapping', 'user_error', true, 'core')
on conflict do nothing;

insert into const.event_message (event_id, language_code, message_template)
values (23001, 'en', 'Rule "{rule_title}" was created by {actor}'),
       (23002, 'en', 'Rule "{rule_title}" was updated by {actor}'),
       (23003, 'en', 'Rule "{rule_title}" was deleted by {actor}'),
       (40001, 'en', 'Rule is not valid: {reason}'),
       (40002, 'en', 'Rule (id: {rule_id}) does not exist'),
       (40003, 'en', 'Rule (id: {rule_id}) is used by {mapping_count} group mapping(s)'),
       (40004, 'en', 'Rule with code "{rule_code}" already exists'),
       (33026, 'en', 'User group (id: {user_group_id}) is synchronized and takes no rule mappings')
on conflict do nothing;

-- 40001: the rule does not follow the format or uses unknown vocabulary
create or replace function error.raise_40001(_reason text) returns void
    language plpgsql
as
$$
begin
    raise exception 'Rule is not valid: %', _reason
        using errcode = '40001';
end;
$$;

-- 40002: the rule does not exist, or not in the caller's tenant
create or replace function error.raise_40002(_rule_id integer) returns void
    language plpgsql
as
$$
begin
    raise exception 'Rule (id: %) does not exist', _rule_id
        using errcode = '40002';
end;
$$;

-- 40003: a rule referenced by group mappings can't be deleted
create or replace function error.raise_40003(_rule_id integer, _mapping_count bigint) returns void
    language plpgsql
as
$$
begin
    raise exception 'Rule (id: %) is used by % group mapping(s)', _rule_id, _mapping_count
        using errcode = '40003';
end;
$$;

-- 40004: the rule code is taken in the tenant
create or replace function error.raise_40004(_rule_code text) returns void
    language plpgsql
as
$$
begin
    raise exception 'Rule with code "%" already exists', _rule_code
        using errcode = '40004';
end;
$$;

-- 33026: synced groups take their members from the sync only
create or replace function error.raise_33026(_user_group_id integer) returns void
    language plpgsql
as
$$
begin
    raise exception 'User group (id: %) is synchronized and takes no rule mappings', _user_group_id
        using errcode = '33026';
end;
$$;


/***
 *    permissions
 */

select unsecure.create_permission_as_system('Rules', '', false, _source := 'core')
where not exists(select from auth.permission where full_code = 'rules');
select unsecure.create_permission_as_system('Create rule', 'rules', true, _source := 'core')
where not exists(select from auth.permission where full_code = 'rules.create_rule');
select unsecure.create_permission_as_system('Update rule', 'rules', true, _source := 'core')
where not exists(select from auth.permission where full_code = 'rules.update_rule');
select unsecure.create_permission_as_system('Delete rule', 'rules', true, _source := 'core')
where not exists(select from auth.permission where full_code = 'rules.delete_rule');
select unsecure.create_permission_as_system('Read rules', 'rules', true, _source := 'core')
where not exists(select from auth.permission where full_code = 'rules.read_rules');
select unsecure.create_permission_as_system('Manage global rules', 'rules', true, _source := 'core')
where not exists(select from auth.permission where full_code = 'rules.manage_global_rules');

-- tenant rules: tenant admins and owners of every tenant, the admins of tenant 1
select unsecure.create_perm_set_permissions('update_v2.21', 1, null, ps.perm_set_id
    , array ['rules.create_rule', 'rules.update_rule', 'rules.delete_rule', 'rules.read_rules'], ps.tenant_id)
from auth.perm_set ps
where ps.code in ('tenant_admin', 'tenant_owner')
   or (ps.tenant_id = 1 and ps.code in ('system_admin', 'full_admin'));

-- global rules: full_admin only, so it can go to a platform team
select unsecure.create_perm_set_permissions('update_v2.21', 1, null, ps.perm_set_id
    , array ['rules.manage_global_rules'], 1)
from auth.perm_set ps
where ps.tenant_id = 1
  and ps.code = 'full_admin';


/***
 *    validation
 */

-- the values of a condition: strings, or {"value": ..., "label": ...}; as written (regex keeps its case)
create or replace function unsecure.get_rule_condition_values(_condition jsonb) returns text[]
    immutable
    language sql
as
$$
select coalesce(array_agg(case jsonb_typeof(e.value)
                              when 'object' then e.value ->> 'value'
                              when 'string' then e.value #>> '{}'
                              when 'number' then e.value #>> '{}'
                              when 'boolean' then e.value #>> '{}'
                          end order by e.ordinality), '{}')
from jsonb_array_elements(case when jsonb_typeof(_condition -> 'values') = 'array'
                                   then _condition -> 'values'
                               else '[]'::jsonb end) with ordinality e;
$$;

create or replace function unsecure.validate_rule_condition(_condition jsonb, _path text) returns void
    stable
    language plpgsql
as
$$
declare
    __field           text := _condition ->> 'field';
    __op              text := _condition ->> 'op';
    __is_array        boolean;
    __is_single_value boolean;
    __is_array_only   boolean;
    __values          text[];
    __value           text;
begin
    if __field is null then
        perform error.raise_40001(format('%s: the field is missing', _path));
    end if;

    -- plain fields by code, prefix fields as <code>.<path> with no empty segment
    select f.is_array
    from const.rule_field f
    where (not f.is_prefix and f.code = __field)
       or (f.is_prefix and __field like f.code || '.%'
        and length(__field) > length(f.code) + 1
        and __field !~ '\.\.|\.$')
    into __is_array;

    if not found then
        perform error.raise_40001(format('%s: unknown field "%s"', _path, __field));
    end if;

    select o.is_single_value, o.is_array_only
    from const.rule_operator o
    where o.code = __op
    into __is_single_value, __is_array_only;

    if not found then
        perform error.raise_40001(format('%s: unknown op "%s"', _path, coalesce(__op, '')));
    end if;

    if __is_array_only and not __is_array then
        perform error.raise_40001(format('%s: "%s" needs a list field, "%s" holds one value', _path, __op, __field));
    end if;

    if jsonb_typeof(_condition -> 'values') is distinct from 'array' then
        perform error.raise_40001(format('%s: values must be an array', _path));
    end if;

    __values := unsecure.get_rule_condition_values(_condition);

    if cardinality(__values) = 0 then
        perform error.raise_40001(format('%s: values are empty', _path));
    end if;

    if __is_single_value and cardinality(__values) <> 1 then
        perform error.raise_40001(format('%s: "%s" takes exactly one value', _path, __op));
    end if;

    foreach __value in array __values
        loop
            if __value is null or __value = '' then
                perform error.raise_40001(format('%s: a value is empty or not a string', _path));
            end if;

            if __op = 'regex' then
                begin
                    perform '' ~ __value;
                exception
                    when invalid_regular_expression then
                        perform error.raise_40001(format('%s: invalid regex "%s"', _path, __value));
                end;
            end if;
        end loop;
end;
$$;

create or replace function unsecure.validate_rule_group(_group jsonb, _path text) returns void
    stable
    language plpgsql
as
$$
declare
    __combinator text := _group ->> 'combinator';
    __condition  jsonb;
    __index      int  := 0;
    __item_path  text;
begin
    if __combinator is not null and not exists(select from const.rule_combinator where code = __combinator) then
        perform error.raise_40001(format('%s: unknown combinator "%s"', _path, __combinator));
    end if;

    if jsonb_typeof(_group -> 'conditions') is distinct from 'array'
        or jsonb_array_length(_group -> 'conditions') = 0 then
        perform error.raise_40001(format('%s: conditions must be a non-empty array', _path));
    end if;

    for __condition in
        select value
        from jsonb_array_elements(_group -> 'conditions')
        loop
            __index := __index + 1;
            __item_path := format('%s.conditions[%s]', _path, __index);

            if jsonb_typeof(__condition) is distinct from 'object' then
                perform error.raise_40001(format('%s: must be an object', __item_path));
            end if;

            if __condition ? 'conditions' then
                perform unsecure.validate_rule_group(__condition, __item_path);
            else
                perform unsecure.validate_rule_condition(__condition, __item_path);
            end if;
        end loop;
end;
$$;

-- raises 40001 unless the rule follows the format and the const vocabulary
create or replace function unsecure.validate_rule(_rule jsonb) returns void
    stable
    language plpgsql
as
$$
declare
    __mode text;
begin
    if _rule is null or jsonb_typeof(_rule) <> 'object' then
        perform error.raise_40001('a rule must be an object with a mode');
    end if;

    __mode := _rule ->> 'mode';

    if __mode is null then
        perform error.raise_40001('the mode is missing');
    end if;

    if not exists(select from const.rule_mode where code = __mode) then
        perform error.raise_40001(format('unknown mode "%s"', __mode));
    end if;

    if __mode = 'conditional' then
        perform unsecure.validate_rule_group(_rule, 'rule');
    end if;
end;
$$;


/***
 *    evaluation
 */

-- what a rule is evaluated against: the user and their identity at _provider_code
create or replace function unsecure.get_rule_subject(_target_user_id bigint, _provider_code text) returns jsonb
    stable
    language sql
as
$$
select jsonb_build_object(
               'email', ui.email,
               'email_domain', nullif(split_part(ui.email, '@', 2), ''),
               'username', ui.username,
               'provider_code', _provider_code,
               'provider_groups', coalesce(to_jsonb(uid.provider_groups), '[]'::jsonb),
               'provider_roles', coalesce(to_jsonb(uid.provider_roles), '[]'::jsonb),
               'claims', coalesce(uid.user_data, '{}'::jsonb))
from auth.user_info ui
         left join lateral (select i.provider_groups, i.provider_roles, i.user_data
                            from auth.user_identity i
                            where i.user_id = ui.user_id
                              and i.provider_code = _provider_code
                            order by i.updated_at desc
                            limit 1) uid on true
where ui.user_id = _target_user_id;
$$;

-- a field of the subject as a lowercased list; one value becomes a list of one, a missing one an empty list
create or replace function unsecure.get_rule_field_values(_field text, _subject jsonb) returns text[]
    immutable
    language sql
as
$$
with v as (select case
                      when _field like 'claims.%'
                          then _subject -> 'claims' #> string_to_array(substr(_field, 8), '.')
                      else _subject -> _field
                      end as value)
select case jsonb_typeof(v.value)
           when 'array' then coalesce((select array_agg(lower(e #>> '{}'))
                                       from jsonb_array_elements(v.value) e
                                       where jsonb_typeof(e) in ('string', 'number', 'boolean')), '{}')
           when 'string' then array [lower(v.value #>> '{}')]
           when 'number' then array [lower(v.value #>> '{}')]
           when 'boolean' then array [lower(v.value #>> '{}')]
           else '{}'::text[]
           end
from v;
$$;

create or replace function unsecure.evaluate_rule_condition(_condition jsonb, _subject jsonb) returns boolean
    immutable
    language plpgsql
as
$$
declare
    __actual text[] := unsecure.get_rule_field_values(_condition ->> 'field', _subject);
    __values text[] := unsecure.get_rule_condition_values(_condition);
    __lower  text[];
begin
    select coalesce(array_agg(lower(v)), '{}')
    from unnest(__values) v
    into __lower;

    return case _condition ->> 'op'
               when 'is' then __lower[1] = any (__actual)
               when 'is_one_of' then __actual && __lower
               when 'is_not' then not coalesce(__lower[1] = any (__actual), false)
               when 'is_not_one_of' then not (__actual && __lower)
               when 'ends_with' then exists(select
                                            from unnest(__actual) a
                                               , unnest(__lower) v
                                            where right(a, length(v)) = v)
               when 'regex' then exists(select
                                        from unnest(__actual) a
                                           , unnest(__values) v
                                        where a ~* v)
               when 'includes' then __actual @> __lower
               else false
        end;
end;
$$;

create or replace function unsecure.evaluate_rule_group(_group jsonb, _subject jsonb) returns boolean
    immutable
    language plpgsql
as
$$
declare
    __is_or     boolean := coalesce(_group ->> 'combinator', 'and') = 'or';
    __condition jsonb;
    __result    boolean;
begin
    if jsonb_typeof(_group -> 'conditions') is distinct from 'array'
        or jsonb_array_length(_group -> 'conditions') = 0 then
        return false;
    end if;

    for __condition in
        select value
        from jsonb_array_elements(_group -> 'conditions')
        loop
            if __condition ? 'conditions' then
                __result := unsecure.evaluate_rule_group(__condition, _subject);
            else
                __result := unsecure.evaluate_rule_condition(__condition, _subject);
            end if;

            if __is_or and __result then
                return true;
            end if;

            if not __is_or and not coalesce(__result, false) then
                return false;
            end if;
        end loop;

    return not __is_or;
end;
$$;

-- true when the rule matches the subject (unsecure.get_rule_subject); never, a missing or an unknown mode: false
create or replace function unsecure.evaluate_rule(_rule jsonb, _subject jsonb) returns boolean
    immutable
    language plpgsql
as
$$
begin
    return case _rule ->> 'mode'
               when 'always' then true
               when 'conditional' then coalesce(unsecure.evaluate_rule_group(_rule, _subject), false)
               else false
        end;
end;
$$;


/***
 *    shared rules
 */

-- the rule must belong to _tenant_id (a global rule too, when _allows_global)
create or replace function unsecure.validate_rule_in_tenant(_rule_id integer, _tenant_id integer, _allows_global boolean default false) returns void
    stable
    language plpgsql
as
$$
begin
    if not exists(select
                  from auth.rule r
                  where r.rule_id = _rule_id
                    and (r.tenant_id = _tenant_id or (_allows_global and r.is_global))) then
        perform error.raise_40002(_rule_id);
    end if;
end;
$$;

create or replace function auth.create_rule(_created_by text, _user_id bigint, _correlation_id text, _title text, _rule jsonb,
                                            _description text default null, _code text default null,
                                            _is_global boolean default false, _tenant_id integer default 1)
    returns table(__rule_id integer)
    rows 1
    language plpgsql
as
$$
declare
    __code      text    := coalesce(_code, helpers.get_code(_title, '_'));
    __tenant_id integer := case when _is_global then 1 else _tenant_id end;
    ___rule_id  integer;
begin
    if _is_global then
        -- global rules are owned by tenant 1 and serve every tenant
        perform auth.has_permission(_user_id, _correlation_id, 'rules.manage_global_rules', 1);
    else
        perform auth.has_permission(_user_id, _correlation_id, 'rules.create_rule', _tenant_id);
    end if;

    perform unsecure.validate_rule(_rule);

    if exists(select from auth.rule r where r.tenant_id = __tenant_id and r.code = __code) then
        perform error.raise_40004(__code);
    end if;

    insert into auth.rule (created_by, updated_by, tenant_id, code, title, description, rule, is_global)
    values (_created_by, _created_by, __tenant_id, __code, _title, _description, _rule, _is_global)
    returning rule_id into ___rule_id;

    perform public.create_journal_message_for_entity(_created_by, _user_id, _correlation_id
        , 23001  -- rule_created
        , 'rule', ___rule_id
        , jsonb_build_object('rule_title', _title, 'rule_code', __code, 'is_global', _is_global, 'new_rule', _rule)
        , __tenant_id);

    return query select ___rule_id;
end;
$$;

create or replace function auth.update_rule(_updated_by text, _user_id bigint, _correlation_id text, _rule_id integer,
                                            _title text, _rule jsonb, _description text default null,
                                            _tenant_id integer default 1)
    returns table(__rule_id integer)
    rows 1
    language plpgsql
as
$$
declare
    __is_global boolean;
    __tenant_id integer;
    __old_rule  jsonb;
begin
    select r.is_global, r.tenant_id, r.rule
    from auth.rule r
    where r.rule_id = _rule_id
    into __is_global, __tenant_id, __old_rule;

    if __is_global then
        perform auth.has_permission(_user_id, _correlation_id, 'rules.manage_global_rules', 1);
    else
        perform auth.has_permission(_user_id, _correlation_id, 'rules.update_rule', _tenant_id);
        perform unsecure.validate_rule_in_tenant(_rule_id, _tenant_id);
    end if;

    perform unsecure.validate_rule(_rule);

    update auth.rule
    set updated_by  = _updated_by
      , updated_at  = now()
      , title       = _title
      , description = _description
      , rule        = _rule
    where rule_id = _rule_id;

    -- current members re-evaluate at their next rebuild; new matches join at their next login or cache expiry
    update auth.user_permission_cache upc
    set expiration_date = now()
      , updated_by      = _updated_by
      , updated_at      = now()
    where upc.user_id in (select m.user_id
                          from auth.user_group_member m
                                   inner join auth.user_group_mapping ugm on ugm.user_group_mapping_id = m.mapping_id
                          where ugm.rule_id = _rule_id);

    perform public.create_journal_message_for_entity(_updated_by, _user_id, _correlation_id
        , 23002  -- rule_updated
        , 'rule', _rule_id
        , jsonb_build_object('rule_title', _title, 'old_rule', __old_rule, 'new_rule', _rule)
        , __tenant_id);

    return query select _rule_id;
end;
$$;

create or replace function auth.delete_rule(_deleted_by text, _user_id bigint, _correlation_id text, _rule_id integer,
                                            _tenant_id integer default 1) returns void
    language plpgsql
as
$$
declare
    __is_global     boolean;
    __tenant_id     integer;
    __title         text;
    __old_rule      jsonb;
    __mapping_count bigint;
begin
    select r.is_global, r.tenant_id, r.title, r.rule
    from auth.rule r
    where r.rule_id = _rule_id
    into __is_global, __tenant_id, __title, __old_rule;

    if __is_global then
        perform auth.has_permission(_user_id, _correlation_id, 'rules.manage_global_rules', 1);
    else
        perform auth.has_permission(_user_id, _correlation_id, 'rules.delete_rule', _tenant_id);
        perform unsecure.validate_rule_in_tenant(_rule_id, _tenant_id);
    end if;

    select count(*)
    from auth.user_group_mapping ugm
    where ugm.rule_id = _rule_id
    into __mapping_count;

    if __mapping_count > 0 then
        perform error.raise_40003(_rule_id, __mapping_count);
    end if;

    delete from auth.rule where rule_id = _rule_id;

    perform public.create_journal_message_for_entity(_deleted_by, _user_id, _correlation_id
        , 23003  -- rule_deleted
        , 'rule', _rule_id
        , jsonb_build_object('rule_title', __title, 'old_rule', __old_rule)
        , __tenant_id);
end;
$$;

-- the rules usable in the tenant: its own and the global ones; mapping counts are the tenant's own
create or replace function auth.get_rules(_user_id bigint, _correlation_id text, _tenant_id integer default 1)
    returns table(
        __rule_id       integer,
        __tenant_id     integer,
        __code          text,
        __title         text,
        __description   text,
        __rule          jsonb,
        __is_global     boolean,
        __mapping_count bigint,
        __created_at    timestamptz,
        __created_by    text,
        __updated_at    timestamptz,
        __updated_by    text
    )
    stable
    language plpgsql
as
$$
begin
    perform auth.has_permission(_user_id, _correlation_id, 'rules.read_rules', _tenant_id);

    return query
        select r.rule_id
             , r.tenant_id
             , r.code
             , r.title
             , r.description
             , r.rule
             , r.is_global
             , (select count(*)
                from auth.user_group_mapping ugm
                         inner join auth.user_group ug on ug.user_group_id = ugm.user_group_id
                where ugm.rule_id = r.rule_id
                  and ug.tenant_id = _tenant_id)
             , r.created_at
             , r.created_by
             , r.updated_at
             , r.updated_by
        from auth.rule r
        where r.tenant_id = _tenant_id
           or r.is_global
        order by r.is_global, r.title;
end;
$$;


/***
 *    rule mappings
 */

create or replace function auth.create_user_group_rule_mapping(_created_by text, _user_id bigint, _correlation_id text,
                                                               _user_group_id integer, _rule jsonb default null,
                                                               _rule_id integer default null, _tenant_id integer default 1)
    returns table(__user_group_mapping_id integer, __user_group_id integer)
    rows 1
    language plpgsql
as
$$
declare
    __is_active  boolean;
    __is_synced  boolean;
    __mapping_id integer;
    __rule_title text;
begin
    perform auth.has_permission(_user_id, _correlation_id, 'groups.create_mapping', _tenant_id);
    perform unsecure.validate_user_group_in_tenant(_user_group_id, _tenant_id);

    select ug.is_active, ug.is_synced
    from auth.user_group ug
    where ug.user_group_id = _user_group_id
    into __is_active, __is_synced;

    if not __is_active then
        perform error.raise_52172(_user_group_id);
    end if;

    if __is_synced then
        perform error.raise_33026(_user_group_id);
    end if;

    if (_rule is null) = (_rule_id is null) then
        perform error.raise_40001('a rule mapping takes either a rule or a rule id');
    end if;

    if _rule is not null then
        perform unsecure.validate_rule(_rule);
    else
        perform unsecure.validate_rule_in_tenant(_rule_id, _tenant_id, _allows_global := true);
        select r.title from auth.rule r where r.rule_id = _rule_id into __rule_title;
    end if;

    insert into auth.user_group_mapping (created_by, user_group_id, rule, rule_id)
    values (_created_by, _user_group_id, _rule, _rule_id)
    returning user_group_mapping_id into __mapping_id;

    -- users join at their next login or permission rebuild (within the cache timeout)

    perform public.create_journal_message_for_entity(_created_by, _user_id, _correlation_id
        , 13020  -- group_mapping_created
        , 'group', _user_group_id
        , jsonb_build_object('group_title', _user_group_id::text
            , 'mapping_name', coalesce(__rule_title, 'rule')
            , 'rule_id', _rule_id, 'rule', _rule)
        , _tenant_id);

    return query select __mapping_id, _user_group_id;
end;
$$;

drop function if exists auth.get_user_group_mappings(text, bigint, text, integer, integer, integer);
drop function if exists auth.search_user_group_mappings(bigint, text, jsonb, integer, integer, integer, integer);

create or replace function auth.get_user_group_mappings(_requested_by text, _user_id bigint, _correlation_id text, _user_group_id integer, _tenant_id integer default 1, _target_tenant_id integer default null)
    returns table(
        __created_at            timestamptz,
        __created_by            text,
        __user_group_mapping_id integer,
        __user_group_id         integer,
        __provider_code         text,
        __mapped_object_id      text,
        __mapped_object_name    text,
        __mapped_role           text,
        __rule_id               integer,
        __rule                  jsonb
    )
    language plpgsql
as
$$
declare
	__effective_tenant_id int;
begin

	__effective_tenant_id := internal.resolve_cross_tenant_access(
		_user_id, _correlation_id, 'groups.get_all_mappings', 'groups.get_mapping', _tenant_id, _target_tenant_id);

	return query select ugm.created_at, ugm.created_by, ugm.user_group_mapping_id, ugm.user_group_id, ugm.provider_code, ugm.mapped_object_id, ugm.mapped_object_name, ugm.mapped_role
					  , ugm.rule_id, coalesce(ugm.rule, r.rule)
				 from auth.user_group_mapping ugm
					 inner join auth.user_group ug on ugm.user_group_id = ug.user_group_id
					 left join auth.rule r on r.rule_id = ugm.rule_id
				 where ugm.user_group_id = _user_group_id
				   and (__effective_tenant_id is null or ug.tenant_id = __effective_tenant_id);

	-- Read operation - journal message omitted (use journal level 'all' to log reads)
end;
$$;

create or replace function auth.search_user_group_mappings(
	_user_id bigint,
	_correlation_id text default null,
	_search_criteria jsonb default null,
	_page integer default 1,
	_page_size integer default 30,
	_tenant_id integer default 1,
	_target_tenant_id integer default null
)
	returns table(
		__user_group_mapping_id integer,
		__user_group_id integer,
		__user_group_title text,
		__user_group_code text,
		__provider_code text,
		__mapped_object_id text,
		__mapped_object_name text,
		__mapped_role text,
		__rule_id integer,
		__rule jsonb,
		__total_items bigint
	)
	stable
	rows 100
	language plpgsql
	set search_path = public, const, ext, stage, helpers, internal, unsecure, auth, triggers
as
$$
declare
	__search_text text;
	__provider_code text;
	__mapped_object_id text;
	__mapped_role text;
	__effective_tenant_id int;
begin
	__effective_tenant_id := internal.resolve_cross_tenant_access(
		_user_id, _correlation_id, 'groups.get_all_mappings', 'groups.get_mapping', _tenant_id, _target_tenant_id);

	__search_text := helpers.normalize_text(_search_criteria ->> 'search_text');
	__provider_code := _search_criteria ->> 'provider_code';
	__mapped_object_id := _search_criteria ->> 'mapped_object_id';
	__mapped_role := _search_criteria ->> 'mapped_role';

	_page := coalesce(_page, 1);
	_page_size := least(coalesce(_page_size, 30), 100);

	return query
		with filtered_mappings as (
			select ugm.user_group_mapping_id
				 , count(*) over () as total_items
			from auth.user_group_mapping ugm
				inner join auth.user_group ug on ugm.user_group_id = ug.user_group_id
			where (__effective_tenant_id is null or ug.tenant_id = __effective_tenant_id)
			  and (__provider_code is null or ugm.provider_code = __provider_code)
			  and (__mapped_object_id is null or ugm.mapped_object_id = __mapped_object_id)
			  and (__mapped_role is null or ugm.mapped_role = __mapped_role)
			  and (helpers.is_empty_string(__search_text)
				   or ugm.mapped_object_id ilike '%' || __search_text || '%'
				   or ugm.mapped_object_name ilike '%' || __search_text || '%'
				   or ugm.mapped_role ilike '%' || __search_text || '%'
				   or ug.title ilike '%' || __search_text || '%')
			order by ug.title, ugm.provider_code, ugm.mapped_object_name
			offset ((_page - 1) * _page_size) limit _page_size
		)
		select ugm.user_group_mapping_id
			 , ugm.user_group_id
			 , ug.title
			 , ug.code
			 , ugm.provider_code
			 , ugm.mapped_object_id
			 , ugm.mapped_object_name
			 , ugm.mapped_role
			 , ugm.rule_id
			 , coalesce(ugm.rule, r.rule)
			 , fm.total_items
		from filtered_mappings fm
			inner join auth.user_group_mapping ugm on fm.user_group_mapping_id = ugm.user_group_mapping_id
			inner join auth.user_group ug on ugm.user_group_id = ug.user_group_id
			left join auth.rule r on r.rule_id = ugm.rule_id;
end;
$$;

-- rule memberships have no provider; they count like direct memberships
create or replace function unsecure.recalculate_user_permissions(_created_by text, _target_user_id bigint, _tenant_id integer DEFAULT NULL::integer)
    returns TABLE(__tenant_id integer, __tenant_uuid uuid, __groups text[], __permissions text[], __short_code_permissions text[])
    language plpgsql
as
$$
declare
    __perm_cache_timeout_in_s bigint;
    __expiration_date         timestamptz;
    __is_active               boolean;
    __is_locked               boolean;
begin

    -- Check if user is active and not locked
    select is_active, is_locked
    from auth.user_info
    where user_id = _target_user_id
    into __is_active, __is_locked;

    if __is_active is null then
        perform error.raise_33001(_target_user_id, null);
    end if;

    if not __is_active then
        perform error.raise_33003(_target_user_id);
    end if;

    if __is_locked then
        perform error.raise_33004(_target_user_id);
    end if;

    if _tenant_id is not null and exists(
            select
            from auth.user_permission_cache
            where tenant_id = _tenant_id
              and user_id = _target_user_id
              and expiration_date > now())
    then

        return query
            select _tenant_id
                 , upc.tenant_uuid
                 , upc.groups
                 , upc.permissions
                 , upc.short_code_permissions
            from auth.user_permission_cache upc
            where upc.tenant_id = _tenant_id
              and upc.user_id = _target_user_id;
    else
        select number_value
        from const.sys_param sp
        where sp.group_code = 'auth'
          and sp.code = 'perm_cache_timeout_in_s'
        into __perm_cache_timeout_in_s;

        if
            (__perm_cache_timeout_in_s is null)
        then
            __perm_cache_timeout_in_s := 300;
        end if;

        drop table if exists __temp_users_groups_permissions;
        create temporary table __temp_users_groups_permissions
        (
            tenant_id                integer,
            tenant_uuid              uuid,
            group_codes              text[],
            permission_codes         text[],
            short_code_permission_codes text[]
        ) on commit drop;

        -- Only memberships that grant: active group, live tenant, and for mapped
        -- (external / synced) memberships an active provider and a not-disabled
        -- identity of the user at that provider.
        with ugs as (
            select distinct ug.tenant_id
                          , t.uuid as tenant_uuid
                          , ug.user_group_id
                          , ug.code as group_code
            from auth.user_group_member ugm
                     inner join auth.user_group ug on ug.user_group_id = ugm.user_group_id
                     inner join auth.tenant t on t.tenant_id = ug.tenant_id
                     left join auth.user_group_mapping m on m.user_group_mapping_id = ugm.mapping_id
                     left join auth.provider pr on pr.code = m.provider_code
                     left join auth.user_identity uid on uid.user_id = ugm.user_id and uid.provider_code = m.provider_code
            where ugm.user_id = _target_user_id
              and ug.is_active
              and t.deleted_at is null
              and (ugm.mapping_id is null
                or m.provider_code is null  -- rule mapping (v2.21)
                or (coalesce(pr.is_active, false) and coalesce(uid.is_active, true))))
           , group_assignments as (
            select distinct pa.tenant_id
                          , ug.tenant_uuid
                          , ep.permission_code as full_code
                          , ep.permission_short_code as short_code
            from ugs ug
                     inner join auth.permission_assignment pa
                                on ug.user_group_id = pa.user_group_id and pa.tenant_id = ug.tenant_id
                     inner join auth.effective_permissions ep on pa.perm_set_id = ep.perm_set_id
            where ep.perm_set_is_assignable = true
              and ep.permission_is_assignable = true
            union
            select distinct pa.tenant_id
                          , ug.tenant_uuid
                          , sp.full_code
                          , sp.short_code
            from ugs ug
                     inner join auth.permission_assignment pa
                                on ug.user_group_id = pa.user_group_id and pa.tenant_id = ug.tenant_id
                     inner join auth.permission p on pa.permission_id = p.permission_id
                     inner join auth.permission sp
                                on sp.node_path <@ p.node_path and sp.is_assignable = true)
           , user_assignments as (
            select distinct pa.tenant_id
                          , t.uuid             as tenant_uuid
                          , ep.permission_code as full_code
                          , ep.permission_short_code as short_code
            from auth.permission_assignment pa
                     inner join auth.tenant t on pa.tenant_id = t.tenant_id and t.deleted_at is null
                     inner join auth.effective_permissions ep
                                on pa.perm_set_id = ep.perm_set_id
            where pa.user_id = _target_user_id
              and ep.perm_set_is_assignable = true
              and ep.permission_is_assignable = true
            union
            select distinct pa.tenant_id
                          , t.uuid as tenant_uuid
                          , sp.full_code
                          , sp.short_code
            from auth.permission_assignment pa
                     inner join auth.tenant t on pa.tenant_id = t.tenant_id and t.deleted_at is null
                     inner join auth.permission p
                                on pa.permission_id = p.permission_id
                     inner join auth.permission sp
                                on sp.node_path <@ p.node_path and sp.is_assignable = true
            where pa.user_id = _target_user_id)
           , owner_assignments as (
            -- a tenant-wide owner holds the tenant's tenant_owner perm set (D-05)
            select distinct o.tenant_id
                          , t.uuid                   as tenant_uuid
                          , ep.permission_code       as full_code
                          , ep.permission_short_code as short_code
            from auth.owner o
                     inner join auth.tenant t on t.tenant_id = o.tenant_id and t.deleted_at is null
                     inner join auth.perm_set ps on ps.tenant_id = o.tenant_id and ps.code = 'tenant_owner'
                     inner join auth.effective_permissions ep on ep.perm_set_id = ps.perm_set_id
            where o.user_id = _target_user_id
              and o.user_group_id is null
              and ep.permission_is_assignable = true)
           , user_permissions as (
            select distinct ga.tenant_id
                          , ga.tenant_uuid
                          , ga.full_code
                          , ga.short_code
            from group_assignments ga
            union
            select ua.tenant_id
                 , ua.tenant_uuid
                 , ua.full_code
                 , ua.short_code
            from user_assignments ua
            union
            select oa.tenant_id
                 , oa.tenant_uuid
                 , oa.full_code
                 , oa.short_code
            from owner_assignments oa
            order by full_code)
        insert
        into __temp_users_groups_permissions(tenant_id, tenant_uuid, group_codes, permission_codes, short_code_permission_codes)
        select data.tenant_id
             , data.tenant_uuid
             , coalesce(array_agg(distinct data.groups) filter ( where data.groups is not null ), array []::text[])
             , coalesce(array_agg(distinct data.perms) filter ( where data.perms is not null ), array []::text[])
             , coalesce(array_agg(distinct data.short_code_perms) filter ( where data.short_code_perms is not null ), array []::text[])
        from (
                 select ug.tenant_id
                      , ug.tenant_uuid
                      , ug.group_code as groups
                      , null          as perms
                      , null          as short_code_perms
                 from ugs ug
                 union
                 select up.tenant_id
                      , up.tenant_uuid
                      , null
                      , up.full_code::text
                      , up.short_code
                 from user_permissions up) data
        group by data.tenant_id, data.tenant_uuid;

        __expiration_date := now() + interval '1 second' * __perm_cache_timeout_in_s;

        insert into auth.user_permission_cache (created_by, user_id, tenant_id, tenant_uuid, groups, permissions,
                                                short_code_permissions, expiration_date)
        select _created_by
             , _target_user_id
             , tugp.tenant_id
             , tugp.tenant_uuid
             , tugp.group_codes
             , tugp.permission_codes
             , tugp.short_code_permission_codes
             , __expiration_date
        from __temp_users_groups_permissions tugp
        on conflict (user_id, tenant_id )
            do update
            set updated_at              = now()
              , updated_by              = _created_by
              , groups                  = excluded.groups
              , permissions             = excluded.permissions
              , short_code_permissions  = excluded.short_code_permissions
              , expiration_date         = __expiration_date;

        return query
            select ugp.tenant_id
                 , ugp.tenant_uuid
                 , ugp.group_codes
                 , ugp.permission_codes
                 , ugp.short_code_permission_codes
            from __temp_users_groups_permissions ugp
            where _tenant_id is null
               or ugp.tenant_id = _tenant_id
            order by ugp.tenant_id;
    end if;
end;
$$;

create or replace view auth.tenant_memberships (tenant_id, user_id, source_code) as
select ug.tenant_id
     , ugm.user_id
     , 'group'::text
from auth.user_group_member ugm
         inner join auth.user_group ug on ug.user_group_id = ugm.user_group_id
         left join auth.user_group_mapping m on m.user_group_mapping_id = ugm.mapping_id
         left join auth.provider pr on pr.code = m.provider_code
         left join auth.user_identity uid on uid.user_id = ugm.user_id and uid.provider_code = m.provider_code
where ug.is_active
  and (ugm.mapping_id is null
    or m.provider_code is null  -- rule mapping (v2.21)
    or (coalesce(pr.is_active, false) and coalesce(uid.is_active, true)))
  -- only groups that grant something; a picker list grants nothing
  and (exists(select from auth.permission_assignment gpa where gpa.user_group_id = ug.user_group_id)
    or exists(select from auth.resource_access gra
              where gra.user_group_id = ug.user_group_id and not gra.is_deny)
    or exists(select from auth.resource_role_assignment grra
                       inner join const.resource_role grr on grr.code = grra.role_code and grr.is_active
              where grra.user_group_id = ug.user_group_id))
union all
select pa.tenant_id
     , pa.user_id
     , 'assignment'::text
from auth.permission_assignment pa
where pa.user_id is not null
union all
select o.tenant_id
     , o.user_id
     , 'owner'::text
from auth.owner o
union all
select ra.tenant_id
     , ra.user_id
     , 'resource_access'::text
from auth.resource_access ra
where ra.user_id is not null
  and not ra.is_deny
union all
select rra.tenant_id
     , rra.user_id
     , 'resource_role'::text
from auth.resource_role_assignment rra
         inner join const.resource_role rr on rr.code = rra.role_code and rr.is_active
where rra.user_id is not null;

-- tenant_id -> affected user_ids
-- Used for: tenant_purged
create or replace view auth.notify_tenant_users
            (tenant_id, user_id) as
select distinct tm.tenant_id
              , tm.user_id::integer
from auth.tenant_memberships tm;


-- Tenant 1 gets the Tenant Members group every other tenant has (add_tenant_user)
do
$$
declare
    __group_id integer;
begin
    if not exists(select from auth.user_group where tenant_id = 1 and code = 'tenant_members') then
        select g.__user_group_id
        from unsecure.create_user_group('update_v2.17', 1, null, 'Tenant Members'
            , true, true, false, true, _tenant_id := 1) g
        into __group_id;

        if exists(select from auth.perm_set where tenant_id = 1 and code = 'tenant_member') then
            perform unsecure.assign_permission('update_v2.17', 1, null
                , __group_id, null, 'tenant_member', _tenant_id := 1);
        end if;
    end if;
end;
$$;

-- login and the permission rebuild: provider mappings (when the provider allows group mapping)
-- and rule mappings (always) decide the mapped memberships
create or replace function unsecure.recalculate_user_groups(_created_by text, _target_user_id bigint, _provider_code text)
    returns TABLE(__tenant_id integer, __user_group_id integer, __user_group_code text)
    language plpgsql
as
$$
declare
    __not_really_used int;
    __provider_groups text[];
    __provider_roles  text[];
    __allows_mapping  boolean;
    __subject         jsonb;
begin

    -- Validate provider code exists (prevent silent failures with NULL arrays)
    if _provider_code is not null and not exists(select 1 from auth.provider where code = _provider_code) then
        raise exception 'Provider "%" does not exist', _provider_code
            using errcode = '22023';  -- invalid_parameter_value
    end if;

    select provider_groups
         , provider_roles
    from auth.user_identity
    where provider_code = _provider_code
      and user_id = _target_user_id
    into __provider_groups, __provider_roles;

    -- provider mappings need a provider that allows group mapping; rule mappings apply with any provider
    __allows_mapping := _provider_code is null
        or coalesce((select allows_group_mapping from auth.provider where code = _provider_code), false);

    __subject := unsecure.get_rule_subject(_target_user_id, _provider_code);

    with matched_mappings as (
        select ugm.user_group_mapping_id
             , ugm.user_group_id
        from auth.user_group_mapping ugm
        where __allows_mapping
          and ugm.provider_code = _provider_code
          and (ugm.mapped_object_id in (select lower(g) from unnest(__provider_groups) g)
            or ugm.mapped_role in (select lower(r) from unnest(__provider_roles) r))
        union all
        select ugm.user_group_mapping_id
             , ugm.user_group_id
        from auth.user_group_mapping ugm
                 left join auth.rule r on r.rule_id = ugm.rule_id
        where (ugm.rule is not null or ugm.rule_id is not null)
          and unsecure.evaluate_rule(coalesce(ugm.rule, r.rule), __subject))
       , matched_groups as (
        -- synced groups take their members from the sync only (v2.19)
        select mm.user_group_id
             , min(mm.user_group_mapping_id) as user_group_mapping_id
        from matched_mappings mm
                 inner join auth.user_group ug on ug.user_group_id = mm.user_group_id
        where not ug.is_synced
        group by mm.user_group_id)
       , affected_deleted_groups as (
        delete
            from auth.user_group_member m
                where m.user_id = _target_user_id
                    and m.mapping_id is not null
                    and m.user_group_id not in (select sg.user_group_id from auth.user_group sg where sg.is_synced)
                    -- without group mapping only the rule memberships follow the login
                    and (__allows_mapping
                        or m.mapping_id in (select rm.user_group_mapping_id
                                            from auth.user_group_mapping rm
                                            where rm.rule is not null
                                               or rm.rule_id is not null))
                    and m.user_group_id not in (select mg.user_group_id from matched_groups mg)
                returning m.user_group_id)
       , affected_added_groups as (
        insert
            into auth.user_group_member (created_by, user_id, user_group_id, mapping_id, member_type_code)
                select _created_by
                     , _target_user_id
                     , mg.user_group_id
                     , mg.user_group_mapping_id
                     , case when ugm.provider_code is null then 'rule' else 'external' end
                from matched_groups mg
                         inner join auth.user_group_mapping ugm on ugm.user_group_mapping_id = mg.user_group_mapping_id
                where mg.user_group_id not in (select x.user_group_id
                                               from auth.user_group_member x
                                               where x.user_id = _target_user_id)
                returning user_group_id)
       , all_group_ids as (
        select user_group_id
        from affected_deleted_groups
        union
        select user_group_id
        from affected_added_groups)
       , all_tenants as (
        select tenant_id
        from all_group_ids ids
                 inner join auth.user_group ug
                            on ids.user_group_id = ug.user_group_id
        group by tenant_id)
       -- count(*) makes every tenant's cache clear run (select into stops at the first row)
    select count(*)
    from all_tenants at
       , lateral unsecure.clear_permission_cache(_created_by, _target_user_id, at.tenant_id) r
    into __not_really_used;

    return query
        select distinct ug.tenant_id
                      , ug.user_group_id
                      , ug.code
        from auth.user_group_member ugm
                 inner join auth.user_group ug on ug.user_group_id = ugm.user_group_id
        where ugm.user_id = _target_user_id;
end;
$$;


select *
from public.stop_version_update('2.21', _component := 'postgresql_permissionmodel');
