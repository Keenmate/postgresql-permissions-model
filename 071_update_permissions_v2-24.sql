/*
 * PostgreSQL Permissions Model — update v2.24
 * ===========================================
 *
 * Tenant templates (D-13, step 5 of audit/design-d13-tenant-actions.md).
 *
 * A template is a seed, not a baseline: create_tenant runs it once and the
 * tenant owns everything afterwards. It creates groups, copies their perm sets
 * from tenant 1, assigns them, and adds the groups' mappings: provider objects
 * or roles, or a global rule.
 *
 *  - auth.tenant_template: named templates (code) plus one nameless default
 *    (code null), seeded with what create_tenant always created (Tenant Admins
 *    with tenant_admin, Tenant Members with tenant_member). The default can be
 *    edited, not deleted or disabled (34010).
 *  - auth.tenant_template_group: title, optional code, is_external,
 *    is_assignable, perm_set_codes (tenant-1 perm sets, copied on use).
 *  - auth.tenant_template_group_mapping: a provider object/role, or a global
 *    rule (auth.rule.is_global).
 *  - Placeholders in group titles/codes and mapping values: {tenant.id},
 *    {tenant.code}, {data.<path>} from create_tenant's _extra_data. Checked on
 *    save (34012), resolved once at creation; a missing value fails
 *    create_tenant (34011).
 *  - create_tenant(_template_code, _extra_data): no code = the default
 *    template; unknown or inactive = 34009. tenant_owner is always copied
 *    (D-05). Journal 11001 carries the template code and the extra data.
 *  - A trigger notifies tenant_created on the permission_changes channel, for
 *    anything the app does beyond the seed.
 *  - Tenant 1: tenants.manage_tenant_templates / read_tenant_templates in
 *    system_admin and full_admin. D-19: whoever puts a perm set into a template
 *    must hold its permissions in tenant 1.
 *  - A global rule used by a template can't be deleted (40003).
 */

set search_path = public, const, ext, stage, helpers, internal, unsecure, auth, triggers;

select *
from public.start_version_update('2.24', 'Tenant templates',
                                 _component := 'postgresql_permissionmodel',
                                 _description := 'create_tenant seeds the tenant from a template: groups, tenant-1 perm sets, mappings (provider objects with {tenant.*}/{data.*} placeholders, or global rules); a nameless default reproduces the old shape; tenant_created notification; tenants.manage/read_tenant_templates in tenant 1.');


/***
 *    tables
 */

create table if not exists auth.tenant_template
(
    created_at         timestamptz default now()     not null,
    created_by         text        default 'unknown' not null,
    updated_at         timestamptz default now()     not null,
    updated_by         text        default 'unknown' not null,
    tenant_template_id integer generated always as identity primary key,
    code               text,  -- null = the default template
    title              text                          not null,
    description        text,
    is_active          boolean     default true      not null,
    constraint tenant_template_created_by_check check (length(created_by) <= 250),
    constraint tenant_template_updated_by_check check (length(updated_by) <= 250),
    constraint uq_tenant_template_code unique (code)
);

-- at most one default template
create unique index if not exists uq_tenant_template_default
    on auth.tenant_template ((true))
    where code is null;

create table if not exists auth.tenant_template_group
(
    created_at               timestamptz default now()     not null,
    created_by               text        default 'unknown' not null,
    updated_at               timestamptz default now()     not null,
    updated_by               text        default 'unknown' not null,
    tenant_template_group_id integer generated always as identity primary key,
    tenant_template_id       integer                       not null
        references auth.tenant_template on delete cascade,
    code                     text,  -- null = from the title
    title                    text                          not null,
    is_external              boolean     default false     not null,
    is_assignable            boolean     default true      not null,
    is_system                boolean     default false     not null,
    perm_set_codes           text[]      default '{}'      not null,  -- tenant-1 perm sets
    constraint tenant_template_group_created_by_check check (length(created_by) <= 250),
    constraint tenant_template_group_updated_by_check check (length(updated_by) <= 250)
);

create index if not exists ix_tenant_template_group_template
    on auth.tenant_template_group (tenant_template_id);

create table if not exists auth.tenant_template_group_mapping
(
    created_at                       timestamptz default now()     not null,
    created_by                       text        default 'unknown' not null,
    tenant_template_group_mapping_id integer generated always as identity primary key,
    tenant_template_group_id         integer                       not null
        references auth.tenant_template_group on delete cascade,
    provider_code                    text
        references auth.provider (code) on update cascade on delete cascade,
    mapped_object_id                 text,
    mapped_object_name               text,
    mapped_role                      text,
    rule_id                          integer
        references auth.rule,  -- auth.delete_rule refuses a rule in use
    constraint tenant_template_group_mapping_created_by_check check (length(created_by) <= 250),
    -- a provider object/role, or a global rule, never both
    constraint tenant_template_group_mapping_rule_or_provider
        check ((rule_id is null and provider_code is not null
                    and (mapped_object_id is not null or mapped_role is not null))
            or (rule_id is not null and provider_code is null
                    and mapped_object_id is null and mapped_object_name is null and mapped_role is null))
);

create index if not exists ix_tenant_template_group_mapping_group
    on auth.tenant_template_group_mapping (tenant_template_group_id);

create index if not exists ix_tenant_template_group_mapping_rule
    on auth.tenant_template_group_mapping (rule_id)
    where rule_id is not null;

-- the default template: what create_tenant always created
insert into auth.tenant_template (created_by, updated_by, code, title, description)
select 'update_v2.24', 'update_v2.24', null, 'Default', 'Tenant Admins and Tenant Members'
where not exists(select from auth.tenant_template where code is null);

insert into auth.tenant_template_group (created_by, updated_by, tenant_template_id, code, title, is_system, perm_set_codes)
select 'update_v2.24', 'update_v2.24', tt.tenant_template_id, g.code, g.title, true, g.perm_set_codes
from auth.tenant_template tt
         cross join (values (1, 'tenant_admins', 'Tenant Admins', array ['tenant_admin']),
                            (2, 'tenant_members', 'Tenant Members', array ['tenant_member'])) g(seq, code, title, perm_set_codes)
where tt.code is null
  and not exists(select from auth.tenant_template_group x where x.tenant_template_id = tt.tenant_template_id)
order by g.seq;


/***
 *    error codes and events
 */

insert into const.event_code (event_id, code, category_code, is_system, source)
values (11013, 'tenant_template_created', 'tenant_event', true, 'core'),
       (11014, 'tenant_template_updated', 'tenant_event', true, 'core'),
       (11015, 'tenant_template_deleted', 'tenant_event', true, 'core'),
       (34009, 'err_tenant_template_not_found', 'tenant_error', true, 'core'),
       (34010, 'err_tenant_template_is_default', 'tenant_error', true, 'core'),
       (34011, 'err_tenant_template_value_missing', 'tenant_error', true, 'core'),
       (34012, 'err_tenant_template_placeholder_invalid', 'tenant_error', true, 'core'),
       (34013, 'err_tenant_template_already_exists', 'tenant_error', true, 'core'),
       (34014, 'err_tenant_template_item_not_found', 'tenant_error', true, 'core'),
       (34015, 'err_tenant_template_mapping_invalid', 'tenant_error', true, 'core')
on conflict do nothing;

insert into const.event_message (event_id, language_code, message_template)
values (11013, 'en', 'Tenant template "{template_title}" was created by {actor}'),
       (11014, 'en', 'Tenant template "{template_title}" was updated by {actor} ({change})'),
       (11015, 'en', 'Tenant template "{template_title}" was deleted by {actor}'),
       (34009, 'en', 'Tenant template "{template}" does not exist or is inactive'),
       (34010, 'en', 'The default tenant template can''t be deleted or disabled'),
       (34011, 'en', 'Tenant template placeholder {{placeholder}} has no value'),
       (34012, 'en', 'Unknown tenant template placeholder {{placeholder}}'),
       (34013, 'en', 'Tenant template "{code}" already exists'),
       (34014, 'en', 'Tenant template {item} (id: {id}) does not exist'),
       (34015, 'en', 'A template group mapping takes a provider object or role, or a global rule')
on conflict do nothing;

-- 34009: no such template (by id or code), or it is inactive
create or replace function error.raise_34009(_template text) returns void
    language plpgsql
as
$$
begin
    raise exception 'Tenant template "%" does not exist or is inactive', _template
        using errcode = '34009';
end;
$$;

-- 34010: the default template stays
create or replace function error.raise_34010() returns void
    language plpgsql
as
$$
begin
    raise exception 'The default tenant template can''t be deleted or disabled'
        using errcode = '34010';
end;
$$;

-- 34011: create_tenant has no value for a placeholder
create or replace function error.raise_34011(_placeholder text) returns void
    language plpgsql
as
$$
begin
    raise exception 'Tenant template placeholder {%} has no value', _placeholder
        using errcode = '34011';
end;
$$;

-- 34012: a placeholder other than {tenant.id}, {tenant.code} or {data.<path>}
create or replace function error.raise_34012(_placeholder text) returns void
    language plpgsql
as
$$
begin
    raise exception 'Unknown tenant template placeholder {%}; use {tenant.id}, {tenant.code} or {data.<path>}', _placeholder
        using errcode = '34012';
end;
$$;

-- 34013: the template code is taken
create or replace function error.raise_34013(_code text) returns void
    language plpgsql
as
$$
begin
    raise exception 'Tenant template "%" already exists', _code
        using errcode = '34013';
end;
$$;

-- 34014: no such template group or mapping
create or replace function error.raise_34014(_item text, _id integer) returns void
    language plpgsql
as
$$
begin
    raise exception 'Tenant template % (id: %) does not exist', _item, _id
        using errcode = '34014';
end;
$$;

-- 34015: a template mapping needs a provider object/role or a global rule, not both
create or replace function error.raise_34015() returns void
    language plpgsql
as
$$
begin
    raise exception 'A template group mapping takes a provider object or role, or a global rule'
        using errcode = '34015';
end;
$$;


/***
 *    permissions
 */

select unsecure.create_permission_as_system('Manage tenant templates', 'tenants', true, _source := 'core')
where not exists(select from auth.permission where full_code = 'tenants.manage_tenant_templates');
select unsecure.create_permission_as_system('Read tenant templates', 'tenants', true, _source := 'core')
where not exists(select from auth.permission where full_code = 'tenants.read_tenant_templates');

select unsecure.create_perm_set_permissions('update_v2.24', 1, null, ps.perm_set_id
    , array ['tenants.manage_tenant_templates', 'tenants.read_tenant_templates'], 1)
from auth.perm_set ps
where ps.tenant_id = 1
  and ps.code in ('system_admin', 'full_admin');


/***
 *    placeholders
 */

-- only {tenant.id}, {tenant.code} and {data.<path>}
create or replace function unsecure.validate_template_placeholders(_text text) returns void
    immutable
    language plpgsql
as
$$
declare
    __placeholder text;
begin
    for __placeholder in
        select m[1] from regexp_matches(coalesce(_text, ''), '\{([^{}]*)\}', 'g') m
    loop
        if __placeholder not in ('tenant.id', 'tenant.code')
            and __placeholder !~ '^data(\.[A-Za-z0-9_-]+)+$' then
            perform error.raise_34012(__placeholder);
        end if;
    end loop;
end;
$$;

-- fills in the placeholders; a missing, empty or non-scalar value raises 34011
create or replace function unsecure.resolve_template_placeholders(_text text, _tenant_id integer, _tenant_code text,
                                                                  _extra_data jsonb) returns text
    immutable
    language plpgsql
as
$$
declare
    __placeholder text;
    __value       text;
    __result      text := _text;
begin
    if _text is null then
        return null;
    end if;

    for __placeholder in
        select distinct m[1] from regexp_matches(_text, '\{([^{}]*)\}', 'g') m
    loop
        __value := case __placeholder
                       when 'tenant.id' then _tenant_id::text
                       when 'tenant.code' then _tenant_code
                       else (select case when jsonb_typeof(v.value) in ('string', 'number', 'boolean')
                                             then v.value #>> '{}' end
                             from (select _extra_data #> string_to_array(substr(__placeholder, 6), '.') as value) v)
            end;

        if __placeholder !~ '^(tenant\.(id|code)|data(\.[A-Za-z0-9_-]+)+)$' or coalesce(__value, '') = '' then
            perform error.raise_34011(__placeholder);
        end if;

        __result := replace(__result, '{' || __placeholder || '}', __value);
    end loop;

    return __result;
end;
$$;

-- the perm sets exist in tenant 1, and D-19: the editor holds their permissions there
create or replace function unsecure.validate_template_perm_sets(_user_id bigint, _correlation_id text,
                                                                _perm_set_codes text[]) returns void
    language plpgsql
as
$$
declare
    __missing text;
begin
    select c
    from unnest(_perm_set_codes) c
    where not exists(select from auth.perm_set ps where ps.tenant_id = 1 and ps.code = c)
    limit 1
    into __missing;

    if __missing is not null then
        perform error.raise_32004(__missing);
    end if;

    perform unsecure.validate_permissions_held(_user_id, _correlation_id
        , unsecure.get_perm_set_permission_codes(array(select ps.perm_set_id
                                                       from auth.perm_set ps
                                                       where ps.tenant_id = 1
                                                         and ps.code = any (_perm_set_codes)))
        , 1);
end;
$$;


/***
 *    templates
 */

create or replace function auth.create_tenant_template(_created_by text, _user_id bigint, _correlation_id text, _title text,
                                                       _code text default null, _description text default null)
    returns table(__tenant_template_id integer)
    rows 1
    language plpgsql
as
$$
declare
    __code                text := coalesce(_code, helpers.get_code(_title));
    ___tenant_template_id integer;
begin
    perform auth.has_permission(_user_id, _correlation_id, 'tenants.manage_tenant_templates', 1);

    if exists(select from auth.tenant_template tt where tt.code = __code) then
        perform error.raise_34013(__code);
    end if;

    insert into auth.tenant_template (created_by, updated_by, code, title, description)
    values (_created_by, _created_by, __code, _title, _description)
    returning tenant_template_id into ___tenant_template_id;

    perform public.create_journal_message_for_entity(_created_by, _user_id, _correlation_id
        , 11013  -- tenant_template_created
        , 'tenant_template', ___tenant_template_id
        , jsonb_build_object('template_title', _title, 'template_code', __code)
        , 1);

    return query select ___tenant_template_id;
end;
$$;

create or replace function auth.update_tenant_template(_updated_by text, _user_id bigint, _correlation_id text,
                                                       _tenant_template_id integer, _title text,
                                                       _description text default null,
                                                       _is_active boolean default true) returns void
    language plpgsql
as
$$
declare
    __code text;
begin
    perform auth.has_permission(_user_id, _correlation_id, 'tenants.manage_tenant_templates', 1);

    select tt.code
    from auth.tenant_template tt
    where tt.tenant_template_id = _tenant_template_id
    into __code;

    if not found then
        perform error.raise_34009(_tenant_template_id::text);
    end if;

    if __code is null and not coalesce(_is_active, true) then
        perform error.raise_34010();
    end if;

    update auth.tenant_template
    set title       = _title
      , description = _description
      , is_active   = coalesce(_is_active, true)
      , updated_by  = _updated_by
      , updated_at  = now()
    where tenant_template_id = _tenant_template_id;

    perform public.create_journal_message_for_entity(_updated_by, _user_id, _correlation_id
        , 11014  -- tenant_template_updated
        , 'tenant_template', _tenant_template_id
        , jsonb_build_object('template_title', _title, 'change', 'template_updated'
            , 'is_active', coalesce(_is_active, true))
        , 1);
end;
$$;

create or replace function auth.delete_tenant_template(_deleted_by text, _user_id bigint, _correlation_id text,
                                                       _tenant_template_id integer) returns void
    language plpgsql
as
$$
declare
    __code  text;
    __title text;
begin
    perform auth.has_permission(_user_id, _correlation_id, 'tenants.manage_tenant_templates', 1);

    select tt.code, tt.title
    from auth.tenant_template tt
    where tt.tenant_template_id = _tenant_template_id
    into __code, __title;

    if not found then
        perform error.raise_34009(_tenant_template_id::text);
    end if;

    if __code is null then
        perform error.raise_34010();
    end if;

    -- groups and mappings go with it; tenants created from it keep everything
    delete from auth.tenant_template where tenant_template_id = _tenant_template_id;

    perform public.create_journal_message_for_entity(_deleted_by, _user_id, _correlation_id
        , 11015  -- tenant_template_deleted
        , 'tenant_template', _tenant_template_id
        , jsonb_build_object('template_title', __title, 'template_code', __code)
        , 1);
end;
$$;

create or replace function auth.create_tenant_template_group(_created_by text, _user_id bigint, _correlation_id text,
                                                             _tenant_template_id integer, _title text,
                                                             _perm_set_codes text[] default null,
                                                             _code text default null,
                                                             _is_external boolean default false,
                                                             _is_assignable boolean default true)
    returns table(__tenant_template_group_id integer)
    rows 1
    language plpgsql
as
$$
declare
    __template_title            text;
    ___tenant_template_group_id integer;
begin
    perform auth.has_permission(_user_id, _correlation_id, 'tenants.manage_tenant_templates', 1);

    select tt.title
    from auth.tenant_template tt
    where tt.tenant_template_id = _tenant_template_id
    into __template_title;

    if not found then
        perform error.raise_34009(_tenant_template_id::text);
    end if;

    perform unsecure.validate_template_placeholders(_title);
    perform unsecure.validate_template_placeholders(_code);
    perform unsecure.validate_template_perm_sets(_user_id, _correlation_id, _perm_set_codes);

    insert into auth.tenant_template_group (created_by, updated_by, tenant_template_id, code, title, is_external,
                                            is_assignable, perm_set_codes)
    values (_created_by, _created_by, _tenant_template_id, _code, _title, coalesce(_is_external, false)
           , coalesce(_is_assignable, true), coalesce(_perm_set_codes, array []::text[]))
    returning tenant_template_group_id into ___tenant_template_group_id;

    perform public.create_journal_message_for_entity(_created_by, _user_id, _correlation_id
        , 11014  -- tenant_template_updated
        , 'tenant_template', _tenant_template_id
        , jsonb_build_object('template_title', __template_title, 'change', 'group_created'
            , 'group_title', _title, 'perm_set_codes', to_jsonb(_perm_set_codes))
        , 1);

    return query select ___tenant_template_group_id;
end;
$$;

create or replace function auth.update_tenant_template_group(_updated_by text, _user_id bigint, _correlation_id text,
                                                             _tenant_template_group_id integer, _title text,
                                                             _perm_set_codes text[] default null,
                                                             _code text default null,
                                                             _is_external boolean default false,
                                                             _is_assignable boolean default true) returns void
    language plpgsql
as
$$
declare
    __tenant_template_id integer;
    __template_title     text;
begin
    perform auth.has_permission(_user_id, _correlation_id, 'tenants.manage_tenant_templates', 1);

    select g.tenant_template_id, tt.title
    from auth.tenant_template_group g
             inner join auth.tenant_template tt on tt.tenant_template_id = g.tenant_template_id
    where g.tenant_template_group_id = _tenant_template_group_id
    into __tenant_template_id, __template_title;

    if not found then
        perform error.raise_34014('group', _tenant_template_group_id);
    end if;

    perform unsecure.validate_template_placeholders(_title);
    perform unsecure.validate_template_placeholders(_code);
    perform unsecure.validate_template_perm_sets(_user_id, _correlation_id, _perm_set_codes);

    update auth.tenant_template_group
    set title          = _title
      , code           = _code
      , is_external    = coalesce(_is_external, false)
      , is_assignable  = coalesce(_is_assignable, true)
      , perm_set_codes = coalesce(_perm_set_codes, array []::text[])
      , updated_by     = _updated_by
      , updated_at     = now()
    where tenant_template_group_id = _tenant_template_group_id;

    perform public.create_journal_message_for_entity(_updated_by, _user_id, _correlation_id
        , 11014  -- tenant_template_updated
        , 'tenant_template', __tenant_template_id
        , jsonb_build_object('template_title', __template_title, 'change', 'group_updated'
            , 'group_title', _title, 'perm_set_codes', to_jsonb(_perm_set_codes))
        , 1);
end;
$$;

create or replace function auth.delete_tenant_template_group(_deleted_by text, _user_id bigint, _correlation_id text,
                                                             _tenant_template_group_id integer) returns void
    language plpgsql
as
$$
declare
    __tenant_template_id integer;
    __template_title     text;
    __group_title        text;
begin
    perform auth.has_permission(_user_id, _correlation_id, 'tenants.manage_tenant_templates', 1);

    select g.tenant_template_id, tt.title, g.title
    from auth.tenant_template_group g
             inner join auth.tenant_template tt on tt.tenant_template_id = g.tenant_template_id
    where g.tenant_template_group_id = _tenant_template_group_id
    into __tenant_template_id, __template_title, __group_title;

    if not found then
        perform error.raise_34014('group', _tenant_template_group_id);
    end if;

    delete from auth.tenant_template_group where tenant_template_group_id = _tenant_template_group_id;

    perform public.create_journal_message_for_entity(_deleted_by, _user_id, _correlation_id
        , 11014  -- tenant_template_updated
        , 'tenant_template', __tenant_template_id
        , jsonb_build_object('template_title', __template_title, 'change', 'group_deleted'
            , 'group_title', __group_title)
        , 1);
end;
$$;

create or replace function auth.create_tenant_template_group_mapping(_created_by text, _user_id bigint, _correlation_id text,
                                                                     _tenant_template_group_id integer,
                                                                     _provider_code text default null,
                                                                     _mapped_object_id text default null,
                                                                     _mapped_object_name text default null,
                                                                     _mapped_role text default null,
                                                                     _rule_id integer default null)
    returns table(__tenant_template_group_mapping_id integer)
    rows 1
    language plpgsql
as
$$
declare
    __tenant_template_id                integer;
    __template_title                    text;
    __group_title                       text;
    ___tenant_template_group_mapping_id integer;
begin
    perform auth.has_permission(_user_id, _correlation_id, 'tenants.manage_tenant_templates', 1);

    select g.tenant_template_id, tt.title, g.title
    from auth.tenant_template_group g
             inner join auth.tenant_template tt on tt.tenant_template_id = g.tenant_template_id
    where g.tenant_template_group_id = _tenant_template_group_id
    into __tenant_template_id, __template_title, __group_title;

    if not found then
        perform error.raise_34014('group', _tenant_template_group_id);
    end if;

    if (_provider_code is null) = (_rule_id is null)
        or (_rule_id is not null
            and coalesce(_mapped_object_id, _mapped_object_name, _mapped_role) is not null) then
        perform error.raise_34015();
    end if;

    if _rule_id is not null then
        -- only global rules serve every tenant
        perform unsecure.validate_rule_in_tenant(_rule_id, null, _allows_global := true);
    else
        if _mapped_object_id is null and _mapped_role is null then
            perform error.raise_31004();
        end if;

        perform auth.validate_provider_allows_group_mapping(_provider_code);
        perform unsecure.validate_template_placeholders(_mapped_object_id);
        perform unsecure.validate_template_placeholders(_mapped_object_name);
        perform unsecure.validate_template_placeholders(_mapped_role);
    end if;

    insert into auth.tenant_template_group_mapping (created_by, tenant_template_group_id, provider_code, mapped_object_id,
                                                    mapped_object_name, mapped_role, rule_id)
    values (_created_by, _tenant_template_group_id, _provider_code, _mapped_object_id, _mapped_object_name
           , _mapped_role, _rule_id)
    returning tenant_template_group_mapping_id into ___tenant_template_group_mapping_id;

    perform public.create_journal_message_for_entity(_created_by, _user_id, _correlation_id
        , 11014  -- tenant_template_updated
        , 'tenant_template', __tenant_template_id
        , jsonb_build_object('template_title', __template_title, 'change', 'mapping_created'
            , 'group_title', __group_title, 'provider_code', _provider_code
            , 'mapped_object_id', _mapped_object_id, 'mapped_role', _mapped_role, 'rule_id', _rule_id)
        , 1);

    return query select ___tenant_template_group_mapping_id;
end;
$$;

create or replace function auth.delete_tenant_template_group_mapping(_deleted_by text, _user_id bigint, _correlation_id text,
                                                                     _tenant_template_group_mapping_id integer) returns void
    language plpgsql
as
$$
declare
    __tenant_template_id integer;
    __template_title     text;
    __group_title        text;
begin
    perform auth.has_permission(_user_id, _correlation_id, 'tenants.manage_tenant_templates', 1);

    select g.tenant_template_id, tt.title, g.title
    from auth.tenant_template_group_mapping m
             inner join auth.tenant_template_group g on g.tenant_template_group_id = m.tenant_template_group_id
             inner join auth.tenant_template tt on tt.tenant_template_id = g.tenant_template_id
    where m.tenant_template_group_mapping_id = _tenant_template_group_mapping_id
    into __tenant_template_id, __template_title, __group_title;

    if not found then
        perform error.raise_34014('mapping', _tenant_template_group_mapping_id);
    end if;

    delete
    from auth.tenant_template_group_mapping
    where tenant_template_group_mapping_id = _tenant_template_group_mapping_id;

    perform public.create_journal_message_for_entity(_deleted_by, _user_id, _correlation_id
        , 11014  -- tenant_template_updated
        , 'tenant_template', __tenant_template_id
        , jsonb_build_object('template_title', __template_title, 'change', 'mapping_deleted'
            , 'group_title', __group_title)
        , 1);
end;
$$;

-- every template with its groups and their mappings
create or replace function auth.get_tenant_templates(_user_id bigint, _correlation_id text)
    returns table(__tenant_template_id integer, __code text, __title text, __description text,
                  __is_active boolean, __is_default boolean, __groups jsonb)
    stable
    language plpgsql
as
$$
begin
    perform auth.has_permission(_user_id, _correlation_id, 'tenants.read_tenant_templates', 1);

    return query
        select tt.tenant_template_id
             , tt.code
             , tt.title
             , tt.description
             , tt.is_active
             , tt.code is null
             , coalesce((select jsonb_agg(jsonb_build_object(
                                     'tenant_template_group_id', g.tenant_template_group_id
                                 , 'code', coalesce(g.code, helpers.get_code(g.title))
                                 , 'title', g.title
                                 , 'is_external', g.is_external
                                 , 'is_assignable', g.is_assignable
                                 , 'is_system', g.is_system
                                 , 'perm_set_codes', to_jsonb(g.perm_set_codes)
                                 , 'mappings', coalesce((select jsonb_agg(jsonb_build_object(
                                                                    'tenant_template_group_mapping_id', m.tenant_template_group_mapping_id
                                                                , 'provider_code', m.provider_code
                                                                , 'mapped_object_id', m.mapped_object_id
                                                                , 'mapped_object_name', m.mapped_object_name
                                                                , 'mapped_role', m.mapped_role
                                                                , 'rule_id', m.rule_id
                                                                , 'rule_code', r.code)
                                                                order by m.tenant_template_group_mapping_id)
                                                         from auth.tenant_template_group_mapping m
                                                                  left join auth.rule r on r.rule_id = m.rule_id
                                                         where m.tenant_template_group_id = g.tenant_template_group_id)
                                     , '[]'::jsonb))
                                 order by g.tenant_template_group_id)
                         from auth.tenant_template_group g
                         where g.tenant_template_id = tt.tenant_template_id), '[]'::jsonb)
        from auth.tenant_template tt
        order by tt.code nulls first, tt.tenant_template_id;
end;
$$;


/***
 *    create_tenant runs the template
 */

drop function if exists auth.create_tenant(text, bigint, text, text, text, boolean, boolean, bigint, integer);

create or replace function auth.create_tenant(_created_by text, _user_id bigint, _correlation_id text, _title text,
                                              _code text default null, _is_removable boolean default true,
                                              _is_assignable boolean default true,
                                              _tenant_owner_id bigint default null, _tenant_id integer default 1,
                                              _template_code text default null, _extra_data jsonb default null)
    returns table(__tenant_id integer, __uuid uuid, __title text, __code text, __is_removable boolean,
                  __is_assignable boolean, __access_type_code text, __is_default boolean)
    rows 1
    language plpgsql
as
$$
declare
    __last_item          auth.tenant;
    __code               text;
    __tenant_template_id integer;
    __group              record;
    __mapping            record;
    ___user_group_id     integer;
    __perm_set_code      text;
    __copied             jsonb := '{}';  -- tenant-1 perm set code -> its copy's code
    __mapped_object_id   text;
    __mapped_object_name text;
    __mapped_role        text;
begin
    perform
        auth.has_permission(_user_id, _correlation_id, 'tenants.create_tenant', 1);  -- tenant 1 only

    -- no code = the default template
    select tt.tenant_template_id
    from auth.tenant_template tt
    where tt.is_active
      and tt.code is not distinct from _template_code
    into __tenant_template_id;

    if __tenant_template_id is null then
        perform error.raise_34009(coalesce(_template_code, 'default'));
    end if;

    __code := coalesce(_code, helpers.get_code(_title));

    -- Burn the code in the permanent identity ledger before creating the tenant.
    -- unique(code) makes any previously-used code (live, soft-deleted or purged)
    -- impossible to reuse; wrap the violation in a friendly error.
    begin
        insert into auth.tenant_identity (code, title, created_by)
        values (__code, _title, _created_by);
    exception when unique_violation then
        perform error.raise_34004(__code);
    end;

    insert into auth.tenant (created_by, updated_by, title, code, is_removable, is_assignable)
    values (_created_by, _created_by, _title, __code, _is_removable, _is_assignable)
    returning *
        into __last_item;

    -- Backfill the ledger with the real uuid + tenant_id now the row exists
    update auth.tenant_identity
    set uuid = __last_item.uuid, original_tenant_id = __last_item.tenant_id
    where code = __code;

    perform public.create_journal_message_for_entity(_created_by, _user_id, _correlation_id
        , 11001  -- tenant_created
        , 'tenant', __last_item.tenant_id
        , jsonb_build_object('tenant_title', __last_item.title, 'tenant_code', __last_item.code
            , 'is_assignable', _is_assignable, 'is_removable', _is_removable
            , 'template_code', _template_code, 'extra_data', _extra_data)
        , 1);

    -- the template: groups, their perm sets (copied from tenant 1) and mappings
    for __group in
        select g.*
        from auth.tenant_template_group g
        where g.tenant_template_id = __tenant_template_id
        order by g.tenant_template_group_id
    loop
        select ug.__user_group_id
        from unsecure.create_user_group(_created_by, _user_id, _correlation_id
                 , unsecure.resolve_template_placeholders(__group.title, __last_item.tenant_id, __last_item.code, _extra_data)
                 , __group.is_assignable, true, __group.is_external, __group.is_system
                 , _tenant_id := __last_item.tenant_id) ug
        into ___user_group_id;

        if __group.code is not null then
            update auth.user_group
            set code = unsecure.resolve_template_placeholders(__group.code, __last_item.tenant_id, __last_item.code, _extra_data)
            where user_group_id = ___user_group_id;
        end if;

        foreach __perm_set_code in array __group.perm_set_codes
        loop
            if not __copied ? __perm_set_code then
                __copied := __copied || jsonb_build_object(__perm_set_code
                    , (select ps.code
                       from unsecure.copy_perm_set(_created_by, _user_id, _correlation_id, __perm_set_code, 1
                                , __last_item.tenant_id) ps));
            end if;

            perform unsecure.assign_permission(_created_by, _user_id, _correlation_id
                , ___user_group_id, null, __copied ->> __perm_set_code, _tenant_id := __last_item.tenant_id);
        end loop;

        for __mapping in
            select m.*
            from auth.tenant_template_group_mapping m
            where m.tenant_template_group_id = __group.tenant_template_group_id
            order by m.tenant_template_group_mapping_id
        loop
            __mapped_object_id := lower(unsecure.resolve_template_placeholders(__mapping.mapped_object_id
                , __last_item.tenant_id, __last_item.code, _extra_data));
            __mapped_object_name := unsecure.resolve_template_placeholders(__mapping.mapped_object_name
                , __last_item.tenant_id, __last_item.code, _extra_data);
            __mapped_role := lower(unsecure.resolve_template_placeholders(__mapping.mapped_role
                , __last_item.tenant_id, __last_item.code, _extra_data));

            insert into auth.user_group_mapping (created_by, user_group_id, provider_code, mapped_object_id,
                                                 mapped_object_name, mapped_role, rule_id)
            values (_created_by, ___user_group_id, __mapping.provider_code, __mapped_object_id, __mapped_object_name
                   , __mapped_role, __mapping.rule_id);

            perform public.create_journal_message_for_entity(_created_by, _user_id, _correlation_id
                , 13020  -- group_mapping_created
                , 'group', ___user_group_id
                , jsonb_build_object('group_title', ___user_group_id::text
                    , 'mapping_name', coalesce(__mapped_object_name, __mapped_object_id, __mapped_role, 'rule')
                    , 'provider_code', __mapping.provider_code
                    , 'mapped_object_id', __mapped_object_id, 'mapped_role', __mapped_role
                    , 'rule_id', __mapping.rule_id)
                , __last_item.tenant_id);
        end loop;
    end loop;

    -- Owners hold the tenant's tenant_owner perm set (D-05), whatever the template
    if not __copied ? 'tenant_owner' then
        perform unsecure.copy_perm_set(_created_by, _user_id, _correlation_id, 'tenant_owner', 1
            , __last_item.tenant_id);
    end if;

    if
        (_tenant_owner_id is not null)
    then
        insert into auth.owner (created_by, tenant_id, user_group_id, user_id)
        values (_created_by, __last_item.tenant_id, null, _tenant_owner_id);

        perform public.create_journal_message_for_entity(_created_by, _user_id, _correlation_id
            , 11010  -- tenant_user_added
            , 'tenant', __last_item.tenant_id
            , jsonb_build_object('username', _tenant_owner_id::text, 'tenant_title', __last_item.title
                , 'user_group_id', null, 'action', 'owner_added')
            , __last_item.tenant_id);
    end if;

    return query
        select tenant_id
             , uuid
             , title
             , code
             , is_removable
             , is_assignable
             , access_type_code
             , is_default
        from auth.tenant
        where tenant_id = __last_item.tenant_id;
end;
$$;


/***
 *    tenant_created notification, for anything beyond the seed
 */

create or replace function triggers.notify_tenant_created() returns trigger
    language plpgsql
as
$$
begin
    perform unsecure.notify_permission_change(
        'tenant_created', NEW.tenant_id, 'tenant', NEW.tenant_id,
        jsonb_build_object('uuid', NEW.uuid, 'code', NEW.code));
    return NEW;
end;
$$;

drop trigger if exists trg_notify_tenant_created on auth.tenant;
create trigger trg_notify_tenant_created
    after insert
    on auth.tenant
    for each row
execute function triggers.notify_tenant_created();

/***
 *    changed functions
 */

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

    -- group mappings and tenant template mappings (v2.24)
    select (select count(*)
            from auth.user_group_mapping ugm
            where ugm.rule_id = _rule_id)
         + (select count(*)
            from auth.tenant_template_group_mapping ttm
            where ttm.rule_id = _rule_id)
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

select *
from public.stop_version_update('2.24', _component := 'postgresql_permissionmodel');
