/*
 * PostgreSQL Permissions Model — update v2.25
 * ===========================================
 *
 * Actions (D-13, step 6 of audit/design-d13-tenant-actions.md).
 *
 * One-shot steps that run when something happens to a user:
 *  - on_registration: the user is created (register_user, a new user in
 *    ensure_user_from_provider, a new user in ensure_user_info / sync).
 *    Fields: email, username, provider, claims; provider groups and roles
 *    arrive with the first login, so rules on them belong to on_entry.
 *  - on_entry: a login, at the end of ensure_groups_and_permissions (the
 *    provider groups and roles are fresh there) and of a successful
 *    create_user_login_attempt (password). run_once_per_user: only the first
 *    time (checked against the run log, so it reaches existing users too).
 *  - on_leave: the user is deleted (delete_user_info), for every tenant they
 *    were a member of. Leaving a single tenant waits for the remove_tenant_user
 *    decision; unsecure.run_actions already takes a tenant.
 *
 * auth.action: tenant_id (null = platform action), code, rule (validated like
 * every rule), event_code, run_once_per_user, sequence, is_active, the author.
 * auth.action_step: the invitation catalogue (const.invitation_action_type,
 * executors, conditions), plus the reverse steps remove_tenant_user,
 * remove_group_member, unassign_perm_set, unassign_permission. Payloads take
 * placeholders {tenant.id}, {tenant.code}, {user.id}, {user.email},
 * {user.username} and {data.<path>} (the event data: provider claims,
 * registration user data, create_tenant has its own).
 *
 * Runs (auth.action_run / action_run_step): database steps run right away
 * (a failure never breaks the login; a failed required step skips the rest);
 * backend and external steps wait with a filled-in payload for the app
 * (auth.get_pending_action_steps, complete_action_step, fail_action_step,
 * actions.process_action_steps in tenant 1, held by svc_authenticator) and are
 * notified as action_steps_pending. The run log keeps the username, so it
 * outlives a deleted user.
 *
 * Permissions: actions.create_action / update_action / delete_action /
 * read_actions in the tenant (tenant_admin, tenant_owner, system_admin,
 * full_admin); platform actions need actions.manage_platform_actions in
 * tenant 1 (full_admin) and take backend and external steps only.
 * D-19: the author must hold what the steps hand out or take away, checked on
 * every save (rule edits included); group steps respect platform groups.
 */

set search_path = public, const, ext, stage, helpers, internal, unsecure, auth, triggers;

select *
from public.start_version_update('2.25', 'Actions',
                                 _component := 'postgresql_permissionmodel',
                                 _description := 'Tenant and platform actions on_registration / on_entry / on_leave: a rule and steps from the invitation catalogue (plus reverse steps); database steps run at once, backend/external steps wait for the app; run log; D-19 on save; actions.* permissions.');


/***
 *    vocabulary
 */

create table if not exists const.action_event
(
    code text not null primary key
);

insert into const.action_event (code)
values ('on_registration'),
       ('on_entry'),
       ('on_leave')
on conflict do nothing;

-- the reverse steps, for on_leave
insert into const.invitation_action_type (code, executor_code, payload_schema, source)
values ('remove_tenant_user', 'database',
        '{"fields": {
            "tenant_id":      {"type": "integer", "required": true, "source": "invitation.tenant_id"},
            "target_user_id": {"type": "integer", "required": true, "source": "invitation.target_user_id"}
        }}'::jsonb, 'core'),
       ('remove_group_member', 'database',
        '{"fields": {
            "user_group_id":  {"type": "integer", "required": true, "source": null},
            "target_user_id": {"type": "integer", "required": true, "source": "invitation.target_user_id"},
            "tenant_id":      {"type": "integer", "required": true, "source": "invitation.tenant_id"}
        }}'::jsonb, 'core'),
       ('unassign_perm_set', 'database',
        '{"fields": {
            "perm_set_code":  {"type": "string",  "required": true, "source": null},
            "target_user_id": {"type": "integer", "required": true, "source": "invitation.target_user_id"},
            "tenant_id":      {"type": "integer", "required": true, "source": "invitation.tenant_id"}
        }}'::jsonb, 'core'),
       ('unassign_permission', 'database',
        '{"fields": {
            "permission_code": {"type": "string",  "required": true, "source": null},
            "target_user_id":  {"type": "integer", "required": true, "source": "invitation.target_user_id"},
            "tenant_id":       {"type": "integer", "required": true, "source": "invitation.tenant_id"}
        }}'::jsonb, 'core')
on conflict do nothing;

insert into public.translation (created_by, updated_by, language_code, data_group, data_object_code, context, value)
values ('system', 'system', 'en', 'invitation_action_type', 'remove_tenant_user', 'title', 'Remove User from Tenant'),
       ('system', 'system', 'en', 'invitation_action_type', 'remove_tenant_user', 'description', 'Removes the user from the Tenant Members group'),
       ('system', 'system', 'en', 'invitation_action_type', 'remove_group_member', 'title', 'Remove User from Group'),
       ('system', 'system', 'en', 'invitation_action_type', 'remove_group_member', 'description', 'Removes the user''s manual membership of a group'),
       ('system', 'system', 'en', 'invitation_action_type', 'unassign_perm_set', 'title', 'Unassign Permission Set'),
       ('system', 'system', 'en', 'invitation_action_type', 'unassign_perm_set', 'description', 'Removes a permission set assigned directly to the user'),
       ('system', 'system', 'en', 'invitation_action_type', 'unassign_permission', 'title', 'Unassign Permission'),
       ('system', 'system', 'en', 'invitation_action_type', 'unassign_permission', 'description', 'Removes a permission assigned directly to the user')
on conflict do nothing;


/***
 *    tables
 */

create table if not exists auth.action
(
    created_at        timestamptz default now()     not null,
    created_by        text        default 'unknown' not null,
    updated_at        timestamptz default now()     not null,
    updated_by        text        default 'unknown' not null,
    action_id         integer generated always as identity primary key,
    tenant_id         integer
        references auth.tenant on delete cascade,  -- null = a platform action
    code              text                          not null,
    title             text                          not null,
    description       text,
    event_code        text                          not null
        references const.action_event,
    rule              jsonb                         not null,
    run_once_per_user boolean     default false     not null,
    sequence          integer     default 0         not null,
    is_active         boolean     default true      not null,
    author_user_id    bigint,  -- who saved it last; database steps act on their behalf
    constraint action_created_by_check check (length(created_by) <= 250),
    constraint action_updated_by_check check (length(updated_by) <= 250)
);

create unique index if not exists uq_action_code
    on auth.action (coalesce(tenant_id, 0), code);

create index if not exists ix_action_event
    on auth.action (event_code)
    where is_active;

create table if not exists auth.action_step
(
    created_at       timestamptz default now()     not null,
    created_by       text        default 'unknown' not null,
    updated_at       timestamptz default now()     not null,
    updated_by       text        default 'unknown' not null,
    action_step_id   integer generated always as identity primary key,
    action_id        integer                       not null
        references auth.action on delete cascade,
    sequence         integer     default 0         not null,
    step_type_code   text                          not null
        references const.invitation_action_type,
    executor_code    text                          not null
        references const.invitation_executor,
    condition_code   text        default 'always'  not null
        references const.invitation_condition,
    is_required      boolean     default true      not null,
    payload_template jsonb       default '{}'      not null,
    constraint action_step_created_by_check check (length(created_by) <= 250),
    constraint action_step_updated_by_check check (length(updated_by) <= 250)
);

create index if not exists ix_action_step_action on auth.action_step (action_id);

create table if not exists auth.action_run
(
    created_at    timestamptz default now()     not null,
    created_by    text        default 'unknown' not null,
    updated_at    timestamptz default now()     not null,
    updated_by    text        default 'unknown' not null,
    action_run_id bigint generated always as identity primary key,
    action_id     integer                       not null
        references auth.action on delete cascade,
    tenant_id     integer
        references auth.tenant on delete cascade,
    user_id       bigint                        not null,  -- no foreign key: the log outlives the user
    username      text,
    event_code    text                          not null
        references const.action_event,
    status_code   text                          not null
        references const.invitation_action_status,
    extra_data    jsonb,
    completed_at  timestamptz,
    constraint action_run_created_by_check check (length(created_by) <= 250),
    constraint action_run_updated_by_check check (length(updated_by) <= 250)
);

create index if not exists ix_action_run_action_user on auth.action_run (action_id, user_id);
create index if not exists ix_action_run_user on auth.action_run (user_id);
create index if not exists ix_action_run_tenant on auth.action_run (tenant_id);

create table if not exists auth.action_run_step
(
    created_at         timestamptz default now()     not null,
    created_by         text        default 'unknown' not null,
    updated_at         timestamptz default now()     not null,
    updated_by         text        default 'unknown' not null,
    action_run_step_id bigint generated always as identity primary key,
    action_run_id      bigint                        not null
        references auth.action_run on delete cascade,
    action_step_id     integer
        references auth.action_step on delete set null,
    sequence           integer                       not null,
    step_type_code     text                          not null,
    executor_code      text                          not null,
    is_required        boolean                       not null,
    status_code        text                          not null
        references const.invitation_action_status,
    payload            jsonb,
    result_data        jsonb,
    error_message      text,
    completed_at       timestamptz,
    constraint action_run_step_created_by_check check (length(created_by) <= 250),
    constraint action_run_step_updated_by_check check (length(updated_by) <= 250)
);

create index if not exists ix_action_run_step_run on auth.action_run_step (action_run_id);
create index if not exists ix_action_run_step_pending
    on auth.action_run_step (action_run_step_id)
    where status_code = 'processing';


/***
 *    error codes and events
 */

insert into const.event_category (category_code, range_start, range_end, is_error, source)
values ('action_event', 24001, 24999, false, 'core'),
       ('action_error', 41001, 41999, true, 'core')
on conflict do nothing;

insert into const.event_code (event_id, code, category_code, is_system, source)
values (24001, 'action_created', 'action_event', true, 'core'),
       (24002, 'action_updated', 'action_event', true, 'core'),
       (24003, 'action_deleted', 'action_event', true, 'core'),
       (24004, 'action_step_failed', 'action_event', true, 'core'),
       (41001, 'err_action_not_found', 'action_error', true, 'core'),
       (41002, 'err_action_already_exists', 'action_error', true, 'core'),
       (41003, 'err_action_invalid', 'action_error', true, 'core'),
       (41004, 'err_action_run_step_not_pending', 'action_error', true, 'core'),
       (41005, 'err_action_value_missing', 'action_error', true, 'core')
on conflict do nothing;

insert into const.event_message (event_id, language_code, message_template)
values (24001, 'en', 'Action "{action_title}" was created by {actor}'),
       (24002, 'en', 'Action "{action_title}" was updated by {actor} ({change})'),
       (24003, 'en', 'Action "{action_title}" was deleted by {actor}'),
       (24004, 'en', 'Step "{step_type}" of action "{action_title}" failed: {error_message}'),
       (41001, 'en', 'Action {item} (id: {id}) does not exist'),
       (41002, 'en', 'Action "{code}" already exists'),
       (41003, 'en', 'Action is not valid: {reason}'),
       (41004, 'en', 'Action run step (id: {id}) is not waiting for a result'),
       (41005, 'en', 'Action placeholder {{placeholder}} has no value')
on conflict do nothing;

-- 41001: no such action, step or run step (in this tenant)
create or replace function error.raise_41001(_item text, _id bigint) returns void
    language plpgsql
as
$$
begin
    raise exception 'Action % (id: %) does not exist', _item, _id
        using errcode = '41001';
end;
$$;

-- 41002: the action code is taken in the tenant
create or replace function error.raise_41002(_code text) returns void
    language plpgsql
as
$$
begin
    raise exception 'Action "%" already exists', _code
        using errcode = '41002';
end;
$$;

-- 41003: an action or step that can't be saved; the message says why
create or replace function error.raise_41003(_reason text) returns void
    language plpgsql
as
$$
begin
    raise exception 'Action is not valid: %', _reason
        using errcode = '41003';
end;
$$;

-- 41004: the app reports a step that isn't waiting
create or replace function error.raise_41004(_action_run_step_id bigint) returns void
    language plpgsql
as
$$
begin
    raise exception 'Action run step (id: %) is not waiting for a result', _action_run_step_id
        using errcode = '41004';
end;
$$;

-- 41005: a payload placeholder without a value at run time
create or replace function error.raise_41005(_placeholder text) returns void
    language plpgsql
as
$$
begin
    raise exception 'Action placeholder {%} has no value', _placeholder
        using errcode = '41005';
end;
$$;


/***
 *    permissions
 */

select unsecure.create_permission_as_system('Actions', '', false, _source := 'core')
where not exists(select from auth.permission where full_code = 'actions');
select unsecure.create_permission_as_system('Create action', 'actions', true, _source := 'core')
where not exists(select from auth.permission where full_code = 'actions.create_action');
select unsecure.create_permission_as_system('Update action', 'actions', true, _source := 'core')
where not exists(select from auth.permission where full_code = 'actions.update_action');
select unsecure.create_permission_as_system('Delete action', 'actions', true, _source := 'core')
where not exists(select from auth.permission where full_code = 'actions.delete_action');
select unsecure.create_permission_as_system('Read actions', 'actions', true, _source := 'core')
where not exists(select from auth.permission where full_code = 'actions.read_actions');
select unsecure.create_permission_as_system('Manage platform actions', 'actions', true, _source := 'core')
where not exists(select from auth.permission where full_code = 'actions.manage_platform_actions');
select unsecure.create_permission_as_system('Process action steps', 'actions', true, _source := 'core')
where not exists(select from auth.permission where full_code = 'actions.process_action_steps');

-- tenant actions: tenant admins and owners of every tenant, the admins of tenant 1
select unsecure.create_perm_set_permissions('update_v2.25', 1, null, ps.perm_set_id
    , array ['actions.create_action', 'actions.update_action', 'actions.delete_action', 'actions.read_actions'], ps.tenant_id)
from auth.perm_set ps
where ps.code in ('tenant_admin', 'tenant_owner')
   or (ps.tenant_id = 1 and ps.code in ('system_admin', 'full_admin'));

-- platform actions: full_admin only
select unsecure.create_perm_set_permissions('update_v2.25', 1, null, ps.perm_set_id
    , array ['actions.manage_platform_actions'], 1)
from auth.perm_set ps
where ps.tenant_id = 1
  and ps.code = 'full_admin';

-- the app's worker for backend and external steps; logins run the actions
select unsecure.create_perm_set_permissions('update_v2.25', 1, null, ps.perm_set_id
    , array ['actions.process_action_steps'], 1)
from auth.perm_set ps
where ps.tenant_id = 1
  and ps.code in ('svc_authenticator_permissions', 'system_admin', 'full_admin');


/***
 *    placeholders
 */

-- {tenant.id}, {tenant.code}, {user.id}, {user.email}, {user.username}, {data.<path>} in any string of the payload
create or replace function unsecure.validate_action_placeholders(_payload jsonb) returns void
    immutable
    language plpgsql
as
$$
declare
    __placeholder text;
begin
    for __placeholder in
        select m[1] from regexp_matches(coalesce(_payload, '{}'::jsonb)::text, '\{([^{}"]+)\}', 'g') m
    loop
        if __placeholder !~ '^(tenant\.(id|code)|user\.(id|email|username)|data(\.[A-Za-z0-9_-]+)+)$' then
            perform error.raise_41003(format('unknown placeholder {%s}', __placeholder));
        end if;
    end loop;
end;
$$;

-- fills in the placeholders from _context {tenant, user, data}; a missing, empty or non-scalar value raises 41005
create or replace function unsecure.resolve_action_placeholders(_payload jsonb, _context jsonb) returns jsonb
    immutable
    language plpgsql
as
$$
declare
    __placeholder text;
    __value       jsonb;
    __escaped     text;
    __result      text := coalesce(_payload, '{}'::jsonb)::text;
begin
    for __placeholder in
        select distinct m[1] from regexp_matches(__result, '\{([^{}"]+)\}', 'g') m
    loop
        __value := _context #> string_to_array(__placeholder, '.');

        if __value is null or jsonb_typeof(__value) not in ('string', 'number', 'boolean')
            or coalesce(__value #>> '{}', '') = '' then
            perform error.raise_41005(__placeholder);
        end if;

        -- the value as the inside of a json string
        __escaped := to_jsonb(__value #>> '{}')::text;
        __escaped := substr(__escaped, 2, length(__escaped) - 2);
        __result := replace(__result, '{' || __placeholder || '}', __escaped);
    end loop;

    return __result::jsonb;
end;
$$;


/***
 *    validation
 */

-- a step can be saved: known type and condition, required fields, platform
-- actions without database steps, objects of the tenant, and D-19 (the author
-- holds what the step hands out or takes away). Returns the executor.
create or replace function unsecure.validate_action_step(_user_id bigint, _correlation_id text, _tenant_id integer,
                                                         _step_type_code text, _condition_code text,
                                                         _payload jsonb) returns text
    language plpgsql
as
$$
declare
    __type     const.invitation_action_type;
    __field    text;
    __codes    text[];
    __group_id integer;
begin
    select *
    from const.invitation_action_type t
    where t.code = _step_type_code
      and t.is_active
    into __type;

    if __type.code is null then
        perform error.raise_41003(format('unknown step type "%s"', _step_type_code));
    end if;

    if not exists(select from const.invitation_condition c where c.code = _condition_code) then
        perform error.raise_41003(format('unknown condition "%s"', _condition_code));
    end if;

    perform unsecure.validate_action_placeholders(_payload);

    -- fields the action has to supply (no source to fill them from)
    for __field in
        select f.key
        from jsonb_each(coalesce(__type.payload_schema -> 'fields', '{}'::jsonb)) f
        where (f.value ->> 'required')::boolean
          and f.value ->> 'source' is null
    loop
        if not coalesce(_payload, '{}'::jsonb) ? __field then
            perform error.raise_41003(format('step "%s" needs "%s"', _step_type_code, __field));
        end if;
    end loop;

    if __type.executor_code <> 'database' then
        return __type.executor_code;
    end if;

    if _tenant_id is null then
        perform error.raise_41003('a platform action takes backend and external steps only');
    end if;

    case _step_type_code
        when 'add_group_member', 'remove_group_member' then
            __group_id := (_payload ->> 'user_group_id')::integer;
            perform unsecure.validate_user_group_access(_user_id, _correlation_id, __group_id, _tenant_id);
            perform unsecure.validate_user_group_permissions_held(_user_id, _correlation_id, __group_id, _tenant_id);
        when 'assign_perm_set', 'unassign_perm_set' then
            if not exists(select from auth.perm_set ps where ps.tenant_id = _tenant_id and ps.code = _payload ->> 'perm_set_code') then
                perform error.raise_32004(_payload ->> 'perm_set_code');
            end if;
            __codes := unsecure.get_grant_permission_codes(_payload ->> 'perm_set_code', null, _tenant_id);
        when 'assign_permission', 'unassign_permission' then
            if not exists(select from auth.permission p where p.full_code = ext.text2ltree(_payload ->> 'permission_code')) then
                perform error.raise_41003(format('unknown permission "%s"', _payload ->> 'permission_code'));
            end if;
            __codes := unsecure.get_permission_codes(array [_payload ->> 'permission_code']);
        when 'add_tenant_user', 'remove_tenant_user' then
            __codes := unsecure.get_user_group_permission_codes(
                    (select ug.user_group_id
                     from auth.user_group ug
                     where ug.tenant_id = _tenant_id
                       and ug.code = 'tenant_members'));
        else
            null;  -- resource access is checked against the author when the step runs
    end case;

    perform unsecure.validate_permissions_held(_user_id, _correlation_id, __codes, _tenant_id);

    return __type.executor_code;
end;
$$;

-- the action exists where the caller works and the caller may change it there;
-- platform actions only from tenant 1 with actions.manage_platform_actions
create or replace function unsecure.validate_action_access(_user_id bigint, _correlation_id text, _action_id integer,
                                                           _perm_code text, _tenant_id integer) returns void
    language plpgsql
as
$$
declare
    __action_tenant_id integer;
begin
    select a.tenant_id
    from auth.action a
    where a.action_id = _action_id
    into __action_tenant_id;

    if not found then
        perform error.raise_41001('action', _action_id);
    end if;

    if __action_tenant_id is null then
        if _tenant_id is distinct from 1 then
            perform error.raise_41001('action', _action_id);
        end if;
        perform auth.has_permission(_user_id, _correlation_id, 'actions.manage_platform_actions', 1);
    else
        perform auth.has_permission(_user_id, _correlation_id, _perm_code, _tenant_id);
        if __action_tenant_id <> _tenant_id then
            perform error.raise_41001('action', _action_id);
        end if;
    end if;
end;
$$;


/***
 *    actions and steps
 */

create or replace function auth.create_action(_created_by text, _user_id bigint, _correlation_id text, _title text,
                                              _event_code text, _rule jsonb, _code text default null,
                                              _description text default null,
                                              _run_once_per_user boolean default false,
                                              _sequence integer default 0, _is_platform boolean default false,
                                              _tenant_id integer default 1)
    returns table(__action_id integer)
    rows 1
    language plpgsql
as
$$
declare
    __code      text    := coalesce(_code, helpers.get_code(_title));
    __tenant_id integer := case when _is_platform then null else _tenant_id end;
    ___action_id integer;
begin
    if _is_platform then
        perform auth.has_permission(_user_id, _correlation_id, 'actions.manage_platform_actions', 1);
    else
        perform auth.has_permission(_user_id, _correlation_id, 'actions.create_action', _tenant_id);
    end if;

    if not exists(select from const.action_event e where e.code = _event_code) then
        perform error.raise_41003(format('unknown event "%s"', _event_code));
    end if;

    perform unsecure.validate_rule(_rule);

    if exists(select from auth.action a where a.tenant_id is not distinct from __tenant_id and a.code = __code) then
        perform error.raise_41002(__code);
    end if;

    insert into auth.action (created_by, updated_by, tenant_id, code, title, description, event_code, rule,
                             run_once_per_user, sequence, author_user_id)
    values (_created_by, _created_by, __tenant_id, __code, _title, _description, _event_code, _rule
           , coalesce(_run_once_per_user, false), coalesce(_sequence, 0), _user_id)
    returning action_id into ___action_id;

    perform public.create_journal_message_for_entity(_created_by, _user_id, _correlation_id
        , 24001  -- action_created
        , 'action', ___action_id
        , jsonb_build_object('action_title', _title, 'action_code', __code, 'event_code', _event_code
            , 'is_platform', coalesce(_is_platform, false), 'rule', _rule)
        , coalesce(__tenant_id, 1));

    return query select ___action_id;
end;
$$;

create or replace function auth.update_action(_updated_by text, _user_id bigint, _correlation_id text, _action_id integer,
                                              _title text, _rule jsonb, _description text default null,
                                              _run_once_per_user boolean default false, _sequence integer default 0,
                                              _is_active boolean default true, _tenant_id integer default 1) returns void
    language plpgsql
as
$$
declare
    __action auth.action;
    __step   record;
begin
    perform unsecure.validate_action_access(_user_id, _correlation_id, _action_id, 'actions.update_action', _tenant_id);
    perform unsecure.validate_rule(_rule);

    select * from auth.action a where a.action_id = _action_id into __action;

    -- D-19: a new rule hands the steps out to other users, so the editor must hold them all
    for __step in
        select s.step_type_code, s.condition_code, s.payload_template
        from auth.action_step s
        where s.action_id = _action_id
    loop
        perform unsecure.validate_action_step(_user_id, _correlation_id, __action.tenant_id
            , __step.step_type_code, __step.condition_code, __step.payload_template);
    end loop;

    update auth.action
    set title             = _title
      , rule              = _rule
      , description       = _description
      , run_once_per_user = coalesce(_run_once_per_user, false)
      , sequence          = coalesce(_sequence, 0)
      , is_active         = coalesce(_is_active, true)
      , author_user_id    = _user_id
      , updated_by        = _updated_by
      , updated_at        = now()
    where action_id = _action_id;

    perform public.create_journal_message_for_entity(_updated_by, _user_id, _correlation_id
        , 24002  -- action_updated
        , 'action', _action_id
        , jsonb_build_object('action_title', _title, 'change', 'action_updated'
            , 'old_rule', __action.rule, 'new_rule', _rule, 'is_active', coalesce(_is_active, true))
        , coalesce(__action.tenant_id, 1));
end;
$$;

create or replace function auth.delete_action(_deleted_by text, _user_id bigint, _correlation_id text, _action_id integer,
                                              _tenant_id integer default 1) returns void
    language plpgsql
as
$$
declare
    __action auth.action;
begin
    perform unsecure.validate_action_access(_user_id, _correlation_id, _action_id, 'actions.delete_action', _tenant_id);

    select * from auth.action a where a.action_id = _action_id into __action;

    -- the steps and the run log go with it
    delete from auth.action where action_id = _action_id;

    perform public.create_journal_message_for_entity(_deleted_by, _user_id, _correlation_id
        , 24003  -- action_deleted
        , 'action', _action_id
        , jsonb_build_object('action_title', __action.title, 'action_code', __action.code, 'rule', __action.rule)
        , coalesce(__action.tenant_id, 1));
end;
$$;

create or replace function auth.create_action_step(_created_by text, _user_id bigint, _correlation_id text,
                                                   _action_id integer, _step_type_code text,
                                                   _payload_template jsonb default '{}',
                                                   _condition_code text default 'always',
                                                   _sequence integer default 0, _is_required boolean default true,
                                                   _tenant_id integer default 1)
    returns table(__action_step_id integer)
    rows 1
    language plpgsql
as
$$
declare
    __action          auth.action;
    __executor_code   text;
    ___action_step_id integer;
begin
    perform unsecure.validate_action_access(_user_id, _correlation_id, _action_id, 'actions.update_action', _tenant_id);

    select * from auth.action a where a.action_id = _action_id into __action;

    __executor_code := unsecure.validate_action_step(_user_id, _correlation_id, __action.tenant_id
        , _step_type_code, coalesce(_condition_code, 'always'), coalesce(_payload_template, '{}'::jsonb));

    insert into auth.action_step (created_by, updated_by, action_id, sequence, step_type_code, executor_code,
                                  condition_code, is_required, payload_template)
    values (_created_by, _created_by, _action_id, coalesce(_sequence, 0), _step_type_code, __executor_code
           , coalesce(_condition_code, 'always'), coalesce(_is_required, true), coalesce(_payload_template, '{}'::jsonb))
    returning action_step_id into ___action_step_id;

    update auth.action
    set author_user_id = _user_id
      , updated_by     = _created_by
      , updated_at     = now()
    where action_id = _action_id;

    perform public.create_journal_message_for_entity(_created_by, _user_id, _correlation_id
        , 24002  -- action_updated
        , 'action', _action_id
        , jsonb_build_object('action_title', __action.title, 'change', 'step_created'
            , 'step_type', _step_type_code, 'payload_template', _payload_template)
        , coalesce(__action.tenant_id, 1));

    return query select ___action_step_id;
end;
$$;

create or replace function auth.update_action_step(_updated_by text, _user_id bigint, _correlation_id text,
                                                   _action_step_id integer, _payload_template jsonb,
                                                   _condition_code text default 'always',
                                                   _sequence integer default 0, _is_required boolean default true,
                                                   _tenant_id integer default 1) returns void
    language plpgsql
as
$$
declare
    __step   auth.action_step;
    __action auth.action;
begin
    select * from auth.action_step s where s.action_step_id = _action_step_id into __step;

    if __step.action_step_id is null then
        perform error.raise_41001('step', _action_step_id);
    end if;

    perform unsecure.validate_action_access(_user_id, _correlation_id, __step.action_id, 'actions.update_action', _tenant_id);

    select * from auth.action a where a.action_id = __step.action_id into __action;

    perform unsecure.validate_action_step(_user_id, _correlation_id, __action.tenant_id
        , __step.step_type_code, coalesce(_condition_code, 'always'), coalesce(_payload_template, '{}'::jsonb));

    update auth.action_step
    set payload_template = coalesce(_payload_template, '{}'::jsonb)
      , condition_code   = coalesce(_condition_code, 'always')
      , sequence         = coalesce(_sequence, 0)
      , is_required      = coalesce(_is_required, true)
      , updated_by       = _updated_by
      , updated_at       = now()
    where action_step_id = _action_step_id;

    update auth.action
    set author_user_id = _user_id
      , updated_by     = _updated_by
      , updated_at     = now()
    where action_id = __step.action_id;

    perform public.create_journal_message_for_entity(_updated_by, _user_id, _correlation_id
        , 24002  -- action_updated
        , 'action', __step.action_id
        , jsonb_build_object('action_title', __action.title, 'change', 'step_updated'
            , 'step_type', __step.step_type_code, 'payload_template', _payload_template)
        , coalesce(__action.tenant_id, 1));
end;
$$;

create or replace function auth.delete_action_step(_deleted_by text, _user_id bigint, _correlation_id text,
                                                   _action_step_id integer, _tenant_id integer default 1) returns void
    language plpgsql
as
$$
declare
    __step   auth.action_step;
    __action auth.action;
begin
    select * from auth.action_step s where s.action_step_id = _action_step_id into __step;

    if __step.action_step_id is null then
        perform error.raise_41001('step', _action_step_id);
    end if;

    perform unsecure.validate_action_access(_user_id, _correlation_id, __step.action_id, 'actions.update_action', _tenant_id);

    select * from auth.action a where a.action_id = __step.action_id into __action;

    delete from auth.action_step where action_step_id = _action_step_id;

    perform public.create_journal_message_for_entity(_deleted_by, _user_id, _correlation_id
        , 24002  -- action_updated
        , 'action', __step.action_id
        , jsonb_build_object('action_title', __action.title, 'change', 'step_deleted'
            , 'step_type', __step.step_type_code)
        , coalesce(__action.tenant_id, 1));
end;
$$;

-- the tenant's actions with their steps; from tenant 1 also the platform actions
-- (with actions.manage_platform_actions)
create or replace function auth.get_actions(_user_id bigint, _correlation_id text, _tenant_id integer default 1)
    returns table(__action_id integer, __tenant_id integer, __code text, __title text, __description text,
                  __event_code text, __rule jsonb, __run_once_per_user boolean, __sequence integer,
                  __is_active boolean, __is_platform boolean, __steps jsonb)
    stable
    language plpgsql
as
$$
declare
    __sees_platform boolean;
begin
    perform auth.has_permission(_user_id, _correlation_id, 'actions.read_actions', _tenant_id);

    __sees_platform := _tenant_id = 1
        and auth.has_permission(_user_id, _correlation_id, 'actions.manage_platform_actions', 1, _throw_err := false);

    return query
        select a.action_id
             , a.tenant_id
             , a.code
             , a.title
             , a.description
             , a.event_code
             , a.rule
             , a.run_once_per_user
             , a.sequence
             , a.is_active
             , a.tenant_id is null
             , coalesce((select jsonb_agg(jsonb_build_object(
                                     'action_step_id', s.action_step_id
                                 , 'sequence', s.sequence
                                 , 'step_type_code', s.step_type_code
                                 , 'executor_code', s.executor_code
                                 , 'condition_code', s.condition_code
                                 , 'is_required', s.is_required
                                 , 'payload_template', s.payload_template)
                                 order by s.sequence, s.action_step_id)
                         from auth.action_step s
                         where s.action_id = a.action_id), '[]'::jsonb)
        from auth.action a
        where a.tenant_id = _tenant_id
           or (__sees_platform and a.tenant_id is null)
        order by a.tenant_id nulls first, a.sequence, a.action_id;
end;
$$;


/***
 *    running
 */

-- one run of an action for a user: database steps now, backend and external
-- steps wait for the app; a failed required step skips the rest
create or replace function unsecure.run_action(_created_by text, _user_id bigint, _correlation_id text, _action_id integer,
                                               _target_user_id bigint, _extra_data jsonb default null) returns bigint
    language plpgsql
as
$$
declare
    __action        auth.action;
    __tenant_code   text;
    __user          record;
    __run_id        bigint;
    __run_step_id   bigint;
    __step          record;
    __context       jsonb;
    __payload       jsonb;
    __error         text;
    __is_failed     boolean := false;
    __is_pending    boolean := false;
begin
    select * from auth.action a where a.action_id = _action_id into __action;
    select t.code from auth.tenant t where t.tenant_id = __action.tenant_id into __tenant_code;
    select ui.user_id, ui.username, ui.email from auth.user_info ui where ui.user_id = _target_user_id into __user;

    insert into auth.action_run (created_by, updated_by, action_id, tenant_id, user_id, username, event_code,
                                 status_code, extra_data)
    values (_created_by, _created_by, _action_id, __action.tenant_id, _target_user_id, __user.username
           , __action.event_code, 'processing', _extra_data)
    returning action_run_id into __run_id;

    __context := jsonb_build_object(
            'tenant', jsonb_build_object('id', __action.tenant_id, 'code', __tenant_code),
            'user', jsonb_build_object('id', __user.user_id, 'email', __user.email, 'username', __user.username),
            'data', coalesce(_extra_data, '{}'::jsonb));

    for __step in
        select s.*
        from auth.action_step s
        where s.action_id = _action_id
        order by s.sequence, s.action_step_id
    loop
        insert into auth.action_run_step (created_by, updated_by, action_run_id, action_step_id, sequence,
                                          step_type_code, executor_code, is_required, status_code, payload)
        values (_created_by, _created_by, __run_id, __step.action_step_id, __step.sequence, __step.step_type_code
               , __step.executor_code, __step.is_required, case when __is_failed then 'skipped' else 'pending' end
               , __step.payload_template)
        returning action_run_step_id into __run_step_id;

        if __is_failed then
            continue;
        end if;

        begin
            __payload := unsecure.resolve_action_payload(__step.step_type_code
                , unsecure.resolve_action_placeholders(__step.payload_template, __context)
                , jsonb_build_object('tenant_id', __action.tenant_id
                    , 'target_user_id', __user.user_id
                    , 'target_email', __user.email
                    , 'inviter_user_id', __action.author_user_id));

            if not unsecure.evaluate_invitation_condition(__step.condition_code, __user.user_id, __action.tenant_id, __payload) then
                update auth.action_run_step
                set status_code = 'skipped', payload = __payload, completed_at = now()
                where action_run_step_id = __run_step_id;
                continue;
            end if;

            if __step.executor_code = 'database' then
                -- on behalf of the author (D-19 was checked against them on save)
                perform unsecure.execute_database_action(_created_by, coalesce(__action.author_user_id, _user_id)
                    , _correlation_id, null, null, __user.user_id, __step.step_type_code, __payload
                    , __action.tenant_id);

                update auth.action_run_step
                set status_code = 'completed', payload = __payload, completed_at = now()
                where action_run_step_id = __run_step_id;
            else
                update auth.action_run_step
                set status_code = 'processing', payload = __payload
                where action_run_step_id = __run_step_id;

                __is_pending := true;
            end if;
        exception
            when others then
                get stacked diagnostics __error = message_text;

                update auth.action_run_step
                set status_code = 'failed', error_message = __error, completed_at = now()
                where action_run_step_id = __run_step_id;

                perform public.create_journal_message_for_entity(_created_by, _user_id, _correlation_id
                    , 24004  -- action_step_failed
                    , 'action', _action_id
                    , jsonb_build_object('action_title', __action.title, 'step_type', __step.step_type_code
                        , 'error_message', __error, 'target_user_id', _target_user_id, 'action_run_id', __run_id)
                    , coalesce(__action.tenant_id, 1));

                if __step.is_required then
                    __is_failed := true;
                end if;
        end;
    end loop;

    update auth.action_run
    set status_code  = case when __is_failed then 'failed' when __is_pending then 'processing' else 'completed' end
      , completed_at = case when __is_failed or not __is_pending then now() end
    where action_run_id = __run_id;

    if __is_pending then
        perform unsecure.notify_permission_change('action_steps_pending', __action.tenant_id, 'user', _target_user_id
            , jsonb_build_object('action_run_id', __run_id, 'action_code', __action.code));
    end if;

    return __run_id;
end;
$$;

-- runs the active actions of an event whose rule matches the user: platform
-- actions first, then by tenant, sequence and id. on_leave with no tenant
-- covers every tenant the user is a member of (call it before the removal).
-- Nothing here raises: a failing action is journaled and the event goes on.
create or replace function unsecure.run_actions(_created_by text, _user_id bigint, _correlation_id text, _event_code text,
                                                _target_user_id bigint, _provider_code text default null,
                                                _tenant_id integer default null, _extra_data jsonb default null) returns void
    language plpgsql
as
$$
declare
    __subject jsonb;
    __action  record;
    __error   text;
begin
    select unsecure.get_rule_subject(ui.user_id, coalesce(_provider_code, ui.last_used_provider_code))
    from auth.user_info ui
    where ui.user_id = _target_user_id
    into __subject;

    if __subject is null then
        return;
    end if;

    for __action in
        select a.action_id, a.title, a.tenant_id, a.rule, a.run_once_per_user
        from auth.action a
                 left join auth.tenant t on t.tenant_id = a.tenant_id
        where a.is_active
          and a.event_code = _event_code
          and (a.tenant_id is null
            or (t.deleted_at is null
                and case
                        when _tenant_id is not null then a.tenant_id = _tenant_id
                        when _event_code = 'on_leave' then exists(select
                                                                  from auth.tenant_memberships tm
                                                                  where tm.tenant_id = a.tenant_id
                                                                    and tm.user_id = _target_user_id)
                        else true
                    end))
        order by a.tenant_id nulls first, a.sequence, a.action_id
    loop
        if __action.run_once_per_user
            and exists(select from auth.action_run r where r.action_id = __action.action_id and r.user_id = _target_user_id) then
            continue;
        end if;

        if not unsecure.evaluate_rule(__action.rule, __subject) then
            continue;
        end if;

        begin
            perform unsecure.run_action(_created_by, _user_id, _correlation_id, __action.action_id, _target_user_id
                , _extra_data);
        exception
            when others then
                get stacked diagnostics __error = message_text;
                perform public.create_journal_message_for_entity(_created_by, _user_id, _correlation_id
                    , 24004  -- action_step_failed
                    , 'action', __action.action_id
                    , jsonb_build_object('action_title', __action.title, 'step_type', null
                        , 'error_message', __error, 'target_user_id', _target_user_id)
                    , coalesce(__action.tenant_id, 1));
        end;
    end loop;
end;
$$;


/***
 *    the app's side: pending steps, results, the run log
 */

create or replace function auth.get_pending_action_steps(_user_id bigint, _correlation_id text,
                                                         _target_user_id bigint default null)
    returns table(__action_run_step_id bigint, __action_run_id bigint, __action_code text, __tenant_id integer,
                  __target_user_id bigint, __step_type_code text, __executor_code text, __sequence integer,
                  __payload jsonb)
    stable
    language plpgsql
as
$$
begin
    perform auth.has_permission(_user_id, _correlation_id, 'actions.process_action_steps', 1);

    return query
        select s.action_run_step_id
             , r.action_run_id
             , a.code
             , r.tenant_id
             , r.user_id
             , s.step_type_code
             , s.executor_code
             , s.sequence
             , s.payload
        from auth.action_run_step s
                 inner join auth.action_run r on r.action_run_id = s.action_run_id
                 inner join auth.action a on a.action_id = r.action_id
        where s.status_code = 'processing'
          and (_target_user_id is null or r.user_id = _target_user_id)
        order by s.action_run_step_id;
end;
$$;

-- a step is done (or failed); the run follows: failed when a required step
-- failed, processing while a step waits, completed otherwise
create or replace function unsecure.finish_action_run_step(_updated_by text, _user_id bigint, _correlation_id text,
                                                           _action_run_step_id bigint, _is_success boolean,
                                                           _result_data jsonb, _error_message text) returns void
    language plpgsql
as
$$
declare
    __run_step record;
begin
    select s.action_run_step_id, s.action_run_id, s.status_code, s.step_type_code, r.user_id, r.action_id,
           a.title, a.tenant_id
    from auth.action_run_step s
             inner join auth.action_run r on r.action_run_id = s.action_run_id
             inner join auth.action a on a.action_id = r.action_id
    where s.action_run_step_id = _action_run_step_id
    into __run_step;

    if __run_step.action_run_step_id is null then
        perform error.raise_41001('run step', _action_run_step_id);
    end if;

    if __run_step.status_code <> 'processing' then
        perform error.raise_41004(_action_run_step_id);
    end if;

    update auth.action_run_step
    set status_code   = case when _is_success then 'completed' else 'failed' end
      , result_data   = _result_data
      , error_message = _error_message
      , completed_at  = now()
      , updated_by    = _updated_by
      , updated_at    = now()
    where action_run_step_id = _action_run_step_id;

    if not _is_success then
        perform public.create_journal_message_for_entity(_updated_by, _user_id, _correlation_id
            , 24004  -- action_step_failed
            , 'action', __run_step.action_id
            , jsonb_build_object('action_title', __run_step.title, 'step_type', __run_step.step_type_code
                , 'error_message', coalesce(_error_message, 'unknown'), 'target_user_id', __run_step.user_id
                , 'action_run_id', __run_step.action_run_id)
            , coalesce(__run_step.tenant_id, 1));
    end if;

    update auth.action_run r
    set status_code  = x.status_code
      , completed_at = case when x.status_code <> 'processing' then now() end
      , updated_by   = _updated_by
      , updated_at   = now()
    from (select case
                     when bool_or(s.status_code = 'failed' and s.is_required) then 'failed'
                     when bool_or(s.status_code in ('pending', 'processing')) then 'processing'
                     else 'completed'
                     end as status_code
          from auth.action_run_step s
          where s.action_run_id = __run_step.action_run_id) x
    where r.action_run_id = __run_step.action_run_id;
end;
$$;

create or replace function auth.complete_action_step(_updated_by text, _user_id bigint, _correlation_id text,
                                                     _action_run_step_id bigint, _result_data jsonb default null) returns void
    language plpgsql
as
$$
begin
    perform auth.has_permission(_user_id, _correlation_id, 'actions.process_action_steps', 1);
    perform unsecure.finish_action_run_step(_updated_by, _user_id, _correlation_id, _action_run_step_id, true
        , _result_data, null);
end;
$$;

create or replace function auth.fail_action_step(_updated_by text, _user_id bigint, _correlation_id text,
                                                 _action_run_step_id bigint, _error_message text default null) returns void
    language plpgsql
as
$$
begin
    perform auth.has_permission(_user_id, _correlation_id, 'actions.process_action_steps', 1);
    perform unsecure.finish_action_run_step(_updated_by, _user_id, _correlation_id, _action_run_step_id, false
        , null, _error_message);
end;
$$;

-- the tenant's runs, newest first; from tenant 1 also the platform runs
-- (with actions.manage_platform_actions)
create or replace function auth.get_action_runs(_user_id bigint, _correlation_id text, _target_user_id bigint default null,
                                                _action_id integer default null, _tenant_id integer default 1,
                                                _page_size integer default 100)
    returns table(__action_run_id bigint, __action_id integer, __action_code text, __tenant_id integer,
                  __user_id bigint, __username text, __event_code text, __status_code text, __extra_data jsonb,
                  __created_at timestamptz, __completed_at timestamptz, __steps jsonb)
    stable
    language plpgsql
as
$$
declare
    __sees_platform boolean;
begin
    perform auth.has_permission(_user_id, _correlation_id, 'actions.read_actions', _tenant_id);

    __sees_platform := _tenant_id = 1
        and auth.has_permission(_user_id, _correlation_id, 'actions.manage_platform_actions', 1, _throw_err := false);

    return query
        select r.action_run_id
             , r.action_id
             , a.code
             , r.tenant_id
             , r.user_id
             , r.username
             , r.event_code
             , r.status_code
             , r.extra_data
             , r.created_at
             , r.completed_at
             , coalesce((select jsonb_agg(jsonb_build_object(
                                     'action_run_step_id', s.action_run_step_id
                                 , 'sequence', s.sequence
                                 , 'step_type_code', s.step_type_code
                                 , 'executor_code', s.executor_code
                                 , 'status_code', s.status_code
                                 , 'payload', s.payload
                                 , 'result_data', s.result_data
                                 , 'error_message', s.error_message
                                 , 'completed_at', s.completed_at)
                                 order by s.sequence, s.action_run_step_id)
                         from auth.action_run_step s
                         where s.action_run_id = r.action_run_id), '[]'::jsonb)
        from auth.action_run r
                 inner join auth.action a on a.action_id = r.action_id
        where (r.tenant_id = _tenant_id or (__sees_platform and r.tenant_id is null))
          and (_target_user_id is null or r.user_id = _target_user_id)
          and (_action_id is null or r.action_id = _action_id)
        order by r.action_run_id desc
        limit coalesce(_page_size, 100);
end;
$$;

/***
 *    the events fire the actions; the executor gets the reverse steps
 */

create or replace function unsecure.execute_database_action(
    _updated_by            text,
    _user_id               bigint,
    _correlation_id        text,
    _invitation_action_id  bigint,
    _invitation_id         bigint,
    _target_user_id        bigint,
    _action_type_code      text,
    _payload               jsonb,
    _tenant_id             integer
) returns void
    language plpgsql
as
$$
declare
    ___group_id integer;
    ___perm_set_code text;
    ___permission_full_code text;
    ___resource_type text;
    ___resource_id jsonb;
    ___access_flags text[];
begin
    case _action_type_code
        when 'add_tenant_user' then
            -- membership is computed (D-03): join the tenant's Tenant Members group
            select ug.user_group_id
            from auth.user_group ug
            where ug.tenant_id = _tenant_id
              and ug.code = 'tenant_members'
            into ___group_id;

            if ___group_id is null then
                perform error.raise_34008(_tenant_id);
            end if;

            if not exists(select from auth.user_group_member
                          where user_group_id = ___group_id and user_id = _target_user_id and mapping_id is null) then
                perform unsecure.create_user_group_member(
                    _updated_by, _user_id, _correlation_id,
                    ___group_id, _target_user_id, _tenant_id
                );
            end if;

        when 'add_group_member' then
            ___group_id := (_payload->>'user_group_id')::integer;
            perform unsecure.create_user_group_member(
                _updated_by, _user_id, _correlation_id,
                ___group_id, _target_user_id, _tenant_id
            );

        when 'assign_perm_set' then
            ___perm_set_code := _payload->>'perm_set_code';
            perform unsecure.assign_permission(
                _updated_by, _user_id, _correlation_id,
                null, _target_user_id, ___perm_set_code, null, _tenant_id
            );

        when 'assign_permission' then
            ___permission_full_code := _payload->>'permission_code';
            perform unsecure.assign_permission(
                _updated_by, _user_id, _correlation_id,
                null, _target_user_id, null, ___permission_full_code, _tenant_id
            );

        when 'assign_resource_access' then
            ___resource_type := _payload->>'resource_type';
            ___resource_id := _payload->'resource_id';
            ___access_flags := array(select jsonb_array_elements_text(_payload->'access_flags'));
            if ___access_flags is null or array_length(___access_flags, 1) is null then
                ___access_flags := array['read'];
            end if;
            perform auth.assign_resource_access(
                _updated_by, _user_id, _correlation_id,
                ___resource_type, ___resource_id,
                _target_user_id, null, ___access_flags, _tenant_id
            );

        -- the reverse steps (v2.25, actions on_leave): only what was given directly
        when 'remove_tenant_user' then
            delete
            from auth.user_group_member ugm
                using auth.user_group ug
            where ug.user_group_id = ugm.user_group_id
              and ug.tenant_id = _tenant_id
              and ug.code = 'tenant_members'
              and ugm.user_id = _target_user_id
              and ugm.member_type_code = 'manual';

        when 'remove_group_member' then
            delete
            from auth.user_group_member ugm
            where ugm.user_group_id = (_payload->>'user_group_id')::integer
              and ugm.user_id = _target_user_id
              and ugm.member_type_code = 'manual';

        when 'unassign_perm_set' then
            perform unsecure.unassign_permission(_updated_by, _user_id, _correlation_id, pa.assignment_id, _tenant_id)
            from auth.permission_assignment pa
                     inner join auth.perm_set ps on ps.perm_set_id = pa.perm_set_id
            where pa.user_id = _target_user_id
              and pa.tenant_id = _tenant_id
              and ps.code = _payload->>'perm_set_code';

        when 'unassign_permission' then
            perform unsecure.unassign_permission(_updated_by, _user_id, _correlation_id, pa.assignment_id, _tenant_id)
            from auth.permission_assignment pa
                     inner join auth.permission p on p.permission_id = pa.permission_id
            where pa.user_id = _target_user_id
              and pa.tenant_id = _tenant_id
              and p.full_code = ext.text2ltree(_payload->>'permission_code');

        else
            -- Unknown database action type — treat as no-op
            null;
    end case;
end;
$$;

create or replace function auth.register_user(_created_by text, _user_id bigint, _correlation_id text, _email text, _password_hash text, _display_name text, _user_data jsonb DEFAULT NULL::jsonb, _request_context jsonb DEFAULT NULL::jsonb, _tenant_id integer default 1)
    returns TABLE(__user_id bigint, __code text, __uuid text, __username text, __email text, __display_name text)
    rows 1
    language plpgsql
as
$$
declare
	__normalized_email text;
	__new_user         auth.user_info;
begin

	perform
		auth.has_permission(_user_id, _correlation_id, 'users.register_user', _tenant_id);

	__normalized_email := lower(trim(_email));

	perform
		auth.validate_provider_is_active('email');

	-- An email identity with this address, or any user with this username, means the
	-- address is taken. Both raise 33007 so the caller cannot tell which one it was.
	if
		exists(
						select
						from auth.user_identity ui
						where ui.provider_code = 'email'
							and ui.uid = __normalized_email
			)
		or exists(
						select
						from auth.user_info u
						where u.username = __normalized_email
			) then
		perform error.raise_52102(__normalized_email);
	end if;

	select *
	from unsecure.create_user_info(_created_by, _user_id, _correlation_id, _email, _email, _display_name,
																 'email')
	into __new_user;

	perform unsecure.create_user_identity(_created_by, _user_id, _correlation_id, __new_user.user_id
		, 'email', __normalized_email, __normalized_email, _password_hash, _is_active := true);

	perform
		auth.update_user_data(_created_by, _user_id, _correlation_id, __new_user.user_id, 'email', _user_data);

	perform unsecure.create_user_event(_created_by, _user_id, _correlation_id, 'user_registered',
		__new_user.user_id,
		_request_context := _request_context,
		_event_data := jsonb_build_object('email', __normalized_email, 'provider', 'email'));

	-- actions (v2.25)
	perform unsecure.run_actions(_created_by, _user_id, _correlation_id, 'on_registration', __new_user.user_id
		, 'email', _extra_data := _user_data);

	return query
		select __new_user.user_id
				 , __new_user.code
				 , __new_user.uuid::text
				 , __new_user.username
				 , __new_user.email
				 , __new_user.display_name;
end;
$$;

create or replace function auth.ensure_user_from_provider(_created_by text, _user_id bigint, _correlation_id text, _provider_code text, _provider_uid text, _provider_oid text, _username text, _display_name text, _email text DEFAULT NULL::text, _user_data jsonb DEFAULT NULL::jsonb, _request_context jsonb DEFAULT NULL::jsonb)
    returns TABLE(__user_id bigint, __code text, __uuid text, __username text, __email text, __display_name text
		, __event_id integer, __outcome_code text, __user_event_id bigint)
    rows 1
    language plpgsql
as
$$
declare
	__target_user_id   bigint;
	__identity_uid     text;
	___username        text;
	___display_name    text;
	___email           text;
	__identity_data    jsonb;
	__check            record;
	___user_event_id   bigint;
	___claim_user_id   bigint;
begin

	if
		lower(_provider_code) = 'email' then
		perform error.raise_52101(_username);
	end if;

	perform
		auth.validate_provider_is_active(_provider_code);

	select uid.user_id, uid.uid, u.username, u.display_name, u.email, uid.user_data
	from auth.user_identity uid
				 inner join auth.user_info u on uid.user_id = u.user_id
	where uid.provider_code = _provider_code
		and (uid.uid = _provider_uid or uid.provider_oid = _provider_oid)
	into __target_user_id, __identity_uid, ___username, ___display_name, ___email, __identity_data;

	-- variant B: a user pre-provisioned for this provider who has never logged in
	-- (no identities at all) is claimed by the first login with the same username
	if __target_user_id is null then
		select ui.user_id
		from auth.user_info ui
		where ui.username = lower(trim(_username))
			and ui.last_used_provider_code = _provider_code
			and not exists(select from auth.user_identity uid where uid.user_id = ui.user_id)
		into ___claim_user_id;

		if ___claim_user_id is not null then
			perform unsecure.create_user_identity(_created_by, _user_id, _correlation_id, ___claim_user_id
				, _provider_code, _provider_uid, _provider_oid, _user_data := _user_data::text
				, _is_active := true, _is_verified := true);

			perform public.create_journal_message_for_entity(_created_by, _user_id, _correlation_id
				, 10031  -- identity_updated
				, 'user', ___claim_user_id
				, jsonb_build_object('provider_code', _provider_code, 'provider_uid', _provider_uid
					, 'action', 'pre_provisioned_user_claimed')
				, 1);

			select uid.user_id, uid.uid, u.username, u.display_name, u.email, uid.user_data
			from auth.user_identity uid
												 inner join auth.user_info u on uid.user_id = u.user_id
			where uid.provider_code = _provider_code
						and (uid.uid = _provider_uid or uid.provider_oid = _provider_oid)
			into __target_user_id, __identity_uid, ___username, ___display_name, ___email, __identity_data;
		end if;
	end if;

	-- variant A: identity pre-created by object id, first login fills in the uid
	if __target_user_id is not null and __identity_uid is null then
		update auth.user_identity
		set uid         = _provider_uid
			, is_verified = true
			, updated_by  = _created_by
			, updated_at  = now()
		where user_id = __target_user_id
			and provider_code = _provider_code
			and provider_oid = _provider_oid
			and uid is null;

		__identity_uid := _provider_uid;

		perform public.create_journal_message_for_entity(_created_by, _user_id, _correlation_id
			, 10031  -- identity_updated
			, 'user', __target_user_id
			, jsonb_build_object('provider_code', _provider_code, 'provider_uid', _provider_uid
				, 'action', 'pre_provisioned_identity_claimed')
			, 1);
	end if;

	if
		__target_user_id is null then
		-- check blacklist by provider identity (primary check for OAuth users)
		if unsecure.check_user_blacklist(
			_provider_code := _provider_code,
			_provider_uid := _provider_uid,
			_provider_oid := _provider_oid
		) then
			perform error.raise_33019(_provider_code, coalesce(_provider_uid, _provider_oid));
		end if;

		-- never attach a new identity to an existing user by username (v2.4),
		-- except the pre-provisioned claim above (v2.18)
		if exists(select from auth.user_info where username = lower(trim(_username))) then
			select e.__user_event_id
			from unsecure.create_user_event(_created_by, _user_id, _correlation_id, 'user_login_failed', null
				, _request_context := _request_context
				, _event_data := jsonb_build_object('provider', _provider_code, 'provider_uid', _provider_uid
					, 'username', lower(trim(_username)), 'reason', 'username_taken')) e
			into ___user_event_id;

			return query select null::bigint, null::text, null::text, null::text, null::text, null::text
				, 33024, 'err_username_already_exists', ___user_event_id;
			return;
		end if;

		select user_id
		from unsecure.create_user_info(_created_by, _user_id, _correlation_id, lower(_username), lower(_email), _display_name,
																	 _provider_code)
		into __target_user_id;

		perform
			unsecure.create_user_identity(_created_by, _user_id, _correlation_id, __target_user_id
				, _provider_code, _provider_uid, _provider_oid, _user_data := _user_data::text
				, _is_active := true, _is_verified := true);

		perform unsecure.create_user_event(_created_by, _user_id, _correlation_id, 'user_registered',
			__target_user_id,
			_request_context := _request_context,
			_event_data := jsonb_build_object('provider', _provider_code, 'provider_uid', _provider_uid));

		-- actions (v2.25); on_entry runs in ensure_groups_and_permissions, with the provider groups
		perform unsecure.run_actions(_created_by, _user_id, _correlation_id, 'on_registration', __target_user_id
			, _provider_code, _extra_data := _user_data);
	else
		select * from unsecure.check_user_can_login(__target_user_id, _provider_code, __identity_uid) into __check;

		if __check.__event_id is not null then
			select e.__user_event_id
			from unsecure.create_user_event(_created_by, _user_id, _correlation_id, 'user_login_failed', __target_user_id
				, _request_context := _request_context
				, _event_data := jsonb_build_object('provider', _provider_code, 'provider_uid', _provider_uid
					, 'reason', __check.__reason)) e
			into ___user_event_id;

			return query select null::bigint, null::text, null::text, null::text, null::text, null::text
				, __check.__event_id, __check.__outcome_code, ___user_event_id;
			return;
		end if;

		-- update provider_oid
		perform unsecure.update_user_identity_uid_oid(_created_by, _user_id, _correlation_id, __target_user_id
			, _provider_code, _provider_uid
			, _provider_oid);

		-- update basic user data coming from the provider
		if
			(trim(lower(_username)) <> ___username
				or _display_name <> ___display_name
				or lower(trim(_email)) is distinct from ___email) then
			perform unsecure.update_user_info_basic_data(_created_by, _user_id, _correlation_id, __target_user_id, _username, _display_name,
																									 _email);
		end if;

		-- refresh the provider data snapshot; null means the caller sent nothing, keep what is stored
		if _user_data is not null and _user_data is distinct from __identity_data then
			update auth.user_identity
			set user_data  = _user_data
				, updated_by = _created_by
				, updated_at = now()
			where user_id = __target_user_id
				and provider_code = _provider_code
				and uid = _provider_uid;

			perform public.create_journal_message_for_entity(_created_by, _user_id, _correlation_id
				, 10031  -- identity_updated
				, 'user', __target_user_id
				, jsonb_build_object('provider_code', _provider_code
					, 'user_data_keys', case when jsonb_typeof(_user_data) = 'object'
						then (select array_agg(k) from jsonb_object_keys(_user_data) k) end)
				, 1);
		end if;
	end if;

	-- clean all previous uids for the same provider for given user
	delete
	from auth.user_identity
	where user_id = __target_user_id
		and provider_code = _provider_code
		and uid <> _provider_uid;

	perform
		unsecure.update_last_used_provider(__target_user_id, _provider_code);

	select e.__user_event_id
	from unsecure.create_user_event(_created_by, _user_id, _correlation_id, 'user_logged_in', __target_user_id
		, _request_context := _request_context
		, _event_data := jsonb_build_object('provider', _provider_code, 'provider_uid', _provider_uid)) e
	into ___user_event_id;

	return query
		select ui.user_id
				 , ui.code
				 , ui.uuid::text
				 , ui.username
				 , ui.email
				 , ui.display_name
				 , 10010
				 , 'user_logged_in'
				 , ___user_event_id
		from auth.user_identity uid
					 inner join auth.user_info ui on uid.user_id = ui.user_id
		where uid.provider_code = _provider_code
			and uid.uid = _provider_uid;
end;
$$;

create or replace function unsecure.ensure_user_info(_created_by text, _user_id bigint, _correlation_id text, _username text, _display_name text, _provider_code text default null, _email text default null, _user_data jsonb default null, _provider_oid text default null)
    returns table(__user_id bigint, __code text, __uuid text, __username text, __email text, __display_name text)
    language plpgsql
as
$$
declare
	__last_id      bigint;
	__username     text;
	__oid_user_id  bigint;
	__is_new       boolean := false;
begin

	__username := trim(lower(_username));

	select u.user_id
	from auth.user_info u
	where u.username = __username
	into __last_id;

	if
		__last_id is null then
		select user_id
		from unsecure.create_user_info(_created_by, _user_id, _correlation_id, __username, lower(_email), _display_name,
																	 _provider_code)
		into __last_id;

		__is_new := true;
	end if;

	-- variant A: pre-create the identity by the provider's object id; the first
	-- login matches it by oid and fills in the uid
	if _provider_code is not null and _provider_oid is not null then
		select uid.user_id
		from auth.user_identity uid
		where uid.provider_oid = _provider_oid
		into __oid_user_id;

		if __oid_user_id is not null and __oid_user_id <> __last_id then
			perform error.raise_33007(_provider_oid);
		end if;

		if __oid_user_id is null
			and not exists(select from auth.user_identity
										 where user_id = __last_id and provider_code = _provider_code) then
			perform unsecure.create_user_identity(_created_by, _user_id, _correlation_id, __last_id
				, _provider_code, null, _provider_oid
				, _is_active := true, _is_verified := false);
		end if;
	end if;

	-- actions (v2.25)
	if __is_new then
		perform unsecure.run_actions(_created_by, _user_id, _correlation_id, 'on_registration', __last_id
			, _provider_code, _extra_data := _user_data);
	end if;

	return query
		select ui.user_id
				 , ui.code
				 , ui.uuid::text
				 , ui.username
				 , ui.email
				 , ui.display_name
		from auth.user_info ui
		where ui.user_id = __last_id;
end;
$$;

create or replace function auth.ensure_groups_and_permissions(_created_by text, _user_id bigint, _correlation_id text, _target_user_id bigint, _provider_code text, _provider_groups text[] DEFAULT NULL::text[], _provider_roles text[] DEFAULT NULL::text[], _tenant_id integer DEFAULT 1)
    returns TABLE(__tenant_id integer, __tenant_uuid uuid, __groups text[], __permissions text[], __short_code_permissions text[])
    rows 1
    language plpgsql
as
$$
begin
    perform
        auth.has_permission(_user_id, _correlation_id, 'authentication.ensure_permissions', _tenant_id);

    update auth.user_identity
    set updated_by      = _created_by
      , updated_at      = now()
      , provider_groups = _provider_groups
      , provider_roles  = _provider_roles
    where provider_code = _provider_code
      and user_id = _target_user_id;

    drop table if exists __temp_users_groups;  -- callable more than once per transaction

    create temporary table __temp_users_groups on commit drop as
    select ug.__tenant_id       as tenant_id
         , ug.__user_group_id   as user_group_id
         , ug.__user_group_code as user_group_code
    from unsecure.recalculate_user_groups(_created_by
             , _target_user_id
             , _provider_code
             ) ug;

    -- actions (v2.25): the login, with fresh provider groups and roles; the claims are the event data
    perform unsecure.run_actions(_created_by, _user_id, _correlation_id, 'on_entry', _target_user_id
        , _provider_code
        , _extra_data := (select uid.user_data
                          from auth.user_identity uid
                          where uid.user_id = _target_user_id
                            and uid.provider_code = _provider_code
                          order by uid.updated_at desc
                          limit 1));

    return query
        select up.__tenant_id
             , up.__tenant_uuid
             , up.__groups
             , up.__permissions
             , up.__short_code_permissions
        from unsecure.recalculate_user_permissions(_created_by
                 , _target_user_id, null) up;
end;
$$;

create or replace function auth.create_user_login_attempt(_created_by text, _user_id bigint, _correlation_id text, _provider_code text, _provider_uid text, _target_user_id bigint, _is_credential_valid boolean, _request_context jsonb DEFAULT NULL::jsonb, _tenant_id integer default 1)
    returns TABLE(__event_id integer, __outcome_code text, __user_event_id bigint, __failed_login_count integer, __max_failed_attempts integer, __locked_until timestamp with time zone)
    rows 1
    language plpgsql
as
$$
declare
	__uid            text;
	__check          record;
	__state          record;
	___user_event_id bigint;
begin
	perform
		auth.has_permission(_user_id, _correlation_id, 'authentication.create_user_login_attempt', _tenant_id);

	__uid := case when lower(_provider_code) = 'email' then lower(trim(_provider_uid)) else _provider_uid end;

	if _target_user_id is null then
		select e.__user_event_id
		from unsecure.create_user_event(_created_by, _user_id, _correlation_id, 'user_login_failed', null
			, _request_context := _request_context
			, _event_data := jsonb_build_object('provider', _provider_code, 'provider_uid', __uid, 'reason', 'user_not_found')) e
		into ___user_event_id;

		return query select 33001, 'err_user_not_found', ___user_event_id, null::integer, null::integer, null::timestamptz;
		return;
	end if;

	select * from unsecure.check_user_can_login(_target_user_id, _provider_code, __uid) into __check;

	if __check.__event_id is not null then
		-- attempts while locked are logged but not counted, so a lock cannot escalate while it runs
		select e.__user_event_id
		from unsecure.create_user_event(_created_by, _user_id, _correlation_id, 'user_login_failed', _target_user_id
			, _request_context := _request_context
			, _event_data := jsonb_build_object('provider', _provider_code, 'provider_uid', __uid, 'reason', __check.__reason)) e
		into ___user_event_id;

		return query select __check.__event_id, __check.__outcome_code, ___user_event_id, null::integer, null::integer, __check.__locked_until;
		return;
	end if;

	if _is_credential_valid is distinct from true then
		select e.__user_event_id
		from unsecure.create_user_event(_created_by, _user_id, _correlation_id, 'user_login_failed', _target_user_id
			, _request_context := _request_context
			, _event_data := jsonb_build_object('provider', _provider_code, 'provider_uid', __uid
				, 'reason', case when _is_credential_valid is null then 'credential_missing' else 'wrong_password' end)) e
		into ___user_event_id;

		select * from unsecure.update_user_login_state(_created_by, _target_user_id, false) into __state;

		if __state.__is_lockout_triggered then
			perform unsecure.create_user_event(_created_by, _user_id, _correlation_id, 'user_auto_locked', _target_user_id
				, _request_context := _request_context
				, _event_data := jsonb_build_object('failed_login_count', __state.__failed_login_count
					, 'locked_until', __state.__locked_until));

			return query select 33004, 'err_user_locked', ___user_event_id, __state.__failed_login_count
				, __state.__max_failed_attempts, __state.__locked_until;
			return;
		end if;

		return query select 33001, 'err_user_not_found', ___user_event_id, __state.__failed_login_count
			, __state.__max_failed_attempts, null::timestamptz;
		return;
	end if;

	select * from unsecure.update_user_login_state(_created_by, _target_user_id, true) into __state;

	perform
		unsecure.update_last_used_provider(_target_user_id, _provider_code);

	select e.__user_event_id
	from unsecure.create_user_event(_created_by, _user_id, _correlation_id, 'user_logged_in', _target_user_id
		, _request_context := _request_context
		, _event_data := jsonb_build_object('provider', _provider_code, 'provider_uid', __uid)) e
	into ___user_event_id;

	-- actions (v2.25)
	perform unsecure.run_actions(_created_by, _user_id, _correlation_id, 'on_entry', _target_user_id, _provider_code);

	return query select 10010, 'user_logged_in', ___user_event_id, 0, __state.__max_failed_attempts, null::timestamptz;
end;
$$;

create or replace function auth.delete_user_info(_deleted_by text, _user_id bigint, _correlation_id text, _target_user_id bigint, _tenant_id integer default 1, _blacklist boolean default false)
    returns table(__user_id bigint, __username text)
    rows 1
    language plpgsql
as
$$
declare
    __is_system bool;
begin
    perform
        auth.has_permission(_user_id, _correlation_id, 'users.delete_user_info', 1);  -- global user state: permission in tenant 1 (D-04)

    select is_system
    from auth.user_info ui
    where ui.user_id = _target_user_id
    into __is_system;

    if __is_system is null then
        perform error.raise_33001(_target_user_id);
    end if;

    if __is_system then
        perform error.raise_33002(_target_user_id);
    end if;

    -- actions (v2.25): every tenant the user is still a member of, before it is gone
    perform unsecure.run_actions(_deleted_by, _user_id, _correlation_id, 'on_leave', _target_user_id);

    return query
        select *
        from unsecure.delete_user_by_id(_deleted_by, _user_id, _correlation_id, _target_user_id, _blacklist);

    perform public.create_journal_message_for_entity(_deleted_by, _user_id, _correlation_id
        , 10003  -- user_deleted
        , 'user', _target_user_id
        , jsonb_build_object('user_id', _target_user_id::text, 'blacklisted', _blacklist::text)
        , _tenant_id);
end;
$$;

select *
from public.stop_version_update('2.25', _component := 'postgresql_permissionmodel');
