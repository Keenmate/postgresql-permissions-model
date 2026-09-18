/*
 * Const Schema Tables
 * ===================
 *
 * Constant/lookup tables: token types, user types, event types, etc.
 *
 * This file is part of the PostgreSQL Permissions Model v2
 * Generated from WHOLE_DB.sql
 */

set search_path = public, const, ext, stage, helpers, internal, unsecure, auth, triggers;

create table const.sys_param
(
    created_at   timestamp with time zone default now()           not null,
    created_by   text                     default 'unknown'::text not null,
    updated_at   timestamp with time zone default now()           not null,
    updated_by   text                     default 'unknown'::text not null,
    sys_param_id integer generated always as identity primary key,
    group_code   text   not null,
    code         text   not null,
    text_value   text,
    number_value bigint,
    bool_value   boolean,
    constraint sys_param_created_by_check check (length(created_by) <= 250),
    constraint sys_param_updated_by_check check (length(updated_by) <= 250)
);

create table const.tenant_access_type
(
    code text not null
        primary key
);

create table const.token_type
(
    code                          text not null
        primary key,
    default_expiration_in_seconds integer,
    is_system                     boolean not null default false
);

create table const.token_channel
(
    code text not null
        primary key
);

create table const.token_state
(
    code text not null
        primary key
);

create table const.user_type
(
    code text not null
        primary key
);

/*
 * Event Code System
 * =================
 *
 * Unified event/error code system with clear ranges:
 *
 * Library ranges (postgresql-permissions-model):
 * ----------------------------------------------
 * 10000-19999  Informational events (audit trail)
 *     10001-10999  User events (login, logout, password change)
 *     11001-11999  Tenant events (created, updated, deleted)
 *     12001-12999  Permission events (assigned, revoked)
 *     13001-13999  Group events (member added, removed)
 *     14001-14999  API key events
 *     15001-15999  Token events
 *     19001-19999  Token config events
 *
 * 30000-39999  Errors (library)
 *     30001-30999  Security/auth errors
 *     31001-31999  Validation errors
 *     32001-32999  Permission errors
 *     33001-33999  User/group errors
 *     34001-34999  Tenant errors
 *     36001-36999  Token config errors
 *
 * Reserved for applications:
 * --------------------------
 * 50000+       Application-specific events & errors
 */

create table const.event_category
(
    category_code text    not null primary key,
    range_start   integer not null,
    range_end     integer not null,
    is_error      boolean not null default false,
    source        text    default null
);

create table const.event_code
(
    event_id      integer not null primary key,
    code          text    not null unique,
    category_code text    not null references const.event_category(category_code),
    is_read_only  boolean not null default false,
    is_system     boolean not null default false,
    source        text    default null
);

/*
 * Event Message Templates
 * =======================
 *
 * Message templates for journal entries, supporting multiple languages.
 * Templates use placeholders like {username}, {group_title} that are
 * replaced with values from journal.keys and journal.data_payload.
 *
 * Example template: 'User "{username}" created'
 * With payload: {"username": "john"}
 * Result: 'User "john" created'
 */
create table const.event_message
(
    created_at       timestamp with time zone default now()           not null,
    created_by       text                     default 'unknown'::text not null,
    updated_at       timestamp with time zone default now()           not null,
    updated_by       text                     default 'unknown'::text not null,
    event_message_id integer generated always as identity primary key,
    event_id         integer not null references const.event_code(event_id),
    language_code    text    not null default 'en',
    message_template text    not null,
    is_active        boolean not null default true,
    constraint event_message_created_by_check check (length(created_by) <= 250),
    constraint event_message_updated_by_check check (length(updated_by) <= 250)
);

create unique index uq_event_message
    on const.event_message (event_id, language_code) where is_active = true;

create table const.user_group_member_type
(
    code text not null
        primary key
);

create unique index uq_sys_params
    on const.sys_param (group_code, code);

create index ix_event_code_category
    on const.event_code (category_code);

