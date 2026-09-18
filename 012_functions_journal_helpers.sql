/*
 * Journal / Storage Config Helpers
 * ================================
 *
 * Native permissions-model helpers that read journal + event-storage
 * configuration from const.sys_param / const.event_code (created in
 * 011_tables_const.sql). Covered by the main v2 version span (010 -> 047),
 * so this file carries no separate version record.
 *
 * NOTE: these functions are intentionally NOT part of the common_helpers
 * library. common_helpers is stateless (no tables); anything coupled to the
 * const.* config tables lives here.
 */

set search_path = public, const, ext, stage, helpers, internal, unsecure, auth, triggers;

/*
 * Journal Level Control
 * =====================
 *
 * Checks the journal logging level from const.sys_param and determines
 * whether a journal entry should be created based on the event type.
 *
 * Levels:
 * - 'all'    : Log everything including read operations
 * - 'update' : Log only state-changing operations (default)
 * - 'none'   : Disable journaling entirely
 *
 * Usage:
 *   if helpers.should_log_journal() then
 *       perform public.create_journal_message(...);
 *   end if;
 *
 *   -- For read-only operations:
 *   if helpers.should_log_journal(true) then
 *       perform public.create_journal_message(...);
 *   end if;
 */
create or replace function helpers.should_log_journal(_is_read_only boolean default false)
    returns boolean
    stable
    language sql
as
$$
select case (select text_value from const.sys_param
             where group_code = 'journal' and code = 'level')
    when 'none' then false
    when 'update' then not _is_read_only
    else true  -- 'all' or not set defaults to logging everything
end;
$$;

/*
 * Check if event is read-only by event_id
 *
 * Looks up the is_read_only flag from const.event_code.
 * Used by public.create_journal_message to automatically determine if logging should happen.
 */
create or replace function helpers.is_event_read_only(_event_id integer)
    returns boolean
    stable
    language sql
as
$$
select coalesce(
    (select is_read_only from const.event_code where event_id = _event_id),
    false
);
$$;

/*
 * Storage Mode Helpers
 * ====================
 *
 * Check storage mode for journal and user_event from const.sys_param.
 * Used by public.create_journal_message() and create_user_event() to control
 * whether data is stored locally in PostgreSQL, sent via pg_notify, or both.
 *
 * Modes:
 * - 'local'  : INSERT into PostgreSQL only (default)
 * - 'notify' : Fire pg_notify only, skip INSERT
 * - 'both'   : INSERT + fire pg_notify
 */
create or replace function helpers.should_store_locally(_group_code text)
    returns boolean
    stable
    language sql
as
$$
select coalesce(
    (select text_value from const.sys_param
     where group_code = _group_code and code = 'storage_mode'),
    'local'
) in ('local', 'both');
$$;

create or replace function helpers.should_notify_storage(_group_code text)
    returns boolean
    stable
    language sql
as
$$
select coalesce(
    (select text_value from const.sys_param
     where group_code = _group_code and code = 'storage_mode'),
    'local'
) in ('notify', 'both');
$$;
