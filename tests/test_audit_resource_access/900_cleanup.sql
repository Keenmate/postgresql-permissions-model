-- Transaction isolation rolls all data back; only the session temp tables are left.
drop table if exists _d14;
drop table if exists _d14_expect;
