-- Transaction isolation rolls all data back; only the session temp tables are left.
drop table if exists _d03;
drop table if exists _d03_expected;
