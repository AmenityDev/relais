-- A second database for the test suite.
--
-- The database-backed tests TRUNCATE every table between cases, which is correct
-- for a test database and destructive for a development one. Pointing
-- RELAIS_TEST_DB_URL at the same database as RELAIS_DB_URL therefore means that
-- running the suite silently wipes the relays, domains and messages an operator was
-- working with — a footgun with no error message, discovered the hard way.
--
-- Two databases in one container costs nothing and removes the choice entirely.
CREATE DATABASE relais_test OWNER relais;
