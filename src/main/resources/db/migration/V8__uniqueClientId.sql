-- client_id identifies a client everywhere (authorize, token, admin API), but the
-- stock Spring Authorization Server schema does not enforce it: two instances
-- seeding the same client at once would both insert it. With the constraint the
-- second insert fails and the seeder treats it as already seeded.
ALTER TABLE oauth2_registered_client
    ADD CONSTRAINT oauth2_registered_client_client_id_key UNIQUE (client_id);
