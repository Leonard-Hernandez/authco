-- Roles become the universe of controlled scopes: the name IS the scope string,
-- namespaced by application. A scope listed here must be granted explicitly;
-- anything not listed (openid, profile, email) is free for any authenticated user.

DELETE FROM user_roles WHERE role_id IN (SELECT id FROM roles WHERE name = 'USER');
DELETE FROM roles WHERE name = 'USER';

UPDATE roles SET name = 'finco:premium' WHERE name = 'PREMIUM';
UPDATE roles SET name = 'finco:admin' WHERE name = 'ADMIN';

INSERT INTO roles (name) VALUES ('platform:premium');
