CREATE TABLE IF NOT EXISTS users
(
    id           SERIAL       NOT NULL PRIMARY KEY,
    email        VARCHAR(255) NOT NULL UNIQUE,
    password     VARCHAR(255) NOT NULL,
    authority_id INTEGER      NOT NULL
);

CREATE TABLE IF NOT EXISTS authorities
(
    id   SERIAL       NOT NULL PRIMARY KEY,
    name VARCHAR(255) NOT NULL UNIQUE
);

ALTER TABLE users
    ADD CONSTRAINT
        fk_authorities_users FOREIGN KEY (authority_id) REFERENCES authorities (id);
