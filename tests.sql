CREATE TABLE login  (
    email         VARCHAR(254) PRIMARY KEY,
    salt          BLOB(16),
    sha512_salt   BLOB(64),
    sha512_NoSalt BLOB(64),
    argon2id      BLOB(32)
);

SELECT email, HEX(salt), HEX(sha512_salt), HEX(sha512_NoSalt), HEX(argon2id) FROM login;

DROP TABLE login;
