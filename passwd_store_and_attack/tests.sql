CREATE TABLE login  (
    email         VARCHAR(254) PRIMARY KEY,
    salt          BLOB(16),
    sha512_salt   BLOB(64),
    sha512_NoSalt BLOB(64),
    argon2id      BLOB(32),
    totp_secret   TEXT -- jeder Benutzer hat eigenes TOTP Secret
);
--Recovery-Informationen werden getrennt con Login Daten gespeichert
CREATE TABLE recovery (
    email       VARCHAR(254) PRIMARY KEY,
    token_hash  BLOB NOT NULL,
    expires_at  INTEGER NOT NULL,
    FOREIGN KEY (email) REFERENCES login(email)
);

CREATE TABLE rainbow (
    passwd VARCHAR(256) PRIMARY KEY,
    sha512 BLOB(64)
);
SELECT passwd, sha512 FROM rainbow LIMIT 500;
INSERT INTO rainbow VALUES ("hello", "awd");

SELECT email, HEX(salt), HEX(sha512_salt), HEX(sha512_NoSalt), HEX(argon2id) FROM login;

DROP TABLE login;
DROP TABLE rainbow;
