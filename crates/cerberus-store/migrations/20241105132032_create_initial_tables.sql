CREATE TABLE keys(
       id INTEGER PRIMARY KEY NOT NULL,
       parent_id INTEGER REFERENCES keys(id) NULL,
       encrypted_key TEXT NOT NULL,
       nonce TEXT NOT NULL
);
