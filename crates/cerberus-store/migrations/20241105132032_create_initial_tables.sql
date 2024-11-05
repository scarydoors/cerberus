CREATE TABLE keys(
       id INT PRIMARY KEY NOT NULL,
       parent_id INT REFERENCES keys(id) NULL,
       encrypted_key TEXT NOT NULL,
       nonce TEXT NOT NULL
);
