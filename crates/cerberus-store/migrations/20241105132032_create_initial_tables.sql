CREATE TABLE keys(
       id INTEGER PRIMARY KEY NOT NULL,
       key_encrypted_data JSONB NOT NULL,
       next_nonce BLOB NOT NULL
);

CREATE TABLE items(
       id INTEGER PRIMARY KEY NOT NULL,
       overview_encrypted_data JSONB NOT NULL,
       item_encrypted_data JSONB NOT NULL,
       created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
       updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE vaults(
      id INTEGER PRIMARY KEY NOT NULL,
      name TEXT NOT NULL,
      salt TEXT NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
