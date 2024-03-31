CREATE TABLE access_log (
    "access_id" uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    -- datetime this access occured
    "time" timestamptz NOT NULL DEFAULT now(),
    -- ip address of the request
    "address" inet NOT NULL,
    -- `User-Agent` header if set
    "user_agent" text,
    -- the hash of the identity key provideded in the `i` query parameter
    -- not a foreign key because perhaps an invalid key can be used
    "identity_hash" sha256_hash
);