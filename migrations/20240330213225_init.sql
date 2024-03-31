CREATE DOMAIN tag_uid AS bytea CHECK (
    octet_length(VALUE) = 4
    OR octet_length(VALUE) = 7
    OR octet_length(VALUE) = 10
);

CREATE DOMAIN sha256_hash AS bytea CHECK (octet_length(VALUE) = 32);

CREATE DOMAIN pgp_fingerprint AS bytea CHECK (
    -- OpenPGP v4 fingerprint
    octet_length(VALUE) = 20 -- OpenPGP v5 fingerprint
    OR octet_length(VALUE) = 32
);

CREATE TABLE tags (
    "uid" tag_uid UNIQUE NOT NULL PRIMARY KEY,
    "creation_date" TIMESTAMPTZ NOT NULL,
    "identity_hash" sha256_hash UNIQUE NOT NULL,
    "pgp_fingerprint" pgp_fingerprint UNIQUE NOT NULL,
    -- in practice, this should also be unique
    "pgp_certificate" bytea NOT NULL,
    -- and so should this
    "pgp_identity_self_signature" bytea NOT NULL
);