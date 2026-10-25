-- +goose Up
CREATE TABLE threats (
    md5         text        PRIMARY KEY CHECK (md5 ~ '^[0-9a-f]{32}$'),
    name        text        NOT NULL CHECK (char_length(name) BETWEEN 1 AND 255),
    severity    text        NOT NULL CHECK (severity IN ('low', 'medium', 'high', 'critical')),
    category    text        NOT NULL CHECK (category IN ('trojan', 'ransomware', 'worm', 'spyware', 'adware', 'other')),
    description text        NOT NULL DEFAULT '' CHECK (char_length(description) <= 2000),
    tags        text[]      NOT NULL DEFAULT '{}' CHECK (cardinality(tags) <= 20),
    created_at  timestamptz NOT NULL,
    updated_at  timestamptz NOT NULL
);

-- +goose Down
DROP TABLE threats;
