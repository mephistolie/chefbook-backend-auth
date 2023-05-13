CREATE TABLE outbox
(
    message_id uuid PRIMARY KEY NOT NULL UNIQUE DEFAULT gen_random_uuid(),
    exchange   VARCHAR(64)                      DEFAULT '',
    type       VARCHAR(64)      NOT NULL,
    body       JSONB            NOT NULL        DEFAULT '{}'::jsonb
);
