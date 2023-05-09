CREATE TYPE msg_status AS ENUM ('pending', 'processing', 'sent');

CREATE TABLE outbox
(
    event_id uuid PRIMARY KEY NOT NULL UNIQUE DEFAULT gen_random_uuid(),
    exchange VARCHAR(64)                      DEFAULT '',
    type     VARCHAR(64)      NOT NULL,
    body     JSONB            NOT NULL        DEFAULT '{}'::jsonb,
    status   msg_status       NOT NULL        DEFAULT 'pending'
);
