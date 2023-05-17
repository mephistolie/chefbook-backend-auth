CREATE TYPE role as ENUM ('member', 'admin');

CREATE TABLE users
(
    user_id    uuid PRIMARY KEY         NOT NULL UNIQUE DEFAULT gen_random_uuid(),
    email      VARCHAR(128)             NOT NULL UNIQUE,
    nickname   VARCHAR(128) UNIQUE                      DEFAULT NULL,
    password   bytea                                    DEFAULT NULL,

    role       role                     NOT NULL        DEFAULT 'member',
    registered TIMESTAMP WITH TIME ZONE NOT NULL        DEFAULT now()::timestamp,
    activated  BOOLEAN                  NOT NULL        DEFAULT false,
    blocked    BOOLEAN                  NOT NULL        DEFAULT false
);

CREATE TABLE activation_codes
(
    user_id         uuid REFERENCES users (user_id) ON DELETE CASCADE NOT NULL UNIQUE,
    activation_code VARCHAR(6)                                        NOT NULL
);

CREATE TABLE sessions
(
    session_id    SERIAL PRIMARY KEY                                NOT NULL UNIQUE,
    user_id       uuid REFERENCES users (user_id) ON DELETE CASCADE NOT NULL,
    refresh_token VARCHAR(40)                                       NOT NULL UNIQUE,
    ip            cidr                                              NOT NULL,
    user_agent    TEXT                                              NOT NULL,
    last_access   TIMESTAMP WITH TIME ZONE                          NOT NULL DEFAULT now()::timestamp,
    expires_at    TIMESTAMP WITH TIME ZONE                          NOT NULL,
    created_at    TIMESTAMP WITH TIME ZONE                          NOT NULL DEFAULT now()::timestamp
);

CREATE TABLE password_resets
(
    reset_id   SERIAL PRIMARY KEY                                NOT NULL UNIQUE,
    user_id    uuid REFERENCES users (user_id) ON DELETE CASCADE NOT NULL,
    reset_code VARCHAR(40)                                       NOT NULL UNIQUE,
    used       BOOLEAN                                           NOT NULL DEFAULT FALSE,
    expires_at TIMESTAMP WITH TIME ZONE                          NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE                          NOT NULL DEFAULT now()::timestamp
);

CREATE TABLE oauth
(
    user_id   uuid REFERENCES users (user_id) ON DELETE CASCADE NOT NULL UNIQUE,
    google_id TEXT UNIQUE   DEFAULT NULL,
    vk_id     BIGINT UNIQUE DEFAULT NULL
);

CREATE TABLE firebase
(
    user_id     uuid REFERENCES users (user_id) ON DELETE CASCADE NOT NULL UNIQUE,
    firebase_id TEXT UNIQUE
);
