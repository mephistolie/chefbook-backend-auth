CREATE TABLE delete_profile_requests
(
    user_id            uuid REFERENCES users (user_id) ON DELETE CASCADE NOT NULL UNIQUE,
    with_shared_data   boolean                                           NOT NULL DEFAULT false,
    deletion_timestamp TIMESTAMP WITH TIME ZONE                          NOT NULL
);
