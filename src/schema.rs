// @generated automatically by Diesel CLI, but maintained manually here.
// Keep in sync with migrations.

diesel::table! {
    users (id) {
        id -> Integer,
        email -> Nullable<Text>,
        name -> Nullable<Text>,
        oauth_provider -> Nullable<Text>,
        oauth_subject -> Nullable<Text>,
        password_hash -> Nullable<Text>,
        created_at -> Timestamp,
        updated_at -> Timestamp,
    }
}

diesel::table! {
    oauth_providers (id) {
        id -> Integer,
        key -> Text,
        auth_url -> Text,
        token_url -> Text,
        userinfo_url -> Text,
        client_id -> Text,
        client_secret -> Text,
        redirect_url -> Text,
        scopes -> Text,
        created_at -> Timestamp,
        updated_at -> Timestamp,
    }
}

diesel::table! {
    user_identities (id) {
        id -> Integer,
        user_id -> Integer,
        provider_key -> Text,
        subject -> Text,
        created_at -> Timestamp,
        updated_at -> Timestamp,
    }
}
