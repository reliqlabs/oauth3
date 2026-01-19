// @generated automatically by Diesel CLI.

diesel::table! {
    oauth_providers (id) {
        id -> Text,
        name -> Text,
        provider_type -> Text,
        mode -> Text,
        client_id -> Nullable<Text>,
        client_secret -> Nullable<Text>,
        issuer -> Nullable<Text>,
        auth_url -> Nullable<Text>,
        token_url -> Nullable<Text>,
        redirect_path -> Text,
        is_enabled -> Integer,
        created_at -> Text,
        updated_at -> Text,
    }
}

diesel::table! {
    user_identities (id) {
        id -> Text,
        user_id -> Text,
        provider_key -> Text,
        subject -> Text,
        email -> Nullable<Text>,
        access_token -> Nullable<Text>,
        refresh_token -> Nullable<Text>,
        expires_at -> Nullable<Text>,
        claims -> Nullable<Text>,
        linked_at -> Text,
    }
}

diesel::table! {
    users (id) {
        id -> Text,
        primary_email -> Nullable<Text>,
        display_name -> Nullable<Text>,
        is_active -> Integer,
        created_at -> Text,
        updated_at -> Text,
    }
}

diesel::joinable!(user_identities -> users (user_id));

diesel::allow_tables_to_appear_in_same_query!(user_identities, users,);
