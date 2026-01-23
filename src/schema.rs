// @generated automatically by Diesel CLI.

diesel::table! {
    api_keys (id) {
        id -> Text,
        user_id -> Text,
        name -> Text,
        key_hash -> Text,
        scopes -> Text,
        created_at -> Text,
        last_used_at -> Nullable<Text>,
        deleted_at -> Nullable<Text>,
    }
}

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
        scopes -> Nullable<Text>,
        redirect_path -> Text,
        is_enabled -> Integer,
        created_at -> Text,
        updated_at -> Text,
        api_base_url -> Nullable<Text>,
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
        scopes -> Nullable<Text>,
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

diesel::joinable!(api_keys -> users (user_id));
diesel::joinable!(user_identities -> users (user_id));

diesel::allow_tables_to_appear_in_same_query!(api_keys, oauth_providers, user_identities, users,);
