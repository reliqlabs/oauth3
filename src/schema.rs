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
    app_access_tokens (id) {
        id -> Text,
        token_hash -> Text,
        app_id -> Text,
        user_id -> Text,
        scopes -> Text,
        expires_at -> Text,
        created_at -> Text,
        last_used_at -> Nullable<Text>,
        revoked_at -> Nullable<Text>,
    }
}

diesel::table! {
    app_redirect_uris (id) {
        id -> Text,
        app_id -> Text,
        redirect_uri -> Text,
        created_at -> Text,
    }
}

diesel::table! {
    app_refresh_tokens (id) {
        id -> Text,
        token_hash -> Text,
        app_id -> Text,
        user_id -> Text,
        scopes -> Text,
        expires_at -> Text,
        created_at -> Text,
        revoked_at -> Nullable<Text>,
        rotation_parent_id -> Nullable<Text>,
        replaced_by_id -> Nullable<Text>,
    }
}

diesel::table! {
    applications (id) {
        id -> Text,
        owner_user_id -> Text,
        name -> Text,
        client_type -> Text,
        client_secret_hash -> Nullable<Text>,
        allowed_scopes -> Text,
        is_enabled -> Integer,
        created_at -> Text,
        updated_at -> Text,
    }
}

diesel::table! {
    oauth_codes (code_hash) {
        code_hash -> Text,
        app_id -> Text,
        user_id -> Text,
        redirect_uri -> Text,
        scopes -> Text,
        code_challenge -> Nullable<Text>,
        code_challenge_method -> Nullable<Text>,
        expires_at -> Text,
        created_at -> Text,
        consumed_at -> Nullable<Text>,
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
    user_consents (id) {
        id -> Text,
        user_id -> Text,
        app_id -> Text,
        scopes -> Text,
        created_at -> Text,
        revoked_at -> Nullable<Text>,
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
diesel::joinable!(app_access_tokens -> applications (app_id));
diesel::joinable!(app_access_tokens -> users (user_id));
diesel::joinable!(app_redirect_uris -> applications (app_id));
diesel::joinable!(app_refresh_tokens -> applications (app_id));
diesel::joinable!(app_refresh_tokens -> users (user_id));
diesel::joinable!(applications -> users (owner_user_id));
diesel::joinable!(oauth_codes -> applications (app_id));
diesel::joinable!(oauth_codes -> users (user_id));
diesel::joinable!(user_consents -> applications (app_id));
diesel::joinable!(user_consents -> users (user_id));
diesel::joinable!(user_identities -> users (user_id));

diesel::allow_tables_to_appear_in_same_query!(
    api_keys,
    app_access_tokens,
    app_redirect_uris,
    app_refresh_tokens,
    applications,
    oauth_codes,
    oauth_providers,
    user_consents,
    user_identities,
    users,
);
