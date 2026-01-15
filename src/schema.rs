// @generated automatically by Diesel CLI.

diesel::table! {
    user_identities (id) {
        id -> Text,
        user_id -> Text,
        provider_key -> Text,
        subject -> Text,
        email -> Nullable<Text>,
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
