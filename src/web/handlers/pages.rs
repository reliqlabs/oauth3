use axum::response::Html;

pub async fn index() -> Html<String> {
    Html(include_str!("../../../views/index.html").to_string())
}

pub async fn login() -> Html<String> {
    Html(include_str!("../../../views/login.html").to_string())
}

pub async fn account() -> Html<String> {
    Html(include_str!("../../../views/account.html").to_string())
}
