use axum::{extract::State, response::Html};
use crate::app::AppState;

pub async fn index() -> Html<String> {
    Html(include_str!("../../../views/index.html").to_string())
}

pub async fn login(State(state): State<AppState>) -> Html<String> {
    match render_login(&state).await {
        Ok(html) => Html(html),
        Err(e) => {
            tracing::error!(error=?e, "failed to render login page");
            Html(include_str!("../../../views/login.html").to_string())
        }
    }
}

async fn render_login(state: &AppState) -> anyhow::Result<String> {
    let providers = state.accounts.list_providers().await?;

    let mut buttons = String::new();
    for p in providers.iter().filter(|p| p.is_enabled == 1) {
        buttons.push_str(&format!(
            r#"      <a class="btn" href="/auth/{}">{}</a>
"#,
            crate::web::handlers::oauth::escape_html(&p.id),
            crate::web::handlers::oauth::escape_html(&p.name)
        ));
    }

    Ok(format!(r#"<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Login</title>
  <link rel="stylesheet" href="/static/styles.css" />
  <style>
    body {{ font-family: system-ui, -apple-system, Segoe UI, Roboto, Ubuntu, Cantarell, Noto Sans, Helvetica, Arial, sans-serif; margin: 0; }}
    main {{ max-width: 520px; margin: 10vh auto; padding: 24px; border-radius: 12px; box-shadow: 0 10px 30px rgba(0,0,0,0.06); }}
    h1 {{ margin-top: 0; font-size: 26px; }}
    .providers {{ display: grid; gap: 12px; margin-top: 20px; }}
    a.btn {{ display: inline-block; text-decoration: none; padding: 12px 16px; border: 1px solid #ddd; border-radius: 8px; color: #111; background: #fff; }}
    a.btn:hover {{ background: #f8f8f8; }}
  </style>
  </head>
<body>
  <main>
    <h1>Sign in</h1>
    <p>Choose a provider to continue:</p>
    <div class="providers">
{}    </div>
  </main>
</body>
</html>"#, buttons))
}

pub async fn account() -> Html<String> {
    Html(include_str!("../../../views/account.html").to_string())
}
