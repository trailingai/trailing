use axum::response::Html;

const INDEX_HTML: &str = include_str!("index.html");

pub async fn index() -> Html<&'static str> {
    Html(INDEX_HTML)
}

#[cfg(test)]
mod tests {
    use super::INDEX_HTML;

    #[test]
    fn embedded_dashboard_has_expected_title() {
        assert!(INDEX_HTML.contains("Compliance Audit Dashboard"));
        assert!(INDEX_HTML.contains("Export JSON"));
        assert!(INDEX_HTML.contains("Export PDF"));
    }
}
