use std::sync::OnceLock;

use axum::response::Html;
use base64::{Engine as _, engine::general_purpose::STANDARD};

const INDEX_HTML_TEMPLATE: &str = include_str!("index.html");
const EU_AI_ACT_SMALL: &[u8] = include_bytes!("logos/eu_ai_act_small.png");
const HIPAA_SMALL: &[u8] = include_bytes!("logos/hipaa_small.png");
const NIST_AI_RMF_SMALL: &[u8] = include_bytes!("logos/nist_ai_rmf_small.png");
const FDA_21_CFR_11_SMALL: &[u8] = include_bytes!("logos/fda_21_cfr_11_small.png");
const SR_11_7_SMALL: &[u8] = include_bytes!("logos/sr_11_7_small.png");

static INDEX_HTML: OnceLock<String> = OnceLock::new();

fn png_data_url(bytes: &[u8]) -> String {
    format!("data:image/png;base64,{}", STANDARD.encode(bytes))
}

fn rendered_index_html() -> &'static str {
    INDEX_HTML
        .get_or_init(|| {
            INDEX_HTML_TEMPLATE
                .replace("__EU_AI_ACT_SMALL__", &png_data_url(EU_AI_ACT_SMALL))
                .replace("__HIPAA_SMALL__", &png_data_url(HIPAA_SMALL))
                .replace("__NIST_AI_RMF_SMALL__", &png_data_url(NIST_AI_RMF_SMALL))
                .replace(
                    "__FDA_21_CFR_11_SMALL__",
                    &png_data_url(FDA_21_CFR_11_SMALL),
                )
                .replace("__SR_11_7_SMALL__", &png_data_url(SR_11_7_SMALL))
        })
        .as_str()
}

pub async fn index() -> Html<&'static str> {
    Html(rendered_index_html())
}

#[cfg(test)]
mod tests {
    use super::rendered_index_html;

    #[test]
    fn embedded_landing_page_has_expected_copy() {
        let html = rendered_index_html();

        assert!(html.contains("Know what your AI"));
        assert!(html.contains("Prove it"));
        assert!(html.contains("github.com/trailingai/trailing"));
        assert!(html.contains("/v1/openapi.yml"));
        assert!(html.contains("Supported Frameworks"));
        assert!(html.contains("data:image/png;base64,"));
        assert!(!html.contains("__EU_AI_ACT_SMALL__"));
    }
}
