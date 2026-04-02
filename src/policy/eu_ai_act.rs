use super::framework::{Control, Framework};

pub fn controls() -> Vec<Control> {
    vec![
        Control::new(
            "EU-AIA-12",
            Framework::EuAiAct,
            "Art 12",
            "Maintain logging capabilities for traceability of system operation.",
            vec!["logging"],
        ),
        Control::new(
            "EU-AIA-13",
            Framework::EuAiAct,
            "Art 13",
            "Provide transparency information for deployers and affected persons.",
            vec!["transparency notice"],
        ),
        Control::new(
            "EU-AIA-14",
            Framework::EuAiAct,
            "Art 14",
            "Establish human oversight measures over system operation.",
            vec!["human oversight"],
        ),
        Control::new(
            "EU-AIA-19",
            Framework::EuAiAct,
            "Art 19",
            "Retain logs and relevant technical documentation for at least six months.",
            vec!["retention 6 months"],
        ),
        Control::new(
            "EU-AIA-72",
            Framework::EuAiAct,
            "Art 72",
            "Operate a post-market monitoring process for deployed systems.",
            vec!["post market monitoring"],
        ),
    ]
}
