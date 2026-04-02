use super::framework::{Control, Framework};

pub fn controls() -> Vec<Control> {
    vec![
        Control::new(
            "NIST-AI-RMF-GOVERN",
            Framework::NistAiRmf,
            "GOVERN",
            "Define governance structures, policies, and accountability for AI risk.",
            vec!["governance policy"],
        ),
        Control::new(
            "NIST-AI-RMF-MEASURE",
            Framework::NistAiRmf,
            "MEASURE",
            "Measure, monitor, and document AI risks with relevant metrics.",
            vec!["risk measurement"],
        ),
        Control::new(
            "NIST-AI-RMF-MANAGE",
            Framework::NistAiRmf,
            "MANAGE",
            "Manage prioritized AI risks through response and remediation processes.",
            vec!["risk management process"],
        ),
    ]
}
