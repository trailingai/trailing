use super::framework::{Control, Framework};

pub fn controls() -> Vec<Control> {
    vec![
        Control::new(
            "SR11-7-LOGGING",
            Framework::Sr117,
            "Documentation",
            "Maintain auditable documentation of model actions and decisions.",
            vec!["audit trail"],
        ),
        Control::new(
            "SR11-7-GOVERNANCE",
            Framework::Sr117,
            "Governance",
            "Document governance policy and assigned responsibility for model oversight.",
            vec!["governance policy"],
        ),
        Control::new(
            "SR11-7-OVERSIGHT",
            Framework::Sr117,
            "Independent Review",
            "Provide human review or effective challenge over model operation.",
            vec!["human oversight"],
        ),
        Control::new(
            "SR11-7-RETENTION",
            Framework::Sr117,
            "Record Retention",
            "Retain model risk and monitoring records for at least six months.",
            vec!["retention 6 months"],
        ),
        Control::new(
            "SR11-7-MONITORING",
            Framework::Sr117,
            "Ongoing Monitoring",
            "Operate an ongoing monitoring process for deployed models.",
            vec!["ongoing monitoring"],
        ),
    ]
}
