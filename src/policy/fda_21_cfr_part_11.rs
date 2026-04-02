use super::framework::{Control, Framework};

pub fn controls() -> Vec<Control> {
    vec![
        Control::new(
            "FDA-11.10(e)",
            Framework::Fda21CfrPart11,
            "11.10(e)",
            "Use secure, computer-generated, time-stamped audit trails.",
            vec!["audit trail"],
        ),
        Control::new(
            "FDA-11.10(g)",
            Framework::Fda21CfrPart11,
            "11.10(g)",
            "Use authority checks to ensure only authorized individuals act on records.",
            vec!["human oversight"],
        ),
        Control::new(
            "FDA-11.10(k)",
            Framework::Fda21CfrPart11,
            "11.10(k)",
            "Maintain policies and accountability for electronic record controls.",
            vec!["governance policy"],
        ),
        Control::new(
            "FDA-11.10(c)",
            Framework::Fda21CfrPart11,
            "11.10(c)",
            "Protect records to enable accurate and ready retrieval throughout retention.",
            vec!["retention 6 months"],
        ),
        Control::new(
            "FDA-11.10(i)",
            Framework::Fda21CfrPart11,
            "11.10(i)",
            "Support ongoing review of system operation and record activity.",
            vec!["ongoing monitoring"],
        ),
    ]
}
