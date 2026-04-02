use super::framework::{Control, Framework};

pub fn controls() -> Vec<Control> {
    vec![
        Control::new(
            "HIPAA-164.312(b)",
            Framework::Hipaa,
            "164.312(b)",
            "Implement audit controls for electronic systems that handle protected information.",
            vec!["audit controls"],
        ),
        Control::new(
            "HIPAA-164.308(a)(1)(ii)(D)",
            Framework::Hipaa,
            "164.308(a)(1)(ii)(D)",
            "Review information system activity on an ongoing basis.",
            vec!["information system activity review"],
        ),
        Control::new(
            "HIPAA-164.308(a)(2)",
            Framework::Hipaa,
            "164.308(a)(2)",
            "Assign responsibility for security oversight and accountability.",
            vec!["assigned responsibility"],
        ),
        Control::new(
            "HIPAA-164.308(a)(8)",
            Framework::Hipaa,
            "164.308(a)(8)",
            "Perform periodic technical and nontechnical oversight of safeguards.",
            vec!["human oversight"],
        ),
        Control::new(
            "HIPAA-164.316(b)(2)(i)",
            Framework::Hipaa,
            "164.316(b)(2)(i)",
            "Retain required compliance documentation for at least six years.",
            vec!["retention 6 years"],
        ),
    ]
}
