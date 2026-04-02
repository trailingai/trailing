use std::{
    fs,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use trailing::policy::{ActionEntry, Framework, PolicyEngine};

#[test]
fn evaluates_eu_ai_act_controls() {
    let engine = PolicyEngine::new();
    let actions = vec![
        ActionEntry::new(
            "record inference event",
            vec!["logging", "retention 6 months"],
            vec!["runbook://ops/logging", "policy://records/retention"],
        ),
        ActionEntry::new(
            "publish deployer materials",
            vec![
                "transparency notice",
                "human oversight",
                "post market monitoring",
            ],
            vec!["doc://product/transparency", "process://safety/oversight"],
        ),
    ];

    let report = engine.evaluate(&Framework::EuAiAct, &actions).unwrap();

    assert_eq!(report.controls_met.len(), 5);
    assert!(report.controls_gaps.is_empty());
    assert_eq!(report.evidence_refs.len(), 4);
}

#[test]
fn reports_nist_gaps_when_evidence_is_missing() {
    let engine = PolicyEngine::new();
    let actions = vec![ActionEntry::new(
        "operate governance review",
        vec!["governance policy"],
        vec!["doc://governance/policy"],
    )];

    let report = engine.evaluate(&Framework::NistAiRmf, &actions).unwrap();

    assert_eq!(report.controls_met.len(), 1);
    assert_eq!(report.controls_gaps.len(), 2);
    assert!(
        report
            .controls_gaps
            .iter()
            .any(|gap| gap.control.article == "MEASURE")
    );
    assert!(
        report
            .controls_gaps
            .iter()
            .any(|gap| gap.control.article == "MANAGE")
    );
}

#[test]
fn loads_custom_frameworks_from_toml() {
    let mut engine = PolicyEngine::new();
    let framework = engine
        .load_custom_framework_from_str(
            r#"
framework = "internal_policy"

[[controls]]
id = "INT-1"
article = "Section 1"
requirement = "Require audit trails for agent actions."
evidence_requirements = ["audit trail"]

[[controls]]
id = "INT-2"
article = "Section 2"
requirement = "Require human approval for escalated actions."
evidence_requirements = ["human approval"]
"#,
        )
        .unwrap();

    let actions = vec![
        ActionEntry::new(
            "write audit event",
            vec!["audit trail"],
            vec!["log://audit/2026-03-29"],
        ),
        ActionEntry::new(
            "route to reviewer",
            vec!["human approval"],
            vec!["ticket://review/42"],
        ),
    ];

    let report = engine.evaluate(&framework, &actions).unwrap();

    assert_eq!(framework, Framework::Custom("internal_policy".to_string()));
    assert_eq!(report.controls_met.len(), 2);
    assert!(report.controls_gaps.is_empty());
}

#[test]
fn loads_custom_frameworks_from_toml_path() {
    let mut engine = PolicyEngine::new();
    let path = unique_temp_path("policy-framework.toml");
    fs::write(
        &path,
        r#"
framework = "team_policy"

[[controls]]
id = "TEAM-1"
article = "Section A"
requirement = "Document operational logging."
evidence_requirements = ["logging evidence"]
"#,
    )
    .unwrap();

    let framework = engine.load_custom_framework_from_path(&path).unwrap();
    let report = engine
        .evaluate(
            &framework,
            &[ActionEntry::new(
                "store execution log",
                vec!["logging evidence"],
                vec!["file://tmp/logging-evidence"],
            )],
        )
        .unwrap();

    assert_eq!(framework, Framework::Custom("team_policy".to_string()));
    assert_eq!(report.controls_met.len(), 1);
    assert!(report.controls_gaps.is_empty());

    fs::remove_file(path).unwrap();
}

fn unique_temp_path(file_name: &str) -> PathBuf {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("{timestamp}-{file_name}"))
}
