use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Framework {
    EuAiAct,
    NistAiRmf,
    Sr117,
    Hipaa,
    Fda21CfrPart11,
    Custom(String),
}

impl Framework {
    pub fn from_name(name: &str) -> Self {
        match name.trim().to_ascii_lowercase().as_str() {
            "eu_ai_act" | "eu ai act" | "eu-ai-act" => Self::EuAiAct,
            "nist_ai_rmf" | "nist ai rmf" | "nist-ai-rmf" => Self::NistAiRmf,
            "sr117" | "sr_117" | "sr-117" | "sr11-7" | "sr_11_7" | "sr-11-7" => Self::Sr117,
            "hipaa" => Self::Hipaa,
            "fda21cfrpart11" | "fda_21_cfr_part_11" | "fda-21-cfr-part-11" => Self::Fda21CfrPart11,
            other => Self::Custom(other.to_string()),
        }
    }

    pub fn name(&self) -> &str {
        match self {
            Self::EuAiAct => "eu-ai-act",
            Self::NistAiRmf => "nist-ai-rmf",
            Self::Sr117 => "sr-11-7",
            Self::Hipaa => "hipaa",
            Self::Fda21CfrPart11 => "fda-21-cfr-part-11",
            Self::Custom(name) => name.as_str(),
        }
    }
}

impl fmt::Display for Framework {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Control {
    pub id: String,
    pub framework: Framework,
    pub article: String,
    pub requirement: String,
    pub evidence_requirements: Vec<String>,
}

impl Control {
    pub fn new(
        id: impl Into<String>,
        framework: Framework,
        article: impl Into<String>,
        requirement: impl Into<String>,
        evidence_requirements: Vec<&str>,
    ) -> Self {
        Self {
            id: id.into(),
            framework,
            article: article.into(),
            requirement: requirement.into(),
            evidence_requirements: evidence_requirements
                .into_iter()
                .map(str::to_string)
                .collect(),
        }
    }
}
