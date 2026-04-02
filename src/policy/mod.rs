use std::{collections::HashMap, error::Error, fmt, path::Path};

pub mod custom;
pub mod eu_ai_act;
pub mod evaluate;
pub mod fda_21_cfr_part_11;
pub mod framework;
pub mod hipaa;
pub mod nist;
pub mod sr_11_7;

pub use evaluate::{ActionEntry, ComplianceReport, ControlResult};
pub use framework::{Control, Framework};

#[derive(Debug)]
pub enum PolicyError {
    FrameworkNotFound(Framework),
    InvalidFrameworkDefinition(String),
    Io(std::io::Error),
    Toml(toml::de::Error),
}

impl fmt::Display for PolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FrameworkNotFound(framework) => {
                write!(f, "framework `{framework}` is not loaded")
            }
            Self::InvalidFrameworkDefinition(message) => f.write_str(message),
            Self::Io(error) => write!(f, "{error}"),
            Self::Toml(error) => write!(f, "{error}"),
        }
    }
}

impl Error for PolicyError {}

impl From<std::io::Error> for PolicyError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<toml::de::Error> for PolicyError {
    fn from(error: toml::de::Error) -> Self {
        Self::Toml(error)
    }
}

pub struct PolicyEngine {
    frameworks: HashMap<Framework, Vec<Control>>,
}

impl Default for PolicyEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl PolicyEngine {
    pub fn new() -> Self {
        let mut frameworks = HashMap::new();
        frameworks.insert(Framework::EuAiAct, eu_ai_act::controls());
        frameworks.insert(Framework::NistAiRmf, nist::controls());
        frameworks.insert(Framework::Sr117, sr_11_7::controls());
        frameworks.insert(Framework::Hipaa, hipaa::controls());
        frameworks.insert(Framework::Fda21CfrPart11, fda_21_cfr_part_11::controls());

        Self { frameworks }
    }

    pub fn controls_for(&self, framework: &Framework) -> Option<&[Control]> {
        self.frameworks.get(framework).map(Vec::as_slice)
    }

    pub fn register_framework(&mut self, framework: Framework, controls: Vec<Control>) {
        self.frameworks.insert(framework, controls);
    }

    pub fn load_custom_framework_from_str(
        &mut self,
        contents: &str,
    ) -> Result<Framework, PolicyError> {
        let (framework, controls) = custom::load_framework_from_str(contents)?;
        self.register_framework(framework.clone(), controls);
        Ok(framework)
    }

    pub fn load_custom_framework_from_path(
        &mut self,
        path: impl AsRef<Path>,
    ) -> Result<Framework, PolicyError> {
        let (framework, controls) = custom::load_framework_from_path(path)?;
        self.register_framework(framework.clone(), controls);
        Ok(framework)
    }

    pub fn evaluate(
        &self,
        framework: &Framework,
        actions: &[ActionEntry],
    ) -> Result<ComplianceReport, PolicyError> {
        let controls = self
            .frameworks
            .get(framework)
            .ok_or_else(|| PolicyError::FrameworkNotFound(framework.clone()))?;

        Ok(evaluate::evaluate_actions(framework, controls, actions))
    }
}
