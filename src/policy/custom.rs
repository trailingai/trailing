use std::{fs, path::Path};

use toml::Value;

use super::{
    PolicyError,
    framework::{Control, Framework},
};

pub fn load_framework_from_path(
    path: impl AsRef<Path>,
) -> Result<(Framework, Vec<Control>), PolicyError> {
    let contents = fs::read_to_string(path)?;
    load_framework_from_str(&contents)
}

pub fn load_framework_from_str(contents: &str) -> Result<(Framework, Vec<Control>), PolicyError> {
    let value = contents.parse::<Value>()?;
    let framework_name = value
        .get("framework")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            PolicyError::InvalidFrameworkDefinition("missing `framework`".to_string())
        })?;
    let controls = value
        .get("controls")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            PolicyError::InvalidFrameworkDefinition("missing `controls` array".to_string())
        })?;

    let framework = Framework::from_name(framework_name);
    let mut parsed_controls = Vec::with_capacity(controls.len());

    for control in controls {
        let table = control.as_table().ok_or_else(|| {
            PolicyError::InvalidFrameworkDefinition(
                "control entries must be TOML tables".to_string(),
            )
        })?;

        let id = get_required_string(table, "id")?;
        let article = get_required_string(table, "article")?;
        let requirement = get_required_string(table, "requirement")?;
        let evidence_requirements = table
            .get("evidence_requirements")
            .and_then(Value::as_array)
            .ok_or_else(|| {
                PolicyError::InvalidFrameworkDefinition(
                    "control is missing `evidence_requirements` array".to_string(),
                )
            })?
            .iter()
            .map(|entry| {
                entry.as_str().map(str::to_string).ok_or_else(|| {
                    PolicyError::InvalidFrameworkDefinition(
                        "`evidence_requirements` entries must be strings".to_string(),
                    )
                })
            })
            .collect::<Result<Vec<_>, _>>()?;

        parsed_controls.push(Control {
            id,
            framework: framework.clone(),
            article,
            requirement,
            evidence_requirements,
        });
    }

    if parsed_controls.is_empty() {
        return Err(PolicyError::InvalidFrameworkDefinition(
            "framework must define at least one control".to_string(),
        ));
    }

    Ok((framework, parsed_controls))
}

fn get_required_string(
    table: &toml::map::Map<String, Value>,
    key: &str,
) -> Result<String, PolicyError> {
    table
        .get(key)
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| {
            PolicyError::InvalidFrameworkDefinition(format!("control is missing `{key}`"))
        })
}
