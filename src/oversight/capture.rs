use crate::collector::{ActionContext, ActionEntry, ActionStorage, AgentType, CollectorError};

use super::{OversightActor, OversightEvent};

pub fn log_oversight_event<S: ActionStorage>(
    storage: &mut S,
    actor: &OversightActor,
    event: OversightEvent,
) -> Result<ActionEntry, CollectorError> {
    let entry = ActionEntry {
        entry_id: crate::collector::normalize::next_entry_id("oversight"),
        modified_entry_id: event.modified_entry_id().map(str::to_string),
        agent_id: actor.agent_id.clone(),
        agent_type: AgentType::detect(&actor.agent_type),
        session_id: actor.session_id.clone(),
        trace_id: None,
        span_id: None,
        action_type: "HumanOverride".to_string(),
        tool_name: None,
        target: event.modified_entry_id().map(str::to_string),
        payload: event.payload(),
        result: None,
        started_at: None,
        ended_at: None,
        status: Some("captured".to_string()),
        context: ActionContext {
            parent_span_id: None,
            data_accessed: Vec::new(),
            permissions_used: vec!["human-oversight".to_string()],
            policy_refs: vec!["EU AI Act Art. 14".to_string()],
        },
    };

    storage.write_action(entry.clone())?;
    Ok(entry)
}

pub fn log_approval<S: ActionStorage>(
    storage: &mut S,
    actor: &OversightActor,
    reviewer: impl Into<String>,
    approved_entry_id: impl Into<String>,
    notes: Option<String>,
) -> Result<ActionEntry, CollectorError> {
    log_oversight_event(
        storage,
        actor,
        OversightEvent::Approval {
            reviewer: reviewer.into(),
            approved_entry_id: approved_entry_id.into(),
            notes,
        },
    )
}

pub fn log_override<S: ActionStorage>(
    storage: &mut S,
    actor: &OversightActor,
    reviewer: impl Into<String>,
    overridden_entry_id: impl Into<String>,
    previous_outcome: Option<String>,
    new_outcome: impl Into<String>,
    reason: impl Into<String>,
) -> Result<ActionEntry, CollectorError> {
    log_oversight_event(
        storage,
        actor,
        OversightEvent::Override {
            reviewer: reviewer.into(),
            overridden_entry_id: overridden_entry_id.into(),
            previous_outcome,
            new_outcome: new_outcome.into(),
            reason: reason.into(),
        },
    )
}

pub fn log_escalation<S: ActionStorage>(
    storage: &mut S,
    actor: &OversightActor,
    reviewer: impl Into<String>,
    escalated_entry_id: impl Into<String>,
    escalation_target: impl Into<String>,
    reason: impl Into<String>,
) -> Result<ActionEntry, CollectorError> {
    log_oversight_event(
        storage,
        actor,
        OversightEvent::Escalation {
            reviewer: reviewer.into(),
            escalated_entry_id: escalated_entry_id.into(),
            escalation_target: escalation_target.into(),
            reason: reason.into(),
        },
    )
}

pub fn log_kill_switch<S: ActionStorage>(
    storage: &mut S,
    actor: &OversightActor,
    reviewer: impl Into<String>,
    halted_entry_id: Option<String>,
    scope: impl Into<String>,
    reason: impl Into<String>,
) -> Result<ActionEntry, CollectorError> {
    log_oversight_event(
        storage,
        actor,
        OversightEvent::KillSwitch {
            reviewer: reviewer.into(),
            halted_entry_id,
            scope: scope.into(),
            reason: reason.into(),
        },
    )
}
