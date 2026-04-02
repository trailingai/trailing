use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use super::CollectorError;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OtelSpan {
    pub trace_id: String,
    pub span_id: String,
    pub name: String,
    #[serde(default)]
    pub attributes: Map<String, Value>,
    pub start_time: Option<String>,
    pub end_time: Option<String>,
    pub parent_span_id: Option<String>,
    pub status: Option<String>,
}

pub fn parse_otlp_http_json(payload: &str) -> Result<Vec<OtelSpan>, CollectorError> {
    let value: Value = serde_json::from_str(payload)?;
    let spans = match &value {
        Value::Array(items) => items
            .iter()
            .map(parse_span)
            .collect::<Result<Vec<_>, _>>()?,
        Value::Object(object) => {
            if let Some(resource_spans) = object.get("resourceSpans").and_then(Value::as_array) {
                let mut spans = Vec::new();
                for resource_span in resource_spans {
                    let Some(resource_span_object) = resource_span.as_object() else {
                        continue;
                    };

                    for scope_key in ["scopeSpans", "instrumentationLibrarySpans"] {
                        if let Some(scope_spans) = resource_span_object
                            .get(scope_key)
                            .and_then(Value::as_array)
                        {
                            for scope_span in scope_spans {
                                let Some(scope_span_object) = scope_span.as_object() else {
                                    continue;
                                };

                                if let Some(inner_spans) =
                                    scope_span_object.get("spans").and_then(Value::as_array)
                                {
                                    for span in inner_spans {
                                        spans.push(parse_span(span)?);
                                    }
                                }
                            }
                        }
                    }
                }
                spans
            } else if let Some(spans) = object.get("spans").and_then(Value::as_array) {
                spans
                    .iter()
                    .map(parse_span)
                    .collect::<Result<Vec<_>, _>>()?
            } else {
                vec![parse_span(&value)?]
            }
        }
        _ => {
            return Err(CollectorError::InvalidOtelPayload(
                "expected a JSON object or array".to_string(),
            ));
        }
    };

    if spans.is_empty() {
        return Err(CollectorError::InvalidOtelPayload(
            "no spans found in OTLP payload".to_string(),
        ));
    }

    Ok(spans)
}

fn parse_span(value: &Value) -> Result<OtelSpan, CollectorError> {
    let object = value.as_object().ok_or_else(|| {
        CollectorError::InvalidOtelPayload("span entry must be a JSON object".to_string())
    })?;

    Ok(OtelSpan {
        trace_id: get_required_string(object, &["traceId", "trace_id"])?,
        span_id: get_required_string(object, &["spanId", "span_id"])?,
        name: get_required_string(object, &["name"])?,
        attributes: parse_attributes(object.get("attributes")),
        start_time: get_optional_string(object, &["startTimeUnixNano", "start_time"]),
        end_time: get_optional_string(object, &["endTimeUnixNano", "end_time"]),
        parent_span_id: get_optional_string(object, &["parentSpanId", "parent_span_id"]),
        status: parse_status(object.get("status")),
    })
}

fn get_required_string(
    object: &Map<String, Value>,
    keys: &[&'static str],
) -> Result<String, CollectorError> {
    get_optional_string(object, keys).ok_or(CollectorError::MissingField(keys[0]))
}

fn get_optional_string(object: &Map<String, Value>, keys: &[&str]) -> Option<String> {
    keys.iter().find_map(|key| extract_string(object.get(*key)))
}

fn extract_string(value: Option<&Value>) -> Option<String> {
    match value {
        Some(Value::String(raw)) => Some(raw.clone()),
        Some(Value::Number(raw)) => Some(raw.to_string()),
        _ => None,
    }
}

fn parse_attributes(value: Option<&Value>) -> Map<String, Value> {
    match value {
        Some(Value::Object(object)) => object.clone(),
        Some(Value::Array(attributes)) => attributes
            .iter()
            .filter_map(|attribute| {
                let attribute_object = attribute.as_object()?;
                let key = attribute_object.get("key")?.as_str()?.to_string();
                let value = attribute_object
                    .get("value")
                    .map(parse_any_value)
                    .unwrap_or(Value::Null);
                Some((key, value))
            })
            .collect(),
        _ => Map::new(),
    }
}

fn parse_any_value(value: &Value) -> Value {
    let Some(object) = value.as_object() else {
        return value.clone();
    };

    if let Some(string_value) = object.get("stringValue").and_then(Value::as_str) {
        return Value::String(string_value.to_string());
    }
    if let Some(bool_value) = object.get("boolValue").and_then(Value::as_bool) {
        return Value::Bool(bool_value);
    }
    if let Some(int_value) = object.get("intValue") {
        return match int_value {
            Value::String(raw) => raw
                .parse::<i64>()
                .map(Into::into)
                .unwrap_or_else(|_| Value::String(raw.clone())),
            Value::Number(number) => Value::Number(number.clone()),
            _ => Value::Null,
        };
    }
    if let Some(double_value) = object.get("doubleValue").and_then(Value::as_f64) {
        return serde_json::Number::from_f64(double_value)
            .map(Value::Number)
            .unwrap_or(Value::Null);
    }
    if let Some(array_value) = object.get("arrayValue").and_then(Value::as_object) {
        let values = array_value
            .get("values")
            .and_then(Value::as_array)
            .map(|items| items.iter().map(parse_any_value).collect())
            .unwrap_or_default();
        return Value::Array(values);
    }
    if let Some(kvlist_value) = object.get("kvlistValue").and_then(Value::as_object) {
        let map = kvlist_value
            .get("values")
            .and_then(Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .filter_map(|item| {
                        let item_object = item.as_object()?;
                        let key = item_object.get("key")?.as_str()?.to_string();
                        let value = item_object
                            .get("value")
                            .map(parse_any_value)
                            .unwrap_or(Value::Null);
                        Some((key, value))
                    })
                    .collect()
            })
            .unwrap_or_default();
        return Value::Object(map);
    }
    if let Some(bytes_value) = object.get("bytesValue").and_then(Value::as_str) {
        return Value::String(bytes_value.to_string());
    }

    value.clone()
}

fn parse_status(value: Option<&Value>) -> Option<String> {
    match value {
        Some(Value::String(status)) => Some(status.clone()),
        Some(Value::Object(object)) => object
            .get("code")
            .and_then(|code| match code {
                Value::String(raw) => Some(raw.clone()),
                Value::Number(raw) => Some(raw.to_string()),
                _ => None,
            })
            .or_else(|| {
                object
                    .get("message")
                    .and_then(Value::as_str)
                    .map(ToOwned::to_owned)
            }),
        _ => None,
    }
}
