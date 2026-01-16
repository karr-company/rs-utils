use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

#[derive(Deserialize, Serialize, Debug, Clone, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct Vehicle {
    pub registration_number: String,
    pub tax_status: Option<String>,
    pub fuel_type: Option<String>,
    pub tax_due_date: Option<String>,
    pub wheelplan: Option<String>,
    pub type_approval: Option<String>,
    pub revenue_weight: Option<u32>,
    #[serde(alias = "euroStatus")]
    pub euro: Option<String>,
    pub co2_emissions: Option<u32>,
    pub engine_capacity: Option<u32>,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ScannedVehicleFine {
    pub vrm: Option<String>,
    pub issue_date: Option<String>,
    pub penalty_after_days: Option<u64>,
    pub pcn: Option<String>,
    pub authority: Option<String>,
    pub base_price: Option<u64>,
    pub penalty_price: Option<u64>,
    pub reduced_price: Option<u64>,
    pub reduced_before_days: Option<u64>,
}

#[derive(Debug, PartialEq, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub enum Operator {
    Equals,
    NotEquals,
    Gt,
    Gte,
    Lt,
    Lte,
    Contains,
    In,
    StartsWith,
}

#[derive(Debug, Copy, Clone, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub enum Field {
    Wheelplan,
    RevenueWeight,
    Euro,
    FuelType,
    TypeApproval,
}

pub enum FieldValue<'a> {
    Str(&'a str),
    Num(u32),
}

#[derive(Debug)]
pub enum Predicate {
    StringField {
        field: Field,
        op: Operator,
        value: String,
    },
    NumberField {
        field: Field,
        op: Operator,
        value: u32,
    },
    StringWithArrayValueField {
        field: Field,
        op: Operator,
        value: Vec<String>,
    },
}

impl Predicate {
    #[inline]
    pub fn evaluate(&self, entity: &Vehicle) -> bool {
        match self {
            Predicate::StringField { field, op, value } => {
                let field_value = match entity.get(*field) {
                    Some(FieldValue::Str(s)) => Some(s),
                    _ => None,
                };

                match (field_value, op) {
                    (Some(v), Operator::Equals) => v == *value,
                    (Some(v), Operator::StartsWith) => v.starts_with(value),
                    (Some(v), Operator::NotEquals) => v != *value,
                    (Some(v), Operator::Contains) => v.contains(value),
                    _ => false,
                }
            }

            Predicate::NumberField { field, op, value } => {
                let field_value = match entity.get(*field) {
                    Some(FieldValue::Num(n)) => Some(n),
                    _ => None,
                };

                match (field_value, op) {
                    (Some(v), Operator::Gt) => v > *value,
                    (Some(v), Operator::Gte) => v >= *value,
                    (Some(v), Operator::Lt) => v < *value,
                    (Some(v), Operator::Lte) => v <= *value,
                    _ => false,
                }
            }

            Predicate::StringWithArrayValueField { field, op, value } => {
                let field_value = match entity.get(*field) {
                    Some(FieldValue::Str(s)) => Some(s),
                    _ => None,
                };

                match (field_value, op) {
                    (Some(v), Operator::In) => value.contains(&v.to_string()),
                    _ => false,
                }
            }
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct Action {
    pub class: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ResultType {
    Boolean,
    Class,
}


#[derive(Debug, Deserialize, PartialEq)]
#[serde(untagged)]
pub enum ResultValue {
    Boolean(bool),
    Class { class: String },
}

impl ResultValue {
    pub fn is_truthy(&self) -> bool {
        match self {
            ResultValue::Boolean(true) => true,
            ResultValue::Boolean(false) => false,
            ResultValue::Class { .. } => true,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum Condition {
    Any { any: Vec<Condition> },
    All { all: Vec<Condition> },
    Not { not: Box<Condition> },
    Always { always: bool },
    Predicate {
        field: Field,
        op: Operator,
        value: serde_json::Value,
    },
}

impl Condition {
    #[inline]
    pub fn evaluate(&self, entity: &Vehicle) -> bool {
        match self {
            Condition::Any { any } => any.iter().any(|cond| cond.evaluate(entity)),
            Condition::All { all } => all.iter().all(|cond| cond.evaluate(entity)),
            Condition::Not { not } => !not.evaluate(entity),
            Condition::Always { always } => *always,
            Condition::Predicate { field, op, value } => {
                let predicate = if op == &Operator::In {
                    let values: Vec<String> = value
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|val| val.as_str().unwrap().to_string())
                        .collect();
                    Predicate::StringWithArrayValueField {
                        field: *field,
                        op: op.clone(),
                        value: values,
                    }
                } else if let Some(num_value) = value.as_u64() {
                    Predicate::NumberField {
                        field: *field,
                        op: op.clone(),
                        value: num_value as u32,
                    }
                } else {
                    Predicate::StringField {
                        field: *field,
                        op: op.clone(),
                        value: value.as_str().unwrap().to_string(),
                    }
                };
                predicate.evaluate(entity)
            }
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct Rule {
    pub description: Option<String>,
    pub when: Condition,
    pub then: Option<ResultValue>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RuleEngine {
    pub road_id: String,
    pub result_type: ResultType,
    pub rules: Vec<Rule>,
    pub default: ResultValue,
}

impl RuleEngine {
    pub fn from_json(json_str: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json_str)
    }

    pub fn evaluate(&self, entity: &Vehicle) -> &ResultValue {
        for rule in &self.rules {
            if rule.when.evaluate(entity) {
                if let Some(result) = &rule.then {
                    return result;
                }
            }
        }
        &self.default
    }
}

impl Vehicle {
    pub fn parse_euro_status(&self) -> Option<u8> {
        let bytes = self.euro.as_ref()?.as_bytes();

        // 1️⃣ Try to find Arabic numerals 1–6
        for &b in bytes {
            match b {
                b'1' => return Some(1),
                b'2' => return Some(2),
                b'3' => return Some(3),
                b'4' => return Some(4),
                b'5' => return Some(5),
                b'6' => return Some(6),
                _ => {}
            }
        }

        // 2️⃣ Scan for Roman numerals (case-insensitive)
        let mut i = 0;
        while i < bytes.len() {
            let c = bytes[i].to_ascii_uppercase();

            if c == b'I' {
                if bytes.get(i + 1).map(|b| b.to_ascii_uppercase()) == Some(b'V') {
                    return Some(4);
                }
                if bytes.get(i + 2).map(|b| b.to_ascii_uppercase()) == Some(b'I') {
                    return Some(3);
                }
                if bytes.get(i + 1).map(|b| b.to_ascii_uppercase()) == Some(b'I') {
                    return Some(2);
                }
                return Some(1);
            }

            if c == b'V' {
                if bytes.get(i + 1).map(|b| b.to_ascii_uppercase()) == Some(b'I') {
                    return Some(6);
                }
                return Some(5);
            }

            i += 1;
        }

        None
    }

    pub fn get(&self, field: Field) -> Option<FieldValue<'_>> {
        match field {
            Field::Wheelplan => self.wheelplan.as_deref().map(FieldValue::Str),
            Field::RevenueWeight => self.revenue_weight.map(FieldValue::Num),
            Field::Euro => self.parse_euro_status().map(|v| FieldValue::Num(v.into())),
            Field::FuelType => self.fuel_type.as_deref().map(FieldValue::Str),
            Field::TypeApproval => self.type_approval.as_deref().map(FieldValue::Str),
        }
    }
}

mod tests {
    #[cfg(test)]
    use super::*;

    #[test]
    fn test_evaluate_rule_engine() {
        let json_str = r#"
        {
            "roadId": "example_road",
            "resultType": "BOOLEAN",
            "rules": [
                {
                    "description": "Check if Euro status is at least 4",
                    "when": {
                        "all": [
                            {
                                "field": "euro",
                                "op": "gte",
                                "value": 4
                            }
                        ]
                    },
                    "then": true
                }
            ],
            "default": false
        }
        "#;

        let engine = RuleEngine::from_json(json_str).unwrap();

        let vehicle = Vehicle {
            registration_number: "ABC123".to_string(),
            tax_status: None,
            fuel_type: None,
            tax_due_date: None,
            wheelplan: None,
            type_approval: None,
            revenue_weight: None,
            euro: Some("Euro 5".to_string()),
            co2_emissions: None,
            engine_capacity: None,
        };

        let result = engine.evaluate(&vehicle);
        assert_eq!(result, &ResultValue::Boolean(true));
    }
}
