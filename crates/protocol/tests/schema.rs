//! The schemas are valid draft 2020-12, the plan's example messages survive a
//! round trip through the generated types, and invalid messages are refused
//! by the schema and by the types alike.

use std::error::Error;
use std::fs;
use std::path::Path;

use jsonschema::{Draft, Registry, Validator};
use runbooks_plugin_protocol::{base, credential};
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};

type TestResult = Result<(), Box<dyn Error>>;

const SCHEMAS: [&str; 2] = ["base.schema.json", "credential.schema.json"];

/// Where the registry keeps each schema. Their `$id`s are relative, so
/// credential's `base.schema.json#/...` refs resolve against this.
const ROOT: &str = "json-schema:///";

fn schema(file: &str) -> Result<Value, Box<dyn Error>> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../schema")
        .join(file);
    Ok(serde_json::from_str(&fs::read_to_string(path)?)?)
}

/// A validator for one definition, `base.schema.json#/$defs/request` say,
/// with `format` asserted.
fn validator(def: &str) -> Result<Validator, Box<dyn Error>> {
    let mut registry = Registry::new();
    for file in SCHEMAS {
        registry = registry.add(format!("{ROOT}{file}"), schema(file)?)?;
    }
    let registry = registry.prepare()?;
    Ok(jsonschema::options()
        .with_draft(Draft::Draft202012)
        .with_registry(&registry)
        .should_validate_formats(true)
        .build(&json!({ "$ref": format!("{ROOT}{def}") }))?)
}

/// Asserts `value` is valid for `def`, naming the first error if it isn't.
fn assert_valid(def: &str, value: &Value) -> TestResult {
    validator(def)?
        .validate(value)
        .map_err(|e| format!("{def}: {e} at {}", e.instance_path()))?;
    Ok(())
}

/// Deserializes `value` as `T`, serializes it back, and checks the result is
/// unchanged and still valid for `def`.
fn round_trip<T: Serialize + DeserializeOwned>(def: &str, value: &Value) -> TestResult {
    assert_valid(def, value)?;
    let typed: T = serde_json::from_value(value.clone())?;
    let back = serde_json::to_value(&typed)?;
    assert_eq!(&back, value, "{def} changed in a round trip");
    assert_valid(def, &back)
}

/// Asserts both the schema and the type refuse `value`.
fn assert_refused<T: DeserializeOwned>(def: &str, value: Value) -> TestResult {
    assert!(!validator(def)?.is_valid(&value), "{def} accepted {value}");
    assert!(
        serde_json::from_value::<T>(value.clone()).is_err(),
        "the type for {def} accepted {value}"
    );
    Ok(())
}

#[test]
fn schemas_are_valid_draft_2020_12() -> TestResult {
    for file in SCHEMAS {
        let schema = schema(file)?;
        jsonschema::draft202012::meta::validate(&schema).map_err(|e| format!("{file}: {e}"))?;
    }
    Ok(())
}

#[test]
fn every_definition_compiles_and_its_refs_resolve() -> TestResult {
    for file in SCHEMAS {
        let Some(defs) = schema(file)?
            .get("$defs")
            .and_then(Value::as_object)
            .cloned()
        else {
            return Err(format!("{file} has no $defs").into());
        };
        for def in defs.keys() {
            validator(&format!("{file}#/$defs/{def}"))?;
        }
    }
    Ok(())
}

// The plan's example: an SSO sign-in, its prompt, and its result.

fn sign_in_request() -> Value {
    json!({"jsonrpc":"2.0","id":2,"method":"signIn","params":{"method":"sso","fields":{"startUrl":"https://example.awsapps.com/start","region":"us-east-1"},"pins":{"account":"123456789012"},"requirements":[]}})
}

fn sign_in_prompt() -> Value {
    json!({"jsonrpc":"2.0","method":"signIn.prompt","params":{"request":2,"kind":"openUrl","url":"https://device.sso.us-east-1.amazonaws.com/","code":"ABCD-EFGH"}})
}

fn sign_in_response() -> Value {
    json!({"jsonrpc":"2.0","id":2,"result":{"principal":"arn:aws:sts::123456789012:assumed-role/dev/someone","kind":"role","method":"sso","targets":{"account":{"id":"123456789012","name":"sandbox"},"role":{"id":"dev","name":"dev"}},"expiresAt":"2026-11-24T22:00:00Z"}})
}

#[test]
fn sign_in_request_round_trips() -> TestResult {
    let request = sign_in_request();
    round_trip::<base::Request>("base.schema.json#/$defs/request", &request)?;
    round_trip::<credential::SignInParams>(
        "credential.schema.json#/$defs/signInParams",
        &request["params"],
    )
}

#[test]
fn sign_in_prompt_round_trips_and_names_its_request() -> TestResult {
    let notification = sign_in_prompt();
    round_trip::<base::Notification>("base.schema.json#/$defs/notification", &notification)?;
    round_trip::<credential::SignInPrompt>(
        "credential.schema.json#/$defs/signInPrompt",
        &notification["params"],
    )?;
    let prompt: credential::SignInPrompt = serde_json::from_value(notification["params"].clone())?;
    let request: base::Request = serde_json::from_value(sign_in_request())?;
    assert_eq!(prompt.request, request.id);
    Ok(())
}

#[test]
fn sign_in_result_round_trips() -> TestResult {
    let response = sign_in_response();
    round_trip::<base::ResultResponse>("base.schema.json#/$defs/resultResponse", &response)?;
    round_trip::<credential::SignInResult>(
        "credential.schema.json#/$defs/signInResult",
        &response["result"],
    )
}

#[test]
fn unknown_fields_are_ignored() -> TestResult {
    let mut params = sign_in_request()["params"].take();
    params["addedInALaterVersion"] = json!(true);
    assert_valid("credential.schema.json#/$defs/signInParams", &params)?;
    let typed: credential::SignInParams = serde_json::from_value(params)?;
    assert_eq!(typed.method, "sso");
    Ok(())
}

#[test]
fn a_request_without_a_method_is_refused() -> TestResult {
    let mut request = sign_in_request();
    request
        .as_object_mut()
        .ok_or("not an object")?
        .remove("method");
    assert_refused::<base::Request>("base.schema.json#/$defs/request", request)
}

#[test]
fn a_request_id_that_is_not_an_integer_or_string_is_refused() -> TestResult {
    for id in [json!(1.5), json!(null), json!({"n": 1})] {
        let mut request = sign_in_request();
        request["id"] = id;
        assert_refused::<base::Request>("base.schema.json#/$defs/request", request)?;
    }
    Ok(())
}

#[test]
fn sign_in_params_without_a_method_are_refused() -> TestResult {
    let mut params = sign_in_request()["params"].take();
    params
        .as_object_mut()
        .ok_or("not an object")?
        .remove("method");
    assert_refused::<credential::SignInParams>("credential.schema.json#/$defs/signInParams", params)
}

#[test]
fn a_prompt_of_an_unknown_kind_is_refused() -> TestResult {
    let mut params = sign_in_prompt()["params"].take();
    params["kind"] = json!("openBrowser");
    assert_refused::<credential::SignInPrompt>("credential.schema.json#/$defs/signInPrompt", params)
}

#[test]
fn an_expiry_that_is_not_a_date_time_is_refused() -> TestResult {
    let mut result = sign_in_response()["result"].take();
    result["expiresAt"] = json!("tomorrow");
    assert_refused::<credential::SignInResult>("credential.schema.json#/$defs/signInResult", result)
}

#[test]
fn a_detection_source_of_an_unknown_kind_is_refused() -> TestResult {
    let params = json!({"sources":[{"kind":"keychain"}],"pins":{},"requirements":[]});
    assert_refused::<credential::DetectParams>("credential.schema.json#/$defs/detectParams", params)
}

#[test]
fn an_error_response_round_trips_with_an_integer_code() -> TestResult {
    let response = json!({"jsonrpc":"2.0","id":2,"error":{"code":-32000,"message":"the role is not in account 123456789012","data":{"kind":"pinMismatch"}}});
    round_trip::<base::ErrorResponse>("base.schema.json#/$defs/errorResponse", &response)
}

#[test]
fn an_error_response_to_an_unreadable_request_has_a_null_id() -> TestResult {
    let response = json!({"jsonrpc":"2.0","id":null,"error":{"code":-32700,"message":"the line is not JSON","data":{"kind":"invalidParams"}}});
    round_trip::<base::ErrorResponse>("base.schema.json#/$defs/errorResponse", &response)
}

#[test]
fn error_data_keeps_a_kinds_own_fields() -> TestResult {
    let data = json!({"kind":"requirementNotMet","unmet":[{"kind":"scopes","scopes":["https://www.googleapis.com/auth/cloud-platform"]}]});
    assert_valid("credential.schema.json#/$defs/requirementNotMetData", &data)?;
    let response = json!({"jsonrpc":"2.0","id":"7","error":{"code":-32000,"message":"a scope is missing","data":data}});
    round_trip::<base::ErrorResponse>("base.schema.json#/$defs/errorResponse", &response)
}

#[test]
fn detect_results_round_trip() -> TestResult {
    let found = json!({"found":true,"identity":{"principal":"someone@example.com","kind":"user","method":"gcloud","targets":{"project":{"id":"sandbox-1234","name":"Sandbox"}}},"source":"gcloud"});
    round_trip::<credential::DetectResult>("credential.schema.json#/$defs/detectResult", &found)?;
    round_trip::<credential::DetectResult>(
        "credential.schema.json#/$defs/detectResult",
        &json!({"found":false}),
    )
}
