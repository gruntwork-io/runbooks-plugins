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
fn assert_refused<T: DeserializeOwned>(def: &str, value: &Value) -> TestResult {
    assert!(!validator(def)?.is_valid(value), "{def} accepted {value}");
    assert!(
        serde_json::from_value::<T>(value.clone()).is_err(),
        "the type for {def} accepted {value}"
    );
    Ok(())
}

/// Takes the member `key` out of the object `value`.
fn take_member(mut value: Value, key: &str) -> Result<Value, Box<dyn Error>> {
    Ok(value
        .as_object_mut()
        .and_then(|object| object.remove(key))
        .ok_or_else(|| format!("no `{key}` member"))?)
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
        request.get("params").ok_or("no params")?,
    )
}

#[test]
fn sign_in_prompt_round_trips_and_names_its_request() -> TestResult {
    let notification = sign_in_prompt();
    round_trip::<base::Notification>("base.schema.json#/$defs/notification", &notification)?;
    let params = notification.get("params").ok_or("no params")?;
    round_trip::<credential::SignInPrompt>("credential.schema.json#/$defs/signInPrompt", params)?;
    let prompt: credential::SignInPrompt = serde_json::from_value(params.clone())?;
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
        response.get("result").ok_or("no result")?,
    )
}

#[test]
fn unknown_fields_are_ignored() -> TestResult {
    let mut params = take_member(sign_in_request(), "params")?;
    params
        .as_object_mut()
        .ok_or("not an object")?
        .insert("addedInALaterVersion".to_owned(), json!(true));
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
    assert_refused::<base::Request>("base.schema.json#/$defs/request", &request)
}

#[test]
fn a_request_id_that_is_not_an_integer_or_string_is_refused() -> TestResult {
    for id in [json!(1.5), json!(null), json!({"n": 1})] {
        let mut request = sign_in_request();
        request
            .as_object_mut()
            .ok_or("not an object")?
            .insert("id".to_owned(), id);
        assert_refused::<base::Request>("base.schema.json#/$defs/request", &request)?;
    }
    Ok(())
}

#[test]
fn sign_in_params_without_a_method_are_refused() -> TestResult {
    let mut params = take_member(sign_in_request(), "params")?;
    params
        .as_object_mut()
        .ok_or("not an object")?
        .remove("method");
    assert_refused::<credential::SignInParams>(
        "credential.schema.json#/$defs/signInParams",
        &params,
    )
}

#[test]
fn a_prompt_of_an_unknown_kind_is_refused() -> TestResult {
    let mut params = take_member(sign_in_prompt(), "params")?;
    params
        .as_object_mut()
        .ok_or("not an object")?
        .insert("kind".to_owned(), json!("openBrowser"));
    assert_refused::<credential::SignInPrompt>(
        "credential.schema.json#/$defs/signInPrompt",
        &params,
    )
}

#[test]
fn an_expiry_that_is_not_a_date_time_is_refused() -> TestResult {
    let mut result = take_member(sign_in_response(), "result")?;
    result
        .as_object_mut()
        .ok_or("not an object")?
        .insert("expiresAt".to_owned(), json!("tomorrow"));
    assert_refused::<credential::SignInResult>(
        "credential.schema.json#/$defs/signInResult",
        &result,
    )
}

#[test]
fn a_detection_source_of_an_unknown_kind_is_refused() -> TestResult {
    let params = json!({"sources":[{"kind":"keychain"}],"pins":{},"requirements":[]});
    assert_refused::<credential::DetectParams>(
        "credential.schema.json#/$defs/detectParams",
        &params,
    )
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

#[test]
fn the_named_error_codes_are_the_schemas() -> TestResult {
    for code in [
        base::RpcErrorCode::SERVER_ERROR,
        base::RpcErrorCode::INVALID_PARAMS,
        base::RpcErrorCode::INVALID_REQUEST,
        base::RpcErrorCode::METHOD_NOT_FOUND,
        base::RpcErrorCode::PARSE_ERROR,
    ] {
        let error = json!({"code": code, "message": "m", "data": {"kind": "internal"}});
        round_trip::<base::RpcError>("base.schema.json#/$defs/rpcError", &error)?;
    }
    Ok(())
}

#[test]
fn constructed_detect_results_are_valid() -> TestResult {
    let identity: credential::Identity =
        serde_json::from_value(take_member(sign_in_response(), "result")?)?;
    for result in [
        credential::DetectResult::found(identity, "env"),
        credential::DetectResult::not_found(),
    ] {
        let value = serde_json::to_value(&result)?;
        round_trip::<credential::DetectResult>(
            "credential.schema.json#/$defs/detectResult",
            &value,
        )?;
    }
    Ok(())
}

// Runbooks 1808ae07 (draft PR #547): a provider gets its block's settings.

fn configure_params(settings: Option<Value>) -> Value {
    let mut params =
        json!({"protocolVersion":"1","caller":"runbooks/0.31.0","stateDir":"/tmp/state"});
    if let (Some(settings), Some(object)) = (settings, params.as_object_mut()) {
        object.insert("settings".to_owned(), settings);
    }
    params
}

#[test]
fn configure_params_carry_the_blocks_settings_or_none() -> TestResult {
    let def = "credential.schema.json#/$defs/configureParams";
    round_trip::<credential::ConfigureParams>(def, &configure_params(None))?;
    let params = configure_params(Some(json!({"defaultRegion": "us-west-2"})));
    round_trip::<credential::ConfigureParams>(def, &params)?;
    let typed: credential::ConfigureParams = serde_json::from_value(params)?;
    assert_eq!(
        typed.settings.get("defaultRegion").map(String::as_str),
        Some("us-west-2")
    );
    Ok(())
}

#[test]
fn a_setting_that_is_not_a_string_is_refused() -> TestResult {
    assert_refused::<credential::ConfigureParams>(
        "credential.schema.json#/$defs/configureParams",
        &configure_params(Some(json!({"defaultRegion": 7}))),
    )
}

/// Asserts the schema refuses `value`. The generated types don't check an
/// array's `maxItems` or `minItems`, so a bound is the schema's alone: it
/// holds what a plugin sends, and Runbooks checks it when decoding.
fn assert_schema_refuses(def: &str, value: &Value) -> TestResult {
    assert!(!validator(def)?.is_valid(value), "{def} accepted {value}");
    Ok(())
}

/// `count` copies of `item`.
fn items(item: &Value, count: usize) -> Value {
    Value::Array(vec![item.clone(); count])
}

// Runbooks 3362bfd6 (draft PR #547): an identity can carry warnings.

fn identity_with_warnings(warnings: Value) -> Result<Value, Box<dyn Error>> {
    let mut identity = take_member(sign_in_response(), "result")?;
    identity
        .as_object_mut()
        .ok_or("not an object")?
        .insert("warnings".to_owned(), warnings);
    Ok(identity)
}

#[test]
fn an_identity_carries_up_to_ten_warnings() -> TestResult {
    let def = "credential.schema.json#/$defs/identity";
    let warning = json!({"message": "us-gov-east-1 is not enabled for this account"});
    let identity = identity_with_warnings(items(&warning, 10))?;
    round_trip::<credential::Identity>(def, &identity)?;
    let typed: credential::Identity = serde_json::from_value(identity)?;
    assert_eq!(typed.warnings.len(), 10);
    assert_schema_refuses(def, &identity_with_warnings(items(&warning, 11))?)
}

#[test]
fn a_warning_without_a_message_is_refused() -> TestResult {
    assert_refused::<credential::Identity>(
        "credential.schema.json#/$defs/identity",
        &identity_with_warnings(json!([{"text": "no message"}]))?,
    )
}

// Runbooks d4c7da5f (draft PR #547): a sign-in field can list its choices.

fn field_with_choices(choices: &Value) -> Value {
    json!({"name":"profile","label":"Profile","required":true,"secret":false,"choices":choices})
}

#[test]
fn a_field_lists_up_to_a_thousand_choices() -> TestResult {
    let def = "credential.schema.json#/$defs/field";
    let choice = json!({"value": "dev", "label": "dev (us-east-1)"});
    let field = field_with_choices(&items(&choice, 1000));
    round_trip::<credential::Field>(def, &field)?;
    let typed: credential::Field = serde_json::from_value(field)?;
    assert_eq!(
        typed
            .choices
            .first()
            .map(|c| (c.value.as_str(), c.label.as_str())),
        Some(("dev", "dev (us-east-1)"))
    );
    assert_schema_refuses(def, &field_with_choices(&items(&choice, 1001)))
}

#[test]
fn a_choice_without_a_label_is_refused() -> TestResult {
    assert_refused::<credential::Field>(
        "credential.schema.json#/$defs/field",
        &field_with_choices(&json!([{"value": "dev"}])),
    )
}

// Runbooks 333e3840 (draft PR #547): a sign-in method can ask for one field
// of a group.

fn method_with_one_of(one_of: &Value) -> Value {
    json!({"name":"servicePrincipal","label":"Service principal","fields":[],"oneOf":one_of})
}

#[test]
fn a_method_asks_for_one_field_of_up_to_ten_groups_of_two_to_ten() -> TestResult {
    let def = "credential.schema.json#/$defs/method";
    let names: Vec<String> = (0..10).map(|n| format!("field{n}")).collect();
    let method = method_with_one_of(&items(&json!(names), 10));
    round_trip::<credential::Method>(def, &method)?;
    let pair = method_with_one_of(&json!([["clientSecret", "certificate"]]));
    round_trip::<credential::Method>(def, &pair)?;
    let typed: credential::Method = serde_json::from_value(pair)?;
    assert_eq!(typed.one_of, [["clientSecret", "certificate"]]);

    let mut eleven = names;
    eleven.push("field10".to_owned());
    for refused in [
        json!([["clientSecret"]]),
        json!([eleven]),
        items(&json!(["clientSecret", "certificate"]), 11),
    ] {
        assert_schema_refuses(def, &method_with_one_of(&refused))?;
    }
    Ok(())
}

#[test]
fn a_one_of_group_that_is_not_names_is_refused() -> TestResult {
    assert_refused::<credential::Method>(
        "credential.schema.json#/$defs/method",
        &method_with_one_of(&json!([["clientSecret", 7]])),
    )
}

// Runbooks cdd84ffa (draft PR #547): a sign-in method can be unavailable.

fn method_unavailable(unavailable: &Value) -> Value {
    json!({"name":"cli","label":"Azure CLI","fields":[],"unavailable":unavailable})
}

#[test]
fn an_unavailable_method_says_why_with_an_error_kind() -> TestResult {
    let def = "credential.schema.json#/$defs/method";
    let method =
        method_unavailable(&json!({"kind": "toolMissing", "message": "az is not installed"}));
    round_trip::<credential::Method>(def, &method)?;
    let typed: credential::Method = serde_json::from_value(method)?;
    assert_eq!(
        typed.unavailable.map(|why| (why.kind, why.message)),
        Some((
            credential::ErrorKind::ToolMissing,
            "az is not installed".to_owned()
        ))
    );
    Ok(())
}

#[test]
fn an_unavailable_method_without_a_known_kind_or_a_message_is_refused() -> TestResult {
    for unavailable in [
        json!({"kind": "notInstalled", "message": "az is not installed"}),
        json!({"kind": "toolMissing"}),
    ] {
        assert_refused::<credential::Method>(
            "credential.schema.json#/$defs/method",
            &method_unavailable(&unavailable),
        )?;
    }
    Ok(())
}

// Runbooks cd5ebe6b (draft PR #547): a target level can be optional.

#[test]
fn a_level_may_be_optional() -> TestResult {
    let def = "credential.schema.json#/$defs/level";
    let level = json!({"name":"subscription","label":"Subscription","chosen":"afterSignIn","optional":true});
    round_trip::<credential::Level>(def, &level)?;
    let typed: credential::Level = serde_json::from_value(level)?;
    assert_eq!(typed.optional, Some(true));
    assert_refused::<credential::Level>(
        def,
        &json!({"name":"subscription","label":"Subscription","chosen":"afterSignIn","optional":"yes"}),
    )
}

#[test]
fn an_identity_and_a_select_may_hold_a_null_target() -> TestResult {
    let identity = json!({"principal":"ana@contoso.com","kind":"user","method":"cli","targets":{"tenant":{"id":"11111111-1111-4111-8111-111111111111","name":"Contoso"},"subscription":null}});
    round_trip::<credential::Identity>("credential.schema.json#/$defs/identity", &identity)?;
    let typed: credential::Identity = serde_json::from_value(identity)?;
    assert!(matches!(typed.targets.get("subscription"), Some(None)));

    let select =
        json!({"targets":{"tenant":"11111111-1111-4111-8111-111111111111","subscription":null}});
    round_trip::<credential::SelectParams>("credential.schema.json#/$defs/selectParams", &select)?;
    let typed: credential::SelectParams = serde_json::from_value(select)?;
    assert!(matches!(typed.targets.get("subscription"), Some(None)));
    Ok(())
}

#[test]
fn a_pin_always_names_a_target() -> TestResult {
    assert_refused::<credential::Pins>(
        "credential.schema.json#/$defs/pins",
        &json!({"subscription": null}),
    )
}

// Runbooks 0705c832 (draft PR #547): a values detection source names its
// block.

#[test]
fn a_values_source_names_its_block() -> TestResult {
    let def = "credential.schema.json#/$defs/detectParams";
    let params = json!({"sources":[{"kind":"values","values":{"AWS_ACCESS_KEY_ID":"AKIAKEYS"},"from":"keys"}],"pins":{},"requirements":[]});
    round_trip::<credential::DetectParams>(def, &params)?;
    let typed: credential::DetectParams = serde_json::from_value(params)?;
    assert!(
        matches!(typed.sources.first(), Some(credential::Source::Values { from, .. }) if from == "keys"),
        "{:?}",
        typed.sources
    );
    assert_refused::<credential::DetectParams>(
        def,
        &json!({"sources":[{"kind":"values","values":{}}],"pins":{},"requirements":[]}),
    )
}

#[test]
fn an_env_values_kind_sets_sensitive_and_file() -> TestResult {
    use credential::{EnvValue, EnvValueKind, EnvValueToItem};
    for (kind, sensitive, file) in [
        (EnvValueKind::Plain, false, false),
        (EnvValueKind::Sensitive, true, false),
        (EnvValueKind::File, false, true),
    ] {
        let value = EnvValue::new("NAME", "/abs/path", kind, vec![EnvValueToItem::Env]);
        let value = serde_json::to_value(value)?;
        assert_valid("credential.schema.json#/$defs/envValue", &value)?;
        assert_eq!(
            (value.get("sensitive"), value.get("file")),
            (Some(&json!(sensitive)), Some(&json!(file))),
            "{kind:?}"
        );
    }
    Ok(())
}
