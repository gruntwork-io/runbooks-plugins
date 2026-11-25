//! Generates `base.rs` and `credential.rs` in `OUT_DIR` from the protocol's
//! JSON Schemas in `schema/`: one Rust item per `$defs` entry.
//!
//! typify resolves a `$ref` by its last path segment and ignores the file, so
//! `base.schema.json#/$defs/configureParams` in the credential schema would
//! resolve to the credential schema's own `configureParams`. This script
//! copies the base definitions into the credential schema under a `base`
//! prefix and points those refs at the copies, as Runbooks'
//! `scripts/plugin-types.ts` does. Each copy is then replaced by the type
//! already generated in `crate::base`, so `Id` is one Rust type.

use std::error::Error;
use std::path::{Path, PathBuf};
use std::{env, fs, iter};

use serde_json::{Map, Value, json};
use typify::{TypeSpace, TypeSpacePatch, TypeSpaceSettings};

const BASE: &str = "base.schema.json";
const CREDENTIAL: &str = "credential.schema.json";

/// Objects in the base schema whose unlisted properties the generated type
/// keeps. typify drops the properties an object doesn't list unless its
/// `additionalProperties` is a schema; `{}` allows the same values as
/// leaving it out, and typify then keeps the rest in an `extra` map. These
/// carry a kind's own fields: a `signIn.prompt`'s url and code, a
/// `requirementNotMet` error's unmet requirements.
const OPEN_OBJECTS: [&str; 2] = [
    "/notification/properties/params",
    "/rpcError/properties/data",
];

fn main() -> Result<(), Box<dyn Error>> {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR")?);
    let schema_dir = manifest_dir.join("../../schema");
    let out_dir = PathBuf::from(env::var("OUT_DIR")?);
    rerun_if_changed(&manifest_dir.join("build.rs"));

    let mut base = read_defs(&schema_dir.join(BASE))?;
    let credential = read_defs(&schema_dir.join(CREDENTIAL))?;

    for pointer in OPEN_OBJECTS {
        base.pointer_mut(pointer)
            .and_then(Value::as_object_mut)
            .ok_or_else(|| format!("{BASE}: expected an object at #/$defs{pointer}"))?
            .insert("additionalProperties".to_owned(), json!({}));
    }

    let mut base_settings = settings()?;
    base_settings.with_patch(
        "Id",
        TypeSpacePatch::default()
            .with_derive("PartialEq")
            .with_derive("Eq")
            .with_derive("Hash"),
    );
    write_types(&out_dir.join("base.rs"), &base_settings, &base)?;

    let mut credential_settings = settings()?;
    let mut defs = Map::new();
    for (name, schema) in object(base)? {
        let copy = prefixed("base", &name);
        credential_settings.with_replacement(
            prefixed("", &copy),
            format!("crate::base::{}", prefixed("", &name)),
            iter::empty(),
        );
        defs.insert(copy, schema);
    }
    for (name, schema) in object(credential)? {
        defs.insert(name, rewrite_refs(schema, BASE, "base")?);
    }
    write_types(
        &out_dir.join("credential.rs"),
        &credential_settings,
        &Value::Object(defs),
    )?;
    Ok(())
}

fn settings() -> Result<TypeSpaceSettings, serde_json::Error> {
    let mut settings = TypeSpaceSettings::default();
    // typify maps `date-time` to chrono's type by default.
    settings.with_conversion(
        serde_json::from_value(json!({ "type": "string", "format": "date-time" }))?,
        "crate::Timestamp",
        iter::empty(),
    );
    Ok(settings)
}

fn rerun_if_changed(path: &Path) {
    println!("cargo::rerun-if-changed={}", path.display());
}

/// The schema file's `$defs` object.
fn read_defs(path: &Path) -> Result<Value, Box<dyn Error>> {
    rerun_if_changed(path);
    let text = fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let mut schema: Value =
        serde_json::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))?;
    match schema.get_mut("$defs").map(Value::take) {
        Some(defs @ Value::Object(_)) => Ok(defs),
        _ => Err(format!("{}: expected a `$defs` object", path.display()).into()),
    }
}

fn object(value: Value) -> Result<Map<String, Value>, String> {
    match value {
        Value::Object(map) => Ok(map),
        other @ (Value::Null
        | Value::Bool(_)
        | Value::Number(_)
        | Value::String(_)
        | Value::Array(_)) => Err(format!("expected an object, found {other}")),
    }
}

/// Points every `$ref` into `file` at the copy of its definition under `prefix`.
fn rewrite_refs(value: Value, file: &str, prefix: &str) -> Result<Value, Box<dyn Error>> {
    Ok(match value {
        Value::Array(items) => Value::Array(
            items
                .into_iter()
                .map(|item| rewrite_refs(item, file, prefix))
                .collect::<Result<_, _>>()?,
        ),
        Value::Object(object) => {
            let mut out = Map::new();
            for (key, child) in object {
                let child = match (key.as_str(), child) {
                    ("$ref", Value::String(target)) if !target.starts_with('#') => {
                        let name = target
                            .strip_prefix(file)
                            .and_then(|rest| rest.strip_prefix("#/$defs/"))
                            .ok_or_else(|| format!("unresolved $ref {target}"))?;
                        Value::String(format!("#/$defs/{}", prefixed(prefix, name)))
                    }
                    (_, child) => rewrite_refs(child, file, prefix)?,
                };
                out.insert(key, child);
            }
            Value::Object(out)
        }
        leaf @ (Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_)) => leaf,
    })
}

fn write_types(
    path: &Path,
    settings: &TypeSpaceSettings,
    defs: &Value,
) -> Result<(), Box<dyn Error>> {
    let mut type_space = TypeSpace::new(settings);
    type_space.add_root_schema(serde_json::from_value(json!({ "$defs": defs }))?)?;
    fs::write(path, type_space.to_stream()?.to_string())?;
    Ok(())
}

/// `prefix` followed by `name` with its first letter in upper case:
/// `prefixed("base", "id")` is `baseId`, and `prefixed("", "id")` is `Id`,
/// the name typify gives the type.
fn prefixed(prefix: &str, name: &str) -> String {
    let mut chars = name.chars();
    chars.next().map_or_else(
        || prefix.to_owned(),
        |first| format!("{prefix}{}{}", first.to_uppercase(), chars.as_str()),
    )
}
