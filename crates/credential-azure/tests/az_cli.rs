//! The real adapter, [`AzCli`], on every OS CI runs, with no Azure CLI
//! installed: a missing `az`, and a script in its place.

#[path = "common/scripted_az.rs"]
mod scripted_az;

use std::error::Error;
use std::path::Path;
use std::time::Duration;

use runbooks_credential_azure::az::{Az, AzCli, AzDir, DeviceCode, Interactive, Listing};
use runbooks_credential_azure::ids::{ClientId, ObjectId, SubscriptionId, TenantId, TenantRef};
use runbooks_credential_azure::process_tree::Killer;
use runbooks_credential_azure::service_principal::{Credential, Secret, ServicePrincipal};
use runbooks_plugin_protocol::credential::ErrorKind;
use serde_json::json;
use tokio::sync::oneshot;
use tokio::time::timeout;

use scripted_az::{DEVICE_LINE, ScriptedAz, token};

type TestResult = Result<(), Box<dyn Error>>;

/// How long a test waits for one call. Each runs a script in a moment, so
/// a call that never ends fails its test rather than hanging the run.
const WAIT: Duration = Duration::from_secs(10);

/// `call`, or an error once [`WAIT`] has passed. Calls are boxed: each
/// holds a whole `az` run.
async fn bounded<T>(call: impl Future<Output = T>) -> Result<T, Box<dyn Error>> {
    Ok(timeout(WAIT, call).await?)
}

const CONTOSO: &str = "11111111-1111-4111-8111-111111111111";
const PROD: &str = "aaaaaaaa-0000-4000-8000-000000000001";
const OBJECT_ID: &str = "00000000-0000-4000-8000-0000000000a1";
const CLIENT: &str = "33333333-3333-4333-8333-333333333333";
/// Letters and digits only, so the Windows script can echo it.
const SECRET: &str = "Sp7SecretValue9";

fn service_principal(credential: Credential) -> Result<ServicePrincipal, Box<dyn Error>> {
    Ok(ServicePrincipal {
        client_id: ClientId::parse(CLIENT).ok_or("client id")?,
        tenant: TenantRef::parse(CONTOSO).ok_or("tenant")?,
        credential,
    })
}

fn ids() -> Result<(TenantId, SubscriptionId, ObjectId), Box<dyn Error>> {
    Ok((
        TenantId::parse(CONTOSO).ok_or("tenant")?,
        SubscriptionId::parse(PROD).ok_or("subscription")?,
        ObjectId::parse(OBJECT_ID).ok_or("object id")?,
    ))
}

fn az_dir(config: &Path, extensions: Option<&Path>) -> AzDir {
    AzDir {
        config: config.to_owned(),
        extensions: extensions.map(Path::to_owned),
    }
}

#[tokio::test]
async fn without_az_every_call_is_tool_missing() -> TestResult {
    let temp = tempfile::tempdir()?;
    let dir = az_dir(temp.path(), None);
    let (tenant, subscription, object_id) = ids()?;
    let missing = temp.path().join("not-there").join("az");
    for az in [
        AzCli::new(None, Vec::new(), Killer::ChildOnly),
        AzCli::new(Some(missing), Vec::new(), Killer::ChildOnly),
    ] {
        let (sender, _receiver) = oneshot::channel();
        let tenant = TenantRef::Id(tenant.clone());
        let principal = service_principal(Credential::Secret(Secret::new(SECRET.to_owned())))?;
        let kinds = [
            az.login(&dir, Interactive::Browser, None, sender)
                .await
                .err(),
            az.login_service_principal(&dir, &principal).await.err(),
            az.principal(&dir, Some(&tenant)).await.err(),
            az.accounts(&dir, Listing::Saved).await.err(),
            az.tenants(&dir).await.err(),
            az.set_subscription(&dir, &subscription).await.err(),
            az.role_names(&dir, "/", &object_id).await.err(),
        ];
        for error in kinds {
            let error = error.ok_or("a call without az succeeded")?;
            assert_eq!(error.kind(), ErrorKind::ToolMissing, "{error}");
            assert!(
                error
                    .message()
                    .starts_with("The Azure CLI (az) isn't installed")
                    && error
                        .message()
                        .contains("https://learn.microsoft.com/cli/azure/install-azure-cli"),
                "{error}"
            );
        }
    }
    Ok(())
}

#[tokio::test]
async fn each_call_runs_az_quietly_in_the_sign_ins_config_dir() -> TestResult {
    let scripted = ScriptedAz::new()?;
    scripted.respond(
        "account-list.out",
        &json!([{"id": PROD, "name": "Prod", "tenantId": CONTOSO, "state": "Enabled"}]).to_string(),
    )?;
    scripted.respond(
        "account-get-access-token.out",
        &json!({"accessToken": token()}).to_string(),
    )?;
    scripted.respond(
        "rest.out",
        &json!({"value": [{"tenantId": CONTOSO, "displayName": "Contoso"}]}).to_string(),
    )?;
    scripted.respond(
        "role-assignment.out",
        &json!([{"roleDefinitionName": "Owner"}, {"roleDefinitionName": "Reader"}]).to_string(),
    )?;
    let (config, extensions) = (tempfile::tempdir()?, tempfile::tempdir()?);
    let dir = az_dir(config.path(), Some(extensions.path()));
    let az = AzCli::new(
        Some(scripted.program()),
        scripted.env(),
        scripted_az::killer(),
    );
    let (tenant, subscription, object_id) = ids()?;

    let accounts = bounded(Box::pin(az.accounts(&dir, Listing::Saved))).await??;
    assert_eq!(accounts.subscriptions.len(), 1);
    let refreshed = bounded(Box::pin(az.accounts(&dir, Listing::Refreshed))).await??;
    assert_eq!(refreshed, accounts);
    let principal = bounded(Box::pin(
        az.principal(&dir, Some(&TenantRef::Id(tenant.clone()))),
    ))
    .await??;
    assert_eq!(principal.name, "ana@contoso.com");
    assert_eq!(principal.tenant_id, tenant);
    let tenants = bounded(Box::pin(az.tenants(&dir))).await??;
    assert_eq!(
        tenants.first().and_then(|t| t.name.as_deref()),
        Some("Contoso")
    );
    bounded(Box::pin(az.set_subscription(&dir, &subscription))).await??;
    let roles = bounded(Box::pin(az.role_names(
        &dir,
        &format!("/subscriptions/{PROD}"),
        &object_id,
    )))
    .await??;
    assert_eq!(roles.into_iter().collect::<Vec<_>>(), ["owner", "reader"]);

    let calls = scripted.calls()?;
    assert_eq!(calls.len(), 6, "{calls:?}");
    let config_dir = config.path().to_str().ok_or("not UTF-8")?;
    let extension_dir = extensions.path().to_str().ok_or("not UTF-8")?;
    for call in &calls {
        assert_eq!(call.config_dir, config_dir, "{call:?}");
        assert_eq!(call.extension_dir, extension_dir, "{call:?}");
        assert_eq!(call.only_show_errors, "true", "{call:?}");
        assert!(call.args.contains("--only-show-errors"), "{call:?}");
    }
    let args: Vec<&str> = calls.iter().map(|call| call.args.as_str()).collect();
    assert_eq!(
        args.get(..2),
        Some(
            &[
                "account list --all -o json --only-show-errors",
                "account list --all --refresh -o json --only-show-errors"
            ][..]
        )
    );
    assert!(
        args.iter()
            .any(|a| a.contains(&format!("get-access-token --tenant {CONTOSO}"))),
        "{args:?}"
    );
    assert!(
        args.iter()
            .any(|a| a.contains(&format!("account set --subscription {PROD}"))),
        "{args:?}"
    );
    assert!(
        args.iter().any(|a| a.contains(&format!(
            "--assignee-object-id {OBJECT_ID} --scope /subscriptions/{PROD} --include-inherited --include-groups"
        ))),
        "{args:?}"
    );
    Ok(())
}

#[tokio::test]
async fn a_device_code_is_sent_as_soon_as_az_prints_it() -> TestResult {
    let scripted = ScriptedAz::new()?;
    scripted.respond("login.err", &format!("WARNING: starting\n{DEVICE_LINE}\n"))?;
    let config = tempfile::tempdir()?;
    let az = AzCli::new(
        Some(scripted.program()),
        scripted.env(),
        scripted_az::killer(),
    );
    let (sender, receiver) = oneshot::channel();
    let tenant = TenantRef::parse("contoso.onmicrosoft.com").ok_or("tenant")?;
    bounded(Box::pin(az.login(
        &az_dir(config.path(), None),
        Interactive::DeviceCode,
        Some(&tenant),
        sender,
    )))
    .await??;
    assert_eq!(
        bounded(receiver).await??,
        DeviceCode {
            url: "https://microsoft.com/devicelogin".to_owned(),
            code: "SCRIPTED1".to_owned()
        }
    );
    let calls = scripted.calls()?;
    let call = calls.first().ok_or("no call")?;
    assert!(
        call.args.starts_with("login --allow-no-subscriptions"),
        "{call:?}"
    );
    assert!(
        call.args
            .contains("--use-device-code --tenant contoso.onmicrosoft.com"),
        "{call:?}"
    );
    assert_eq!(
        call.extension_dir, "",
        "a fresh sign-in keeps az's own extension dir"
    );
    Ok(())
}

#[tokio::test]
async fn a_failure_is_answered_with_its_error_line_and_kind() -> TestResult {
    let scripted = ScriptedAz::new()?;
    scripted.respond("login.fail", "")?;
    scripted.respond(
        "login.err",
        "WARNING: Retrieving tenants.\nERROR: AADSTS50076: Due to a configuration change made by your administrator, you must use multi-factor authentication.\n",
    )?;
    scripted.respond("account-list.fail", "")?;
    scripted.respond(
        "account-list.err",
        "ERROR: Please run 'az login' to setup account.\n",
    )?;
    let config = tempfile::tempdir()?;
    let dir = az_dir(config.path(), None);
    let az = AzCli::new(
        Some(scripted.program()),
        scripted.env(),
        scripted_az::killer(),
    );

    let (sender, _receiver) = oneshot::channel();
    let login = bounded(Box::pin(az.login(&dir, Interactive::Browser, None, sender)))
        .await?
        .err()
        .ok_or("login succeeded")?;
    assert_eq!(login.kind(), ErrorKind::AccessDenied);
    assert!(
        login.message().starts_with("az login failed: AADSTS50076"),
        "{login}"
    );

    let accounts = bounded(Box::pin(az.accounts(&dir, Listing::Saved)))
        .await?
        .err()
        .ok_or("account list succeeded")?;
    assert_eq!(accounts.kind(), ErrorKind::NotSignedIn);
    assert!(
        accounts.message().contains("Please run 'az login'"),
        "{accounts}"
    );
    Ok(())
}

#[tokio::test]
async fn output_that_is_not_what_az_documents_is_never_quoted() -> TestResult {
    let scripted = ScriptedAz::new()?;
    scripted.respond(
        "account-get-access-token.out",
        "{\"accessToken\": 7, \"x\": \"SECRET-SIGNATURE\"",
    )?;
    let config = tempfile::tempdir()?;
    let az = AzCli::new(
        Some(scripted.program()),
        scripted.env(),
        scripted_az::killer(),
    );
    let error = bounded(Box::pin(az.principal(&az_dir(config.path(), None), None)))
        .await?
        .err()
        .ok_or("a malformed token was accepted")?;
    assert_eq!(error.kind(), ErrorKind::Internal);
    assert!(!format!("{error:?}").contains("SECRET"), "{error:?}");
    Ok(())
}

/// A token for a named tenant that az can't get without a new sign-in says
/// to sign in with that tenant, and keeps az's own reason and kind. Without
/// a tenant, az's error is passed on as it is.
#[tokio::test]
async fn a_token_az_cant_get_for_a_tenant_says_to_sign_in_with_it() -> TestResult {
    let scripted = ScriptedAz::new()?;
    scripted.respond("account-get-access-token.fail", "")?;
    scripted.respond(
        "account-get-access-token.err",
        "ERROR: AADSTS50076: Due to a configuration change made by your administrator, you must use multi-factor authentication.\n",
    )?;
    let config = tempfile::tempdir()?;
    let dir = az_dir(config.path(), None);
    let az = AzCli::new(
        Some(scripted.program()),
        scripted.env(),
        scripted_az::killer(),
    );
    let (tenant, _, _) = ids()?;

    let error = bounded(Box::pin(az.principal(&dir, Some(&TenantRef::Id(tenant)))))
        .await?
        .err()
        .ok_or("a token was got")?;
    assert_eq!(error.kind(), ErrorKind::AccessDenied);
    assert!(
        error.message().starts_with(&format!(
            "az could not get a token for tenant {CONTOSO} without signing in again (az account get-access-token failed: AADSTS50076"
        )),
        "{error}"
    );

    let error = bounded(Box::pin(az.principal(&dir, None)))
        .await?
        .err()
        .ok_or("a token was got")?;
    assert_eq!(error.kind(), ErrorKind::AccessDenied);
    assert!(
        error
            .message()
            .starts_with("az account get-access-token failed: AADSTS50076"),
        "{error}"
    );
    Ok(())
}

#[tokio::test]
async fn a_service_principal_secret_goes_on_stdin_and_never_into_a_message() -> TestResult {
    let scripted = ScriptedAz::new()?;
    let config = tempfile::tempdir()?;
    let dir = az_dir(config.path(), None);
    let az = AzCli::new(
        Some(scripted.program()),
        scripted.env(),
        scripted_az::killer(),
    );
    let principal = service_principal(Credential::Secret(Secret::new(SECRET.to_owned())))?;

    az.login_service_principal(&dir, &principal).await?;
    assert_eq!(scripted.stdin()?, SECRET);
    let calls = scripted.calls()?;
    let call = calls.first().ok_or("no call")?;
    assert!(
        call.args.starts_with(&format!(
            "login --service-principal --username {CLIENT} --tenant {CONTOSO} --allow-no-subscriptions"
        )),
        "{call:?}"
    );
    assert!(call.args.contains("--password=@-"), "{call:?}");
    assert!(!call.args.contains(SECRET), "{call:?}");

    // An az that repeats what it read: the message must not.
    scripted.respond("login.fail", "")?;
    scripted.respond(
        "login.err",
        &format!("ERROR: AADSTS7000215: Invalid client secret provided: {SECRET}\n"),
    )?;
    let error = az
        .login_service_principal(&dir, &principal)
        .await
        .err()
        .ok_or("a refused secret signed in")?;
    assert_eq!(error.kind(), ErrorKind::AccessDenied);
    assert!(error.message().contains("AADSTS7000215"), "{error}");
    assert!(!format!("{error:?}").contains(SECRET), "{error:?}");
    Ok(())
}

#[tokio::test]
async fn a_service_principal_certificate_is_passed_by_path() -> TestResult {
    let scripted = ScriptedAz::new()?;
    let config = tempfile::tempdir()?;
    let pem = config.path().join("client-certificate.pem");
    let az = AzCli::new(
        Some(scripted.program()),
        scripted.env(),
        scripted_az::killer(),
    );
    let principal = service_principal(Credential::Certificate(pem.clone()))?;
    az.login_service_principal(&az_dir(config.path(), None), &principal)
        .await?;
    let calls = scripted.calls()?;
    let call = calls.first().ok_or("no call")?;
    let pem = pem.to_str().ok_or("not UTF-8")?;
    assert!(
        call.args.contains(&format!("--certificate {pem}")),
        "{call:?}"
    );
    assert!(!call.args.contains("--password"), "{call:?}");
    assert_eq!(scripted.stdin()?, "", "nothing on stdin");
    Ok(())
}
