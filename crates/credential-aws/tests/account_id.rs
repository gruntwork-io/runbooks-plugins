//! [`AccountId`]: exactly 12 ASCII digits, and an error that shows what
//! was refused.

use runbooks_credential_aws::AccountId;

#[test]
fn an_account_id_is_twelve_digits() {
    let id = AccountId::parse("012345678901");
    assert_eq!(id.as_ref().map(AccountId::as_str), Ok("012345678901"));
    assert_eq!(id.map(|id| id.to_string()), Ok("012345678901".to_owned()));
    for bad in [
        "",
        "01234567890",
        "0123456789012",
        "01234567890a",
        "0123-5678901",
    ] {
        let error = AccountId::parse(bad).err();
        assert_eq!(
            error.map(|error| error.value),
            Some(bad.to_owned()),
            "{bad:?}"
        );
    }
}

#[test]
fn a_refused_value_is_shown_cut_to_32_characters() {
    let long = "9".repeat(40);
    let error = AccountId::parse(&long).err();
    assert_eq!(
        error.map(|error| error.to_string()),
        Some(format!(
            "{:?} is not an AWS account id: it should be 12 digits",
            "9".repeat(32)
        ))
    );
}
