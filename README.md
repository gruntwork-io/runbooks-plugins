# runbooks-plugins

Plugins for [Runbooks](https://github.com/gruntwork-io/runbooks): bundled binaries that a Runbooks block uses through JSON-RPC 2.0 over standard input and output.

The first are the credential plugins, which sign in to a cloud and hand a run its environment:

| Binary | Signs in to | How |
|---|---|---|
| `runbooks-credential-aws` | AWS | Environment, profiles, SSO device sign-in, role assumption |
| `runbooks-credential-google` | Google Cloud | Environment, ADC, gcloud, browser sign-in |
| `runbooks-credential-azure` | Azure | `az` for a user, or a service principal |

## Status

Being built as track A of the Runbooks rebuild (gruntwork-io/runbooks, PR stack #519). Nothing is released yet.

## Development

mise installs every tool and runs every gate:

```sh
mise install
mise run check
mise tasks
```

## Releases

1. Create a draft release whose tag is `v<version>`, where `<version>` is the workspace version in `Cargo.toml`, and whose target is a full commit SHA: `gh release create v0.1.0 --draft --target <sha> --generate-notes`.
2. Run [`release.yml`](.github/workflows/release.yml) with that tag: `gh workflow run release.yml -f version=v0.1.0`. It builds each binary at the draft's commit for macOS (arm64 and amd64), Linux (arm64 and amd64) and Windows (amd64), signs and notarizes the macOS ones, and attaches them to the draft with a `SHA256SUMS` file. The Windows ones are not signed.
3. Publish the draft. GitHub then creates the tag at the draft's commit.

Each asset is named `<binary>_<version>_<os>_<arch>`, plus `.exe` on Windows, such as `runbooks-credential-aws_0.1.0_darwin_arm64`. `<os>` is `darwin`, `linux` or `windows`, and `<arch>` is `arm64` or `amd64`.

Signing needs `MACOS_CERTIFICATE`, `MACOS_CERTIFICATE_PASSWORD`, `MACOS_AC_LOGIN`, `MACOS_AC_PASSWORD` and `MACOS_AC_PROVIDER` as repository secrets. A run fails without them.

`mise run dist <target>` and `mise run checksums` make the same files, unsigned, in `target/dist`.

## The protocol

- One JSON object per line: requests on standard input, responses and notifications on standard output, logs on standard error.
- `configure` is the first call. Closing standard input stops the plugin, and cancels a sign-in.
- A credential plugin answers `configure`, `detect`, `signIn`, `targets`, `select`, `env` and `signOut`. Only `env` returns secret values.

Each binary runs the loop in [`runbooks-plugin-transport`](crates/transport), so none writes its own JSON-RPC.

The protocol's JSON Schemas, [`schema/base.schema.json`](schema/base.schema.json) and [`schema/credential.schema.json`](schema/credential.schema.json), live in this repository and are released with the binaries under the protocol version, `PROTOCOL_VERSION` in [`runbooks-plugin-protocol`](crates/protocol). That crate's Rust types, and the TypeScript types in Runbooks, are generated from them.

Runbooks pins each release by version and SHA-256 per binary, OS and architecture, and checks the hash before it starts a binary.

## License

[MPL-2.0](LICENSE)
