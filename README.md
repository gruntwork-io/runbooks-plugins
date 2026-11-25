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

## The protocol

- One JSON object per line: requests on standard input, responses and notifications on standard output, logs on standard error.
- `configure` is the first call. Closing standard input stops the plugin, and cancels a sign-in.
- A credential plugin answers `configure`, `detect`, `signIn`, `targets`, `select`, `env` and `signOut`. Only `env` returns secret values.

Each binary runs the loop in [`runbooks-plugin-transport`](crates/transport), so none writes its own JSON-RPC.

The protocol's JSON Schemas, [`schema/base.schema.json`](schema/base.schema.json) and [`schema/credential.schema.json`](schema/credential.schema.json), live in this repository and are released with the binaries under the protocol version, `PROTOCOL_VERSION` in [`runbooks-plugin-protocol`](crates/protocol). That crate's Rust types, and the TypeScript types in Runbooks, are generated from them.

Runbooks pins each release by version and SHA-256 per binary, OS and architecture, and checks the hash before it starts a binary.

## License

[MPL-2.0](LICENSE)
