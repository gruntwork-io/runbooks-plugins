# runbooks-plugins

Plugins for [Runbooks](https://github.com/gruntwork-io/runbooks): bundled binaries that a Runbooks block uses through JSON-RPC 2.0 over standard input and output.

The first are the credential plugins, which sign in to a cloud and hand a run its environment:

| Binary | Signs in to | How |
|---|---|---|
| AWS | AWS | Environment, profiles, SSO device sign-in, role assumption |
| Google | Google Cloud | Environment, ADC, gcloud, browser sign-in |
| Azure | Azure | `az` for a user, or a service principal |

## Status

Being built as track A of the Runbooks rebuild (gruntwork-io/runbooks, PR stack #519). Nothing is released yet.

## The protocol

- One JSON object per line: requests on standard input, responses and notifications on standard output, logs on standard error.
- `configure` is the first call. Closing standard input stops the plugin, and cancels a sign-in.
- A credential plugin answers `configure`, `detect`, `signIn`, `targets`, `select`, `env` and `signOut`. Only `env` returns secret values.

The protocol's JSON Schema lives in this repository and is released with the binaries under its protocol version. The Rust types here, and the TypeScript types in Runbooks, are generated from it.

Runbooks pins each release by version and SHA-256 per binary, OS and architecture, and checks the hash before it starts a binary.

## License

[MPL-2.0](LICENSE)
