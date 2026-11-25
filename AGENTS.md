## Working agreement

- Work in small increments. Stop after each one so the operator can review it.
- The operator makes every commit. Never run `git commit`, `git push`, or anything else that
  writes history.
- Use the latest version of every tool and dependency.
- Add a tool, crate, or recipe only when something needs it, and say why it earns its place.
- Never add a `Co-Authored-By` trailer or a "Generated with Claude Code" footer to a commit, pull
  request, issue, or comment.

## General

- Read the `rust` skill before writing, editing, or reviewing Rust.

- Make it unrepresentable. If a type can rule out a bug class, use the type. A test asserting the bad state never happens is the fallback. A type that removes a state is not speculative abstraction.
  - Two arguments that must agree become one: take the source and derive the other inside.
  - One validator per concept, as a type, so no second copy drifts from it.
  - A proof type has a private constructor. Only the function that did the checking calls it.

- When writing for human consumption — comments, replies — use as few words as possible. Pick every word deliberately. Less is more.

- Don't touch blocks of code unrelated to the feature you implement.

- Edit files with your standard file-editing tools. Never rewrite them with shell one-liners like `sed -i`, `perl -pi` or heredocs.

- Do the simplest thing that works. Write the least code that solves the actual problem: no speculative abstraction, no config for a case that doesn't exist yet, no layer that only forwards a call. When in doubt, leave it out.

- Before starting work review the self-review skill to avoid churn later.

- Do not add comments unless absolutely necessary. Never restate the code, and keep the comments that exist true as the code drifts.

- Comments state current facts only: no "today X, once Y ships" framing, no measurements or investigation notes, no notes about removed or moved code, and nothing about another component's behavior.

- A README or doc comment claims only what a test proves.

- No positional `bool` params: use an enum.

- Never add a wrapper, alias, or default-argument shim whose only purpose is sparing callers a signature change; update every call site instead, including tests. A wrapper earns its place only when it isolates a dependency, adapts an interface, or keeps a genuinely stable public API; "avoids churn" is not a reason.

- Keep functions short and data scoped as tightly as the code allows.

- Code an agent wrote is not precedent. Never justify a choice by pointing at existing agent-written code; justify it on its merits.

- Verify, don't assume. Read a dependency's source rather than assuming typical behavior. Check an external API's shape against its official documentation and cite the link. Take versions from the latest release (`mise latest` for tools), never from a local clone. Probe a library's behavior with a test in the project, not a throwaway program.

- Sanity check everything. Run what you changed and watch it behave as intended. A new check, lint, or hook is proven only once it has failed on bad input.

## Testing

### Unit Tests

Anything with no network calls. A unit test may depend on external binaries such as git. Working
against an on-disk git remote is still a unit test.

Most modules implement unit tests by extracting their business logic to pure functions.

Test behavior through public APIs. Name a test for the behavior it checks.

- Write the test first. Build any test infrastructure, run the test and watch it fail for the reason you expect, then implement until it passes.

- Test against the real format at the boundary: recorded platform events, the real environment, real concurrent invocations. A test built from your own model of the input proves only the model.

- Code that can run concurrently (threads, tasks, or processes sharing a file) gets a test that runs it concurrently.

- Test the inputs that break naive code: empty, corrupt, non-UTF-8 and binary.

- Create the most minimal tests possible to exercise the feature. Prefer higher level tests that guarantee a contract. Be judicious with test creation. Avoid mocks where possible.

- LLMs like to write code that tests mocks. The test becomes a tautology (this function was called with this arg). It doesn't prove any behavior beyond the compiler.

- Pin observable behavior: return values, files written, errors returned, counters advanced. Never assert on captured log output. If a log line is the only signal, expose a status field or counter.

- Pass what a test needs (a timeout, a limit) as a parameter, so the test does not depend on private consts.

- A test that is slow because it must reach a hardcoded cap or delay (writing 1,000,000 entries, waiting out a 15s forwarding delay) signals a design problem. Make the limit injectable and trip it with a small value. Inject a fake for a clock, subprocess, or network. Keep the real magnitude only when it is the behavior under test.

- Path escape tests use neutral placeholders: `/abs/path` for an absolute path and `../../outside` for a relative escape. Never `/etc/passwd` or SSH key paths, unless the test needs that real path.

- Fuzz parsers and sanitizers that read untrusted input.

## Bounds

- Bound every recursion, every loop over untrusted structure, task fan-out, and input that a remote or fetched artifact controls.

- Every network call takes a timeout and makes a bounded number of attempts.

- A child process that can wait on the network or a prompt gets a timeout that kills it.

## Untrusted content

- Anything unpacked from an archive, tarball, or git tree stays under its destination. Never follow a symlink the source controls.

- Sanitize untrusted text before it reaches a terminal.

- Keep data as bytes until it must be text. Decoding turns valid non-UTF-8 output into an error.

- Redact URLs and credentials before they reach an error or a log line.

## Standing expectations

- Run `mise run fmt`, then all code must pass `mise run check` (lint, semver, test, in that order).
- Linting must pass. Never suppress a linter to make a warning go away. A suppression is a last resort, must be narrowly scoped to the single offending line or declaration, and must carry a comment saying why. A bare or unexplained suppression is not acceptable.
- Never hide errors. Return them with context, or log them where they cannot be returned.
- Never change the working directory: pass explicit paths, including a child process's working
  directory.
- A child process inherits the parent's environment. Set or clear every variable that changes what
  it does, such as `GIT_DIR`, and disable interactive prompts. Set `LC_ALL=C` when its output is
  parsed or matched.
- Decisions are pure functions. When logic around the filesystem, child processes, the clock,
  randomness, or the network is worth testing without the real thing, the entry point passes the
  effect in as a value or a handle, and a lint bans the direct call.
- Never hand-edit `Cargo.lock` or `mise.lock`. A hook blocks lockfile edits.
- Every tool runs through mise: `mise x <tool> -- <command>`.
