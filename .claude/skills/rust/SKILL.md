---
name: rust
description: Rust conventions for this workspace. Read before writing, editing, or reviewing Rust code or Cargo manifests.
---

# Rust

## Types

- Rule out a bug class with a newtype, a sealed enum, a typestate, or an owned handle. One
  validator per concept is a newtype.
- A status field beside `Option` fields that depend on it is an enum: one variant per shape, each
  with only its own fields. Same for a `bool` beside the data that depends on it.
- Keep the wire format separate from the Rust type. When a serialized shape must stay flat with
  `null`s, a private struct writes it, converted from the enum in one place with
  `#[serde(into = "...")]`. A reader parses into the enum at the boundary with `from` or
  `try_from`.
- Parse outside values, such as an API's state or a record's status, into an enum at the boundary.
  No `match s.as_str()` or string comparison below it.
- Signs the type is wrong: a catch-all arm for a combination that "cannot happen",
  `unwrap_or_default()` on a field that is "always set", a comment explaining why a `let ... else`
  cannot fire.
- Coerce to a trait object with a typed binding (`let e: &dyn Error = &err;`); `as` is denied.

## Ownership

- Borrow by default. A function takes `&T`, `&[T]`, or `&str` for what it only reads, and takes
  ownership only of what it keeps. Hand back a slice of the input instead of a copy when the caller
  can use it before the next call. Clone or allocate only for a value that outlives its source,
  such as an error's payload.

## Errors

- Return errors with `?` and context. Never discard one with `let _ =`, `.ok()`,
  `unwrap_or_default()`, or an empty `Err(_)` arm.
- Parse the command line with `clap`'s derive API, define library errors with `thiserror`, and
  add context to errors in the binary with `anyhow`. A `thiserror` type either names its cause
  in the message or marks it `#[source]`, never both, since the binary prints the whole chain.
- `Box<dyn Error>` usually means the error handling stopped short. A library gives each failing
  step its own `thiserror` variant, so the message and the type both say which step failed, and a
  binary adds that context with `anyhow`. Box only to erase an error type the caller picks, such as
  a trait's associated `Error` in an error type that is not generic over the trait.
- Where a panic is allowed at all, such as in a `const`, write `expect("…")`, never `unwrap()`.
  The message states why the panic cannot fire.
- Where a protocol matches error text exactly, print the library error unchanged, without `anyhow`
  context.

## Lints and safety

- Suppress a lint with `#[expect(lint, reason = "…")]`, never `#[allow]`.
- `unsafe` is forbidden workspace-wide. If a syscall needs it, raise that with the operator first.
- `main` passes each effect in, and `disallowed-methods` in `clippy.toml` bans the direct call. The
  `venv-seam` skill has the steps.
- Set a child process's working directory with `Command::current_dir`. Clippy denies
  `std::env::set_current_dir`.

## Untrusted content

- Cap anything a remote or a fetched artifact controls with `Read::take`.
- An unpacked path stays under its destination when every `Path::components()` item is
  `Component::Normal`.
- Hold untrusted output as `&[u8]` or `Vec<u8>` until it must be text. A `String` API turns valid
  non-UTF-8 output into an error.
- Parse a value that can carry credentials, such as a URL or token, after clap: a clap
  `value_parser` error echoes the rejected value.
- A type that holds a secret implements `Debug` by hand and redacts the value.
- A child process's stderr can carry credentials. Keep it in an error field, out of `Display`.

## Tests

- Warnings fail only `mise run lint`, `mise run test` and the hooks, so a half-written change still
  runs under `mise exec -- cargo nextest run`.
- Tests may return `Result<(), Box<dyn Error>>`.
- Test behavior that depends on an environment variable in a child process, with `Command::env`.
  `std::env::set_var` is `unsafe`.
- Tests create temporary directories with the `tempfile` crate.
- Inject a limit through a builder method or a `pub` field whose `Default` is the production const.
- Tell errors apart with `matches!` against an error variant. Never match `err.to_string()` text.
  If no variant fits, add one.

Reach for `proptest` where hand-picked cases miss the input space, such as paths and chunk
boundaries. When a property fails, proptest writes the case to a `.proptest-regressions` file
beside the test; commit it with the fix so the case runs every time.

`mise run mutants` runs `cargo-mutants`, which makes one small change to the code at a time and
lists each change no test notices. Treat a missed mutant as a missing test. When a mutant cannot
change behavior, add it to `.cargo/mutants.toml` with the reason.

## Dependencies

- Declare each dependency once in `[workspace.dependencies]`, at the latest version `cargo info`
  reports, and inherit it with `<name>.workspace = true`. Then run `mise run lock`.
- Check a crate's API on docs.rs and cite the link. Probe its behavior with a test in the crate,
  not a throwaway binary.
