---
name: venv-seam
description: Use when logic with OS effects (filesystem, child processes, clock, randomness, network) is worth testing without the real thing, or when banning direct OS access behind a seam.
---

# Venv seam

Decisions are pure functions. Side effects reach the OS through handles `main` passes in, so every
layer runs in memory and deterministically.

## When

Add a seam when code makes decisions around an effect: what it does when a file is missing, when a
token expires, how it retries a failed request, what it does when a process outlives its timeout.
Code that only forwards an effect tests against the real thing, such as a temporary directory.

A test of the integration itself, such as the kernel refusing a symlink under `O_NOFOLLOW`, runs
against the real thing, because a fake would test only the fake. A test of how the application
behaves as a client uses the seam.

## Shape

Take the first that fits:

1. A value. When code needs one reading, `main` takes it and passes it as an argument: the current
   time, a cutoff, a nonce.
2. A trait per effect, with only the operations the project uses: `Vfs`, `Exec`, `Clock`, `Random`,
   `Net`. A function takes the handles it uses as parameters.
3. A `Venv` struct bundling the handles, once several layers pass the same set.

`main` builds the OS backends. Tests pass in-memory backends, or wrap one so a chosen operation
fails. Each OS backend is one module.

Tokio's timers (`sleep`, `timeout`, `interval`) need no `Clock`. Enable tokio's `test-util`
feature in dev-dependencies and write `#[tokio::test(start_paused = true)]`.

## Enforce

Once a seam exists, ban the calls it replaces. Add the entries for each seam the project has to
`disallowed-methods` in `clippy.toml`, and for each crate the project depends on.

Filesystem:

```toml
  { path = "std::fs::canonicalize", reason = "use the Vfs passed in" },
  { path = "std::fs::copy", reason = "use the Vfs passed in" },
  { path = "std::fs::create_dir", reason = "use the Vfs passed in" },
  { path = "std::fs::create_dir_all", reason = "use the Vfs passed in" },
  { path = "std::fs::exists", reason = "use the Vfs passed in" },
  { path = "std::fs::hard_link", reason = "use the Vfs passed in" },
  { path = "std::fs::metadata", reason = "use the Vfs passed in" },
  { path = "std::fs::read", reason = "use the Vfs passed in" },
  { path = "std::fs::read_dir", reason = "use the Vfs passed in" },
  { path = "std::fs::read_link", reason = "use the Vfs passed in" },
  { path = "std::fs::read_to_string", reason = "use the Vfs passed in" },
  { path = "std::fs::remove_dir", reason = "use the Vfs passed in" },
  { path = "std::fs::remove_dir_all", reason = "use the Vfs passed in" },
  { path = "std::fs::remove_file", reason = "use the Vfs passed in" },
  { path = "std::fs::rename", reason = "use the Vfs passed in" },
  { path = "std::fs::set_permissions", reason = "use the Vfs passed in" },
  { path = "std::fs::symlink_metadata", reason = "use the Vfs passed in" },
  { path = "std::fs::write", reason = "use the Vfs passed in" },
  { path = "std::fs::File::create", reason = "use the Vfs passed in" },
  { path = "std::fs::File::create_new", reason = "use the Vfs passed in" },
  { path = "std::fs::File::open", reason = "use the Vfs passed in" },
  { path = "std::fs::File::options", reason = "use the Vfs passed in" },
  { path = "std::fs::OpenOptions::new", reason = "use the Vfs passed in" },
  { path = "std::path::Path::canonicalize", reason = "use the Vfs passed in" },
  { path = "std::path::Path::exists", reason = "use the Vfs passed in" },
  { path = "std::path::Path::is_dir", reason = "use the Vfs passed in" },
  { path = "std::path::Path::is_file", reason = "use the Vfs passed in" },
  { path = "std::path::Path::metadata", reason = "use the Vfs passed in" },
  { path = "std::path::Path::read_dir", reason = "use the Vfs passed in" },
  { path = "std::path::Path::read_link", reason = "use the Vfs passed in" },
  { path = "std::path::Path::symlink_metadata", reason = "use the Vfs passed in" },
  { path = "std::path::Path::try_exists", reason = "use the Vfs passed in" },
```

Processes:

```toml
  { path = "std::process::Command::new", reason = "use the Exec passed in" },
  { path = "tokio::process::Command::new", reason = "use the Exec passed in" },
```

Clock:

```toml
  { path = "std::time::SystemTime::now", reason = "use the Clock passed in" },
  { path = "std::time::Instant::now", reason = "use the Clock passed in" },
  { path = "std::thread::sleep", reason = "use the Clock passed in" },
```

Randomness:

```toml
  { path = "getrandom::fill", reason = "use the Random passed in" },
  { path = "rand::rng", reason = "use the Random passed in" },
```

Network:

```toml
  { path = "std::net::TcpListener::bind", reason = "use the Net passed in" },
  { path = "std::net::TcpStream::connect", reason = "use the Net passed in" },
  { path = "std::net::UdpSocket::bind", reason = "use the Net passed in" },
  { path = "tokio::net::TcpListener::bind", reason = "use the Net passed in" },
  { path = "tokio::net::TcpStream::connect", reason = "use the Net passed in" },
  { path = "reqwest::Client::builder", reason = "use the Net passed in" },
  { path = "reqwest::Client::new", reason = "use the Net passed in" },
  { path = "reqwest::get", reason = "use the Net passed in" },
```

Then put one inner attribute at the top of each OS backend module:

```rust
#![expect(clippy::disallowed_methods, reason = "the OS backend of the Clock")]
```

A test that inspects what a compiled binary did, such as the files it wrote, takes the same
attribute with its own reason.
