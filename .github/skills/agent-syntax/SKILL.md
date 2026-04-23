---
name: agent-syntax
description: |
  Enforce idiomatic, production-ready Rust in rs-utils.
  Load before writing or reviewing any Rust code in this crate.
  Triggers on: any file edit, new module, refactor, or code review request.
---

# Agent Syntax — rs-utils (Rust)

This skill prevents the most common AI-generated anti-patterns that accumulate as technical debt in production Rust libraries. Every rule below has been chosen because the "bad" version is something LLMs produce by default.

---

## Rule 1 — No ASCII-Art Section Banners

**Never** use decorative comment dividers. They are not idiomatic Rust and add noise without structure.

```rust
// ❌ DO NOT generate
// ==============================
// Section: Encryption Helpers
// ==============================

// ❌ DO NOT generate
//----------------------------------------------------------
// Error types
//----------------------------------------------------------
```

Use a blank line + a single `//` comment instead, or prefer Rustdoc headings inside `///` doc blocks.

```rust
// ✅ Correct — simple, idiomatic
// Encryption helpers

/// # Error Types
/// ...
```

---

## Rule 2 — Arrow Syntax: `->` Only

In doc comments, inline comments, and JSDoc-style annotations, always write `->`. Never insert the Unicode `→` character (U+2192). It is invisible in some terminals, breaks grep, and looks inconsistent across editors.

```rust
// ❌ fn encrypt(data: &[u8]) → Vec<u8>
// ✅ fn encrypt(data: &[u8]) -> Vec<u8>
```

---

## Rule 3 — Prefer Iterator Chains over Manual Index Loops

Rust iterators are zero-cost abstractions. Manual index loops are harder to read, easier to get wrong (off-by-one), and obscure intent.

```rust
// ❌ Avoid
let mut results = Vec::new();
for i in 0..items.len() {
    if items[i].active {
        results.push(items[i].id);
    }
}

// ✅ Idiomatic
let results: Vec<_> = items.iter()
    .filter(|item| item.active)
    .map(|item| item.id)
    .collect();
```

**When manual loops ARE appropriate**: mutating elements in-place (`iter_mut`), or when the loop body has complex early-exit logic that `.try_fold()` would obscure.

---

## Rule 4 — Integer Division Truncates Toward Zero, Not Floor

Rust `a / b` truncates toward zero (C semantics). This differs from Python's `//` which floors toward negative infinity. When the domain requires floor division (e.g., financial rounding, time bucketing), be explicit.

```rust
// ❌ Silently wrong for negative inputs
let bucket = offset / bucket_size;

// ✅ Explicit about the behaviour you need
let bucket = offset.div_euclid(bucket_size);   // mathematical floor
let truncated = offset / bucket_size;           // toward-zero (fine if inputs are always ≥ 0)
```

Document which behaviour is intended whenever the inputs can be negative.

---

## Rule 5 — `?` over `unwrap()` / `expect()` in Library Code

`unwrap()` panics; library code must never panic on caller-controlled input.
`expect("msg")` is acceptable **only** for true invariants that can never fail in a correct program (e.g., parsing a compile-time constant).

```rust
// ❌ Panics on bad input — never in library code
let value = map.get("key").unwrap();
let parsed: u64 = s.parse().expect("should be a number");

// ✅ Propagate errors to the caller
let value = map.get("key").ok_or(MyError::MissingKey)?;
let parsed: u64 = s.parse().map_err(MyError::ParseInt)?;

// ✅ expect() is fine for compile-time invariants only
let re = Regex::new(r"^\d+$").expect("hardcoded regex is always valid");
```

---

## Rule 6 — `match` over Nested `if let` Chains

Two or more `if let` / `else if let` branches signal that `match` (or `match` + guards) is the right tool.

```rust
// ❌ Difficult to extend, easy to miss cases
if let Some(user) = get_user(id) {
    if let Ok(role) = parse_role(&user.role_str) {
        // ...
    } else {
        return Err(MyError::InvalidRole);
    }
} else {
    return Err(MyError::UserNotFound);
}

// ✅ All branches visible at a glance
let (user, role) = match (get_user(id), parse_role_str) {
    (Some(u), Ok(r)) => (u, r),
    (None, _)        => return Err(MyError::UserNotFound),
    (_, Err(_))      => return Err(MyError::InvalidRole),
};
```

---

## Rule 7 — No Gratuitous `.clone()`

If you are calling `.clone()` to satisfy the borrow checker, reconsider the design first. Common solutions: pass a reference, restructure ownership, use `Rc`/`Arc` deliberately.

```rust
// ❌ Cloning because ownership wasn't thought through
let name = user.name.clone();
process(user);
log(name);

// ✅ Borrow what you need before moving
let name = &user.name;
log(name);
process(user);
```

`.clone()` is acceptable when cloning is the correct semantic (e.g., producing an independent copy for a different thread) — just make sure it is intentional.

---

## Rule 8 — No Unexplained `#[allow(...)]`

Every `#[allow(dead_code)]`, `#[allow(unused_variables)]`, etc. must have a comment explaining *why* the suppression is justified, not just that it is.

```rust
// ❌ Silent suppression hides real problems
#[allow(dead_code)]
struct LegacyPayload { ... }

// ✅ Intent is documented
// Retained for wire-format compatibility; not constructed internally.
#[allow(dead_code)]
struct LegacyPayload { ... }
```

---

## Rule 9 — Custom Errors via `thiserror`, Not `Box<dyn Error>`

`Box<dyn Error>` erases type information and prevents callers from matching error variants. Use `thiserror` (already in `Cargo.toml`) for all custom error types.

```rust
// ❌ Callers cannot distinguish error kinds
fn parse(s: &str) -> Result<Parsed, Box<dyn std::error::Error>> { ... }

// ✅ Typed, matchable errors
#[derive(Debug, thiserror::Error)]
pub enum ParseError {
    #[error("empty input")]
    Empty,
    #[error("invalid token: {0}")]
    Invalid(String),
}

fn parse(s: &str) -> Result<Parsed, ParseError> { ... }
```

---

## Rule 10 — Named Constants, Not Magic Numbers

```rust
// ❌ What does 86_400 mean?
if elapsed > 86_400 { expire(); }

// ✅ Self-documenting
const ONE_DAY_SECS: u64 = 86_400;
if elapsed > ONE_DAY_SECS { expire(); }
```

---

## Rule 11 — No `panic!()` in Library Code

Panics are contagious — they unwind the entire thread and cannot be caught cleanly in async runtimes. Return a `Result` or `Option` instead.

```rust
// ❌ Callers cannot recover
fn get_config() -> Config {
    std::fs::read_to_string("config.toml")
        .map(|s| toml::from_str(&s).unwrap())
        .expect("config must exist")
}

// ✅ Let the caller decide what to do on failure
fn get_config() -> Result<Config, ConfigError> {
    let s = std::fs::read_to_string("config.toml").map_err(ConfigError::Io)?;
    toml::from_str(&s).map_err(ConfigError::Parse)
}
```

---

## Rule 12 — `.to_owned()` not `.to_string()` on String Literals

`.to_string()` on `&str` goes through the `Display` trait (a formatting round-trip). `.to_owned()` is the direct, zero-overhead conversion.

```rust
// ❌ Unnecessary Display formatting
let s = "hello".to_string();

// ✅ Direct
let s = "hello".to_owned();
// or
let s = String::from("hello");
```

---

## Anti-Pattern Quick Reference

| Anti-pattern | Idiomatic alternative |
|---|---|
| `//====== Section ======` | Blank line + plain `//` comment |
| Unicode `→` in comments | ASCII `->` |
| `for i in 0..v.len()` | `.iter().enumerate()` or `for item in &v` |
| `a / b` on possibly-negative ints | `.div_euclid()` or explicit comment |
| `.unwrap()` in library code | `?` with typed error |
| `if let … else if let …` (3+ branches) | `match` |
| `.clone()` to placate borrow checker | Restructure ownership |
| `#[allow(dead_code)]` with no comment | Add an explanatory comment |
| `Box<dyn Error>` as return type | `thiserror` enum |
| Magic numbers | Named `const` |
| `panic!()` in library fn | `Result<_, E>` |
| `"str".to_string()` | `"str".to_owned()` |
