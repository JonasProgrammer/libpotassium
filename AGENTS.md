# Project instructions

- Read `AGENTS-local.md` if present for additional local development instructions.
- Format C++ code with clang-format using the repository's `.clang-format`.
- Build in C++26 mode and use C++23 as the source baseline.
- Use a module-first approach and put public C++ APIs in named modules.
- Forward-declare identity tags, including algorithm and key-purpose tags, as incomplete structs (for example, `struct sha256;`) and leave them undefined throughout the project.
- Use `import std;` for the C++ standard library.
- Use a C++26 feature only when it is explicitly enabled in this file.
- Do not use any feature explicitly forbidden in this file.
- Never add ephemeral information, temporary notes, or planning material to committed documentation.
- Use ASCII characters only in Markdown, source code, and other project files unless instructed otherwise.
- In `COMPARISON.md`, emoji may accompany text labels to indicate wrapping status.
- Write Markdown with one sentence per line to keep diffs focused.
- Follow the [AI usage and attribution policy](README.md#ai-usage).

## Error handling

- For fallible cryptographic operations, provide a throwing overload and a `noexcept` overload with a final `std::nothrow_t` parameter that returns `std::expected<T, errc>`.
- Use `std::expected<void, errc>` when success has no value.
- Implement the operation in the nonthrowing overload and have the throwing overload delegate with `std::nothrow` and translate errors through `throw_error`.
- Return `std::unexpected(errc::crypto_failed)` for cryptographic failures and `std::unexpected(errc::allocation_failed)` for allocation failures, catching only the exception types that the operation can translate to those errors.
- Use a function try-block when exception handling applies to the entire function body.
- Use a local try-block when the handler should cover only a specific operation.

## In-code documentation

- Use Doxygen for in-code documentation.
- Both `///` and `/** ... */` comment forms are allowed.
- Prefix Doxygen commands with `@`, as in `@pre` and `@ref`.
- Keep documentation terse and useful.
- Document preconditions with `@pre` instead of using exceptions.
- The global precondition that `init` must have been called does not need to be repeated for every function.

## Source file notices

Start each project source file, including examples, build scripts, and source templates, with the following notices in the file's comment syntax.
Place the notices immediately after the shebang in executable scripts.
Use the year the file was first published for new files and preserve existing copyright notices.

```cpp
// SPDX-FileCopyrightText: 2026 libpotassium team
// SPDX-License-Identifier: BSL-1.0
```

## Commit messages

Follow [Conventional Commits 1.0.0](https://www.conventionalcommits.org/en/v1.0.0/).
Use `<type>[optional scope]: <description>` for the subject.
Use `feat` for new features, `fix` for bug fixes, and a suitable type such as `build`, `docs`, or `test` for other changes.
Indicate breaking changes with `!` before the subject's colon or a `BREAKING CHANGE:` footer.
Include an `Assisted-By` trailer for AI-assisted commits as specified in the README.

## C++26 features

- `std::indirect` is enabled for general use.
- Deleted-function reasons are enabled.

## Forbidden features

None are currently listed.
