# Project instructions

- Read `AGENTS-local.md` if present for additional local development instructions.
- Format C++ code with clang-format using the repository's `.clang-format`.
- Target C++23.
- Use a module-first approach and put public C++ APIs in named modules.
- Use `import std;` for the C++ standard library.
- Use a C++26 feature only when it is explicitly enabled in this file.
- Do not use any feature explicitly forbidden in this file.
- Use ASCII characters only in Markdown, source code, and other project files unless instructed otherwise.
- Write Markdown with one sentence per line to keep diffs focused.
- Follow the [AI usage and attribution policy](README.md#ai-usage).

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

Deleted-function reasons are enabled for rvalue key borrowing on compilers that accept them in C++23 mode.

## Forbidden features

None are currently listed.
