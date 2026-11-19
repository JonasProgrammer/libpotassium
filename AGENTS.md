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

## Commit messages

Follow [Conventional Commits 1.0.0](https://www.conventionalcommits.org/en/v1.0.0/).
Use `<type>[optional scope]: <description>` for the subject.
Use `feat` for new features, `fix` for bug fixes, and a suitable type such as `build`, `docs`, or `test` for other changes.
Indicate breaking changes with `!` before the subject's colon or a `BREAKING CHANGE:` footer.
Include an `Assisted-By` trailer for AI-assisted commits as specified in the README.

## C++26 features

None are currently enabled.

## Forbidden features

None are currently listed.
