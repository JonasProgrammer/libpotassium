# libpotassium

libpotassium is an opinionated C++ wrapper for libsodium.

## Build and test

Use CMake 4.5 or newer, Ninja 1.11 or newer, libsodium development files, and a C++23 toolchain whose standard library provides the `std` module.
See [HACKING.md](HACKING.md) for the pinned Nix development shell, toolchain details, and CLion setup.

```sh
cmake -S . -B build -G Ninja
cmake --build build
ctest --test-dir build --output-on-failure
```

Run the example directly with `./build/libpotassium_example`.

## Contributing

Follow the project rules in [AGENTS.md](AGENTS.md).
Enable soft wrapping in your editor so Markdown remains easy to read while keeping one sentence per line for focused diffs.

## AI usage

AI tools are used in developing libpotassium.
A human reviews and improves AI-assisted code, and pull requests containing AI-assisted code are accepted only after that manual review and improvement.
Each AI-assisted commit must attribute the assistance with a Git trailer in the following format.

```text
Assisted-By: Agent (Provider; underlying model)
```
