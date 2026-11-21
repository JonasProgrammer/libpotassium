# libpotassium

libpotassium is an opinionated C++ wrapper for libsodium.

## Build and test

Use CMake 4.5 or newer, Ninja 1.11 or newer, libsodium development files, and a C++26 toolchain whose `std` module exports `std::indirect`.
The test suite requires Catch2 v3, which is available in the full Nix development shell.
To configure without the test suite, pass `-DBUILD_TESTING=OFF`.
See [HACKING.md](HACKING.md) for the pinned Nix development shell, toolchain details, and CLion setup.

```sh
cmake --preset debug
cmake --build --preset debug
ctest --preset debug
```

Run the example directly with `./build/debug/libpotassium_example`.
Use `release` in the same commands for an optimized build in `build/release`.

## API documentation

With Doxygen installed, enable and build the HTML documentation with the following commands.

```sh
cmake --preset docs
cmake --build --preset docs
```

Open `build/docs/docs/html/index.html` to browse the documentation.
The documentation option defaults to `OFF`.
If enabled while Doxygen is missing, CMake warns and skips the documentation target.

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

## License

libpotassium is licensed under the [Boost Software License 1.0](LICENSE).
