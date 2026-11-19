# Hacking on libpotassium

Read [AGENTS.md](AGENTS.md) for the project rules and [README.md](README.md#build-and-test) for build and test commands.

## Toolchain

CMake 4.5 makes `import std;` available to scanned C++ targets without the earlier experimental opt-in.
This project enables scanning with `CMAKE_CXX_SCAN_FOR_MODULES` and declares its public module interface with a `CXX_MODULES` file set.
Use a Ninja generator and a toolchain that ships usable standard-library module sources and metadata.
See the [CMake 4.5 release notes](https://cmake.org/cmake/help/v4.5/release/4.5.html#languages) and [CMake modules manual](https://cmake.org/cmake/help/v4.5/manual/cmake-cxxmodules.7.html#import-std-support).

## Nix development shell

The repository flake provides GCC 16 with libstdc++, CMake 4.5, Ninja, and libsodium for x86_64 Linux.
The flake takes CMake from the pinned nixpkgs staging input.
Use the checked-in `flake.lock` to reproduce the development environment.

```sh
nix --extra-experimental-features 'nix-command flakes' develop .
```

In a Git checkout, Nix only sees tracked files when it evaluates the Git-backed flake.
Track new flake inputs before trying to evaluate them through the Git-backed flake.

### Example local instructions

Create an `AGENTS-local.md` in the repository root if your local workflow needs additional instructions.
For example:

```markdown
# Local development instructions

- Use the repository flake for configuration, builds, and tests.
- Start an interactive shell with `nix --extra-experimental-features 'nix-command flakes' develop .`.
- For individual commands, use `nix --extra-experimental-features 'nix-command flakes' develop . --command <command> <args>`.
```

## CLion

1. Launch CLion normally and open the repository as a CMake project.
2. Under **Settings > Build, Execution, Deployment > Toolchains**, select a local **System** toolchain.
3. Choose **Add environment > From file** and select the repository's `clion-env.sh`.
4. Make sure CLion sources the file with Bash.
   On Linux CLion uses the shell named by `$SHELL`, and its fallback shell setting applies only when `$SHELL` is unset.
5. From the Nix development shell, use the commands below to find the tool paths.
   Set CLion's C and C++ compilers to the Nix wrappers and select the Nix CMake and Ninja executables.
6. Under **Settings > Build, Execution, Deployment > CMake**, select that toolchain for the active profile and set the generator to **Ninja**.

```sh
printf '%s\n' "$CC" "$CXX"
command -v cmake
command -v ninja
```

The script uses `nix print-dev-env` to load the flake environment into CLion's toolchain.
After updating `flake.lock`, refresh any stored Nix tool paths and reset the CMake cache if CLion still uses the old environment.
See [CLion toolchain setup](https://www.jetbrains.com/help/clion/how-to-create-toolchain-in-clion.html#toolchain-environment).

### Example presets for a custom CLion toolchain

The [CMakeUserPresets.example.json](CMakeUserPresets.example.json) example extends the shared `debug`, `release`, and `docs` presets with profiles that select a CLion toolchain named `libpotassium`.
Name the toolchain you configured above `libpotassium`, or change each `toolchain` value in your local copy to match your toolchain's name in CLion.
The toolchain must make Doxygen available to build the `clion-docs` preset.

If you do not have a `CMakeUserPresets.json` in the project root, copy the example to that filename.

```sh
cp CMakeUserPresets.example.json CMakeUserPresets.json
```

If you already have a `CMakeUserPresets.json`, merge the example's configure and build presets into it and use schema version 10.
Git ignores `CMakeUserPresets.json` so you can keep your toolchain settings local.
Reload the CMake project in CLion and enable the desired `clion-*` profile under **Settings > Build, Execution, Deployment > CMake**.
See [CLion's CMake presets documentation](https://www.jetbrains.com/help/clion/cmake-presets.html).

## Updating the development shell

```sh
nix --extra-experimental-features 'nix-command flakes' flake update nixpkgs nixpkgs-staging
```

Verify that configuration, build, and CTest pass in the updated shell, then commit `flake.lock`.
