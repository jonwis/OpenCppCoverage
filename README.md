![](https://github.com/OpenCppCoverage/OpenCppCoverage/workflows/Unit%20tests/badge.svg)
# OpenCppCoverage

OpenCppCoverage is an open source code coverage tool for C++ under Windows.

The main usage is for unit testing coverage, but you can also use it to know the executed lines in a program for debugging purpose.

---------------------
## Project status: archived and no longer maintained

This project is no longer actively maintained.

I stopped active development and maintenance approximately seven years ago after moving away from C++ in my professional work. At first, I expected this to be temporary, but I am now formally retiring the project.

The existing source code and releases will remain available for historical use. However:

* no further releases, bug fixes, or compatibility updates are planned;
* issues and pull requests will not be reviewed;
* support questions may not receive a response;
* security fixes should not be expected;
* users should evaluate the software carefully before continuing to depend on it.

Forks and independent continuation of the project are welcome, subject to the existing licence.

### Community-maintained forks

**There is currently no designated successor or recommended fork.**

The following independent fork has been brought to my attention:

[bmarques1995/OpenCppCoverage](https://github.com/bmarques1995/OpenCppCoverage)

**Note: I have not reviewed or tested this fork.**

If you actively maintain a fork of this project and would like it to be considered for inclusion here, please contact me through OpenCppCoverage@gmail.com.

I intend to link from this page to the most active community-maintained fork I am aware of. The selected fork may change over time as development activity changes.

Any fork listed here is maintained independently. Its inclusion does not constitute a transfer of ownership, and I cannot provide support or guarantees for it.

### Existing issues and pull requests

Existing issues and pull requests have been closed as part of retiring the project.

Their closure does not necessarily mean that an issue was resolved, that a proposed change was rejected, or that the contribution lacked value. It only means that the original repository is no longer being maintained.

The history and discussion will remain available for reference.

### Licence

The project remains available under the terms described in the [LICENSE](LICENSE) file.

Archiving the project does not change its licence. You may use, modify, fork, and redistribute the code according to those terms.

### Thank you

Thank you to everyone who used the project, reported issues, contributed code or documentation, reviewed changes, answered questions, or otherwise helped improve it.

Maintaining this project and working with its community was a valuable experience. I am grateful for all the time and effort contributed over the years.

---------------------
## Features:
- **Visual Studio support**: Support compiler with program database file (.pdb).
- **Non intrusive**: Just run your program with OpenCppCoverage, no need to recompile your application.
- **HTML reporting**
- **Line coverage**.
- **Run as Visual Studio Plugin**: See [here](https://github.com/OpenCppCoverage/OpenCppCoveragePlugin) for more information.
- **Jenkins support**: See [here](https://github.com/OpenCppCoverage/OpenCppCoverage/wiki/Jenkins) for more information.
- **Support optimized build**.
- **Exclude a line based on a regular expression**.
- **Child processes coverage**.
- **Coverage aggregation**: Run several code coverages and merge them into a single report.
 
## Requirements
- Windows 10 or later. ARM64EC and AMD64 emulation require Windows 11 on ARM64.
- Matching PDBs for source reports. Symbol-free collection can run without PDBs.

## Building

Build `CppCoverage.sln` with Visual Studio 2022 and the v143 C++ tools. Install the
Windows SDK, DIA SDK, and Visual Studio vcpkg component. ARM64 builds also require
the ARM64 C++ tools; the mixed-ISA fixture requires the ARM64EC tools.
The x64 C++/CLI test fixture requires C++/CLI support and the .NET Framework 4.8
targeting pack. Its MSTest framework and adapter are restored from NuGet.

MSBuild restores the pinned dependencies from `vcpkg.json`. Dependencies are
installed under `vcpkg_installed\<Platform>` so architecture builds remain
independent. An existing vcpkg checkout can be selected with `/p:VcpkgRoot=...`.
No machine-wide vcpkg integration is required.
NuGet restores the pinned C++/CLI test dependencies to the repository's `packages`
directory using the configured package sources.

```powershell
msbuild .\CppCoverage.sln /restore /p:RestorePackagesConfig=true /m /p:Configuration=Debug /p:Platform=x64
msbuild .\CppCoverage.sln /restore /p:RestorePackagesConfig=true /m /p:Configuration=Debug /p:Platform=ARM64
```

## Download
OpenCppCoverage can be downloaded from [here](../../releases).

## Usage
You can simply run the following command:

```OpenCppCoverage.exe --sources MySourcePath* -- YourProgram.exe arg1 arg2```

For example, *MySourcePath* can be *MyProject*, if your sources are located in *C:\Dev\MyProject*.

See [Getting Started](https://github.com/OpenCppCoverage/OpenCppCoverage/wiki) for more information about the usage.
You can also have a look at [Command-line reference](https://github.com/OpenCppCoverage/OpenCppCoverage/wiki/Command-line-reference).

### Collect without symbols, resolve later

`--symbol-free` discovers basic blocks from the PE image and records whether each
block executed. It uses entrypoints, exports, local import targets, TLS callbacks,
CFG and EH continuation tables, exception/unwind metadata, and ARM64EC code maps
as roots, then follows direct control flow with Capstone.

```powershell
.\OpenCppCoverage.exe --symbol-free --modules MyProgram.exe --export_type binary:run.cov -- .\MyProgram.exe arg1
```

The `.cov` file contains module identities, instruction sets, and RVA ranges with
execution flags. Source paths and line mappings are added during resolution.
Collection accepts binary exports and module filters; apply source and line
filters when resolving.

On a machine with matching binaries and PDBs:

```powershell
.\OpenCppCoverage.exe --resolve .\run.cov --module_dir C:\Build\bin --sources '*MyProject*' --export_type html:coverage --export_type cobertura:coverage.xml
```

Resolution searches the recorded image path and each `--module_dir`, verifies the
image identity and SHA-256 hash, and loads matching symbols through DIA.
Place PDBs beside the images or configure `_NT_SYMBOL_PATH`.
Existing HTML, Cobertura, binary, and plugin exporters remain available.
Resolve raw coverage before merging it with source coverage.

Use the native ARM64 collector for ARM64, ARM64EC, and AMD64-on-ARM64 processes.
The AMD64 collector supports AMD64 processes on AMD64 Windows.
The existing symbol-based collection path remains available for x86 and AMD64.

Discovery follows reachable code from known roots. Arbitrary indirect branches,
jump tables, and generated code can leave blocks undiscovered. Only discovered
code contributes to the resolved line-coverage denominator.
Collection rejects mapped code that differs from its
image after ordinary ASLR relocations. ARM64X dynamic relocations and runtime
code modification are unsupported.
