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

Microsoft DIA redistribution terms are identified in
`CppCoverage\Dia\DIA-NOTICE.txt`, which is copied alongside the runtime into the
build output. Redistributors must meet its license and downstream agreement
requirements.

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

With `--cover_children`, hits are a boolean union across matching images.
Children and reloaded modules reuse discovery for the same image identity and
loader function-override values. Blocks already covered are left uninstrumented;
breakpoints in resident instances are retired at that process's next stopped
debug event. Queued breakpoint exceptions remain recognized.

#### Select contributors in a launched process tree

`--processes` and `--excluded_processes` select main executables independently
of `--modules` and `--excluded_modules`. They require `--symbol-free` and support
both launched programs and the fixed existing-process cohort described below.

```powershell
.\OpenCppCoverage.exe --symbol-free --cover_children --processes 'te.processhost*' --processes '*notepad*' --excluded_processes '*helper*' --modules shcore.dll --modules MyLibrary.dll -- .\TestLauncher.exe
```

`--cover_children` remains explicit. Unselected roots and intermediaries stay
under debugger control so matching children and grandchildren can contribute.
Their main images and DLLs are not instrumented for coverage. A selected process
can load a matching DLL later; selecting a DLL never implicitly selects its host.
Without `--cover_children`, only the launched root is eligible for coverage.

Repeated includes are ORed; any exclusion wins. Includes default to `*`, including
when only exclusions are supplied. Without process filters, launch behavior is
unchanged. Process globs match the entire basename unless they contain `\`, in
which case they match the queried full Win32 main-image path. Matching is ordinal
case-insensitive; `*` is the only wildcard and `?` is literal. `svchost.exe` is an
exact basename, while `*system32\runtimebroker*` is a path glob. Extended DOS/UNC
prefixes are normalized for comparison; environment variables and path aliases
are not expanded. Existing module filters retain their substring semantics.
Process filters can also be repeated in configuration files.

#### Collect from existing processes

Omit the launched program and supply explicit `--processes`, `--modules`, and
a positive `--duration` in whole seconds:

```powershell
.\OpenCppCoverage.exe --symbol-free --processes 'MyHost*.exe' --processes 'C:\Tests\OtherHost.exe' --excluded_processes '*helper*' --modules MyLibrary.dll --modules OtherLibrary.dll --duration 30 --export_type binary:existing.cov
```

The initial process snapshot defines the cohort. All eligible matching instances
are considered, including unrelated processes. The collector verifies each
process's creation time and main-image path before admission. A selected process
remains attached when no matching DLL is loaded yet; later DLL loads can contribute.
Hits from identical images are unioned as in launched collection. The raw format
and deferred-resolution workflow are unchanged.

`--duration` starts after cohort admission and bootstrap. Ctrl+C requests an
orderly early stop. External processes are never terminated by these stop paths.
Cleanup holds live threads, restores original bytes and page protections, repairs
queued coverage traps, detaches, and releases only the collector's suspensions.
If cleanup fails, the collector retains debugger ownership and retries with an
error diagnostic; cleanup can exceed the requested duration.
Ambiguous attach-bootstrap exceptions retain the connection for recovery rather
than being swallowed as collector-owned breakpoints.
Application exceptions and breakpoints on known original threads retain normal
target dispatch during bootstrap.

Attachment is invasive: it pauses threads and changes executable memory.
An owned helper establishes the debugger's non-killing exit policy before any
external attachment. This does not make collector crashes safe: outstanding
software breakpoints can remain in external processes. Use controlled targets
and allow orderly cleanup; do not forcibly end the collector.

Collection observes execution after attachment. Earlier execution, startup code,
and DLL initialization that already ran are not recovered. Future process
launches and children outside the initial cohort are not monitored;
`--cover_children` is rejected in existing-process mode. Use controlled launch
when coverage must begin before application entry.

The collector does not elevate or enable debug privileges. It refuses critical
processes, processes whose critical status cannot be established, already-debugged
processes, and unsupported architectures. Admission failures are logged and give
a nonzero result even when other targets contribute. Inaccessible candidates
whose main-image paths cannot be checked are reported as incomplete admissions.
An empty eligible cohort also returns a nonzero result.

On a machine with matching binaries and PDBs:

```powershell
.\OpenCppCoverage.exe --resolve .\run.cov --module_dir C:\Build\bin --sources '*MyProject*' --export_type html:coverage --export_type cobertura:coverage.xml
```

Resolution searches the recorded image path and each `--module_dir`, verifies the
image identity and SHA-256 hash, and loads matching symbols through DIA.
Place PDBs beside the images or configure `_NT_SYMBOL_PATH`.
Existing HTML, Cobertura, binary, and plugin exporters remain available.
Resolve raw coverage before merging it with source coverage.

#### View a capture in Visual Studio 2026

On the symbol machine, use PowerShell 7.2 or later:

```powershell
.\ConvertTo-VsCoverage.ps1 -InputCoverage .\run.cov -ModuleDirectory C:\Build\bin
```

The script resolves the capture, writes `run.coverage`, and opens it in Visual
Studio 2026 when installed, otherwise through the Windows file association.
Use **Code Coverage Results > Import Results** to open the file on another machine.
Matching binaries and PDBs are required. `_NT_SYMBOL_PATH` supplies symbol servers.
`-OpenCppCoverage` selects the resolver executable; `-Output` selects the report.
`-Sources` accepts source filters, and `-SourcePathSubstitution` accepts
`<pdbStartPath>?<localPath>` mappings for source navigation.

The script finds the tested `dotnet-coverage` version, or installs version
18.7.0 into ignored `out\tools` using a .NET 8 or later SDK. Installation honors
configured NuGet sources and credentials; `-NuGetConfigFile` selects an explicit
configuration. Global tools are unchanged.

Default flow is **resolve, convert, open**. `-Verify` adds a native-to-Cobertura
round-trip and compares every module/file/line/boolean-hit tuple before publishing
or opening the report. `-NoOpen` suppresses opening for automation. A failed
conversion or verification leaves an existing destination report unchanged.

Visual Studio shows explicitly labelled **[file-level coverage]** containers.
Function and branch coverage are unavailable in the source model. The opt-in
`cobertura-vs` intermediate preserves recorded source paths and distinguishes
modules with identical basenames and source files that share a filename.
Source navigation requires the corresponding local files or source-path substitutions.
Ordinary Cobertura exports and raw RVA captures are unchanged.

Use the native ARM64 collector for ARM64, ARM64EC, and AMD64-on-ARM64 processes.
The AMD64 collector supports AMD64 processes on AMD64 Windows.
The existing symbol-based collection path remains available for x86 and AMD64.

Discovery follows reachable code from known roots. Arbitrary indirect branches,
jump tables, and generated code can leave blocks undiscovered. Only discovered
code contributes to the resolved line-coverage denominator.
Collection rejects mapped code that differs from its
image after ordinary ASLR relocations. ARM64X dynamic relocations and runtime
code modification are unsupported.

### Runtime performance harness

`PerformanceTests\DirectoryHash.cpp` recursively enumerates a directory and hashes
each file with BCrypt SHA-256 through SHCore file streams. Each pass reports wall
time, application CPU time, file and byte counts, and a combined digest. The
combined digest is SHA-256 of the concatenated 32-byte file hashes, ordered by
ordinal full path. Reparse points are skipped; read errors fail the run.

Build the Release collector and workload for the target architecture:

```powershell
msbuild .\CppCoverage.sln /m /t:OpenCppCoverage,DirectoryHash /p:Configuration=Release /p:Platform=ARM64
pwsh -File .\PerformanceTests\Test-DirectoryHash.ps1 -App .\ARM64\Release\DirectoryHash.exe -OutputDirectory .\out\hash-check
pwsh -File .\PerformanceTests\Measure-DirectoryHash.ps1 -Tool .\ARM64\Release\OpenCppCoverage.exe -App .\ARM64\Release\DirectoryHash.exe -OutputDirectory .\out\hash-performance
```

The PowerShell 7 runner generates a deterministic **128 MiB / 256-file** directory
in the new output directory. It verifies hashes independently with .NET and warms
the filesystem cache before timing. Two counterbalanced pairs run collector then
baseline, followed by baseline then collector, with 33 directory passes per
process. `-DataMiB`, `-Passes`, and `-Pairs` adjust those defaults.

Collection selects KernelBase, SHCore, BCrypt, and the workload EXE. The workload
copy has no adjacent PDB; symbol paths are cleared and collection is symbol-free.
Both modes run without WPR. Every pass must match the independent digest, counts,
and byte total; raw captures must contain executed blocks for all four modules
and matching image hashes.

`measurements.json` retains per-pass data, binary identities and raw module
counts; `summary.json` reports mode averages. Startup covers process creation
through the start of work. First-pass time includes initial runtime breakpoint
hits; later passes measure warmed execution. End-to-end time includes launch,
all passes, shutdown, and coverage serialization. Application CPU excludes
collector CPU; `launchedProcessCpuSeconds` is collector CPU in collected runs and
application CPU in baseline runs. These are warm-cache, single-threaded workload
measurements, with the selected module set determining the coverage overhead.
CNG provider code in additional DLLs is outside the selected module set.

`--verbose` logs per-module RVA preparation timings for image parsing, discovery,
mapped-code validation, and breakpoint installation. Each phase reports wall time
and collector-thread CPU time; CPU accounting has Windows scheduler granularity.
Diagnostics also identify discovery-cache reuse and shared-hit retirement.

The fresh-code fixture checks first-hit and queued-breakpoint handling with four
synchronized threads calling 1,024 distinct functions. Each thread verifies its
checksum; the runner verifies that every function entry is covered, then reports
the first pass and a warmed repeat separately. Use the Release console
fixture so incremental-link jump thunks do not obscure function entry RVAs.

```powershell
.\PerformanceTests\Measure-FreshCode.ps1 -Tool .\ARM64\Release\OpenCppCoverage.exe -Fixture .\ARM64\Release\TestCoverageConsole.exe -OutputDirectory .\out\fresh-code
```

The runner copies the fixture without adjacent PDBs, clears symbol paths, warms
the fixture, and counterbalances uncollected and collected runs. Every measured
run starts a new process. `-ControlTool` adds a second collector build for
comparisons using the same fixture.
