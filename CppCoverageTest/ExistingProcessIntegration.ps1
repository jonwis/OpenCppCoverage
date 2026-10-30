# OpenCppCoverage is an open source code coverage for C++.
# Copyright (C) 2026 Jon Wiswall
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.

param(
    [Parameter(Mandatory = $true)][string]$Tool,
    [Parameter(Mandatory = $true)][string]$Fixture,
    [Parameter(Mandatory = $true)][string]$OutputDirectory,
    [string]$Library,
    [int]$AdmissionTimeoutSeconds = 30,
    [switch]$LibraryOnly,
    [switch]$Cancel,
    [switch]$RejectDebugged,
    [switch]$LoaderLock,
    [switch]$ExitDuringCollection,
    [switch]$ExpectMixedIsa
)
$ErrorActionPreference = 'Stop'
if ($LibraryOnly -and !$Library) { throw 'LibraryOnly requires Library.' }
if ($LoaderLock -and !$Library) { throw 'LoaderLock requires Library.' }
if ($RejectDebugged -and !$Cancel) { throw 'RejectDebugged requires Cancel.' }
$Tool = (Resolve-Path -LiteralPath $Tool).Path
$Fixture = (Resolve-Path -LiteralPath $Fixture).Path
$null = New-Item -ItemType Directory -Force -Path $OutputDirectory
$OutputDirectory = (Resolve-Path -LiteralPath $OutputDirectory).Path
$tag = 'occ-' + [Guid]::NewGuid().ToString('N').Substring(0, 10)
$events = @{}
$processes = @()
$targetPaths = @{}
$collector = $null
$passed = $false

function Start-OwnedProcess([string]$Path, [string[]]$Arguments, [string]$Name) {
    $start = [Diagnostics.ProcessStartInfo]::new($Path)
    $start.UseShellExecute = $false
    foreach ($argument in $Arguments) { $start.ArgumentList.Add($argument) }
    return [Diagnostics.Process]::Start($start)
}

function Read-CollectorLog([string]$Name) {
    return ((Get-Content -LiteralPath (Join-Path $OutputDirectory "$Name.stdout.log") -Raw -ErrorAction SilentlyContinue) +
            (Get-Content -LiteralPath (Join-Path $OutputDirectory "$Name.stderr.log") -Raw -ErrorAction SilentlyContinue))
}

try {
    $fixtureDirectory = Join-Path $OutputDirectory 'fixtures'
    $null = New-Item -ItemType Directory -Force -Path $fixtureDirectory
    if ($Library) {
        $Library = (Resolve-Path -LiteralPath $Library).Path
        Get-ChildItem -LiteralPath (Split-Path -Parent $Library) -Filter '*.dll' |
            Copy-Item -Destination $fixtureDirectory -Force
    }
    foreach ($role in 'a', 'b', 'excluded') {
        $path = Join-Path $fixtureDirectory "$tag-match-$role.exe"
        $targetPaths[$role] = $path
        Copy-Item -LiteralPath $Fixture -Destination $path -Force
        $prefix = "Local\$tag-$role"
        foreach ($event in 'ready', 'work', 'stop', 'load', 'post', 'checked', 'hit', 'locked', 'release', 'unlocked') {
            $events["$role-$event"] = [Threading.EventWaitHandle]::new(
                $false, [Threading.EventResetMode]::ManualReset, "$prefix-$event")
        }
        $arguments = @('--external-work', $prefix)
        if ($Library) {
            $arguments += @(Join-Path $fixtureDirectory ([IO.Path]::GetFileName($Library)))
            $arguments += $role
            if ($role -eq 'b') { $arguments += 'delayed' }
            if ($LoaderLock -and $role -eq 'a') { $arguments += @('preloaded', 'hold-loader-lock') }
        }
        if ($role -eq 'b') {
            $parentPath = Join-Path $fixtureDirectory "$tag-parent.exe"
            Copy-Item -LiteralPath $Fixture -Destination $parentPath -Force
            $processes += Start-OwnedProcess $parentPath (@('--external-spawn', $path) + $arguments) 'parent'
        }
        else {
            $processes += Start-OwnedProcess $path $arguments $role
        }
        if (!$events["$role-ready"].WaitOne(15000)) { throw "Fixture did not become ready: $role" }
        if ($LoaderLock -and $role -eq 'a' -and !$events['a-locked'].WaitOne(15000)) {
            throw 'The original sentinel thread did not enter DllMain under the loader lock.'
        }
    }
    $rounds = if ($ExitDuringCollection) { @(1) } else { @(1, 2) }
    foreach ($round in $rounds) {
        $name = "round-$round"
        $raw = Join-Path $OutputDirectory "$name.cov"
        $xml = Join-Path $OutputDirectory "$name.xml"
        $duration = if ($Cancel) { '60' } else { '2' }
        $arguments = @('--verbose', '--symbol-free', '--duration', $duration,
                       '--export_type', "binary:$raw")
        if (!$LibraryOnly) { $arguments += @('--modules', "$tag-match-*.exe") }
        if ($Library) { $arguments += @('--modules', [IO.Path]::GetFileName($Library)) }
        if ($round -eq 1) {
            $arguments += @('--processes', "$tag-match-a.exe".ToUpperInvariant(),
                            '--processes', $targetPaths.b,
                            '--processes', "$tag-match-excluded.exe")
        }
        else { $arguments += @('--processes', "$tag-match-*.exe") }
        $arguments += @('--excluded_processes', '*excluded*')
        $pdbLocks = @()
        try {
            $pdbs = @([IO.Path]::ChangeExtension($Fixture, '.pdb'))
            if ($Library) { $pdbs += [IO.Path]::ChangeExtension($Library, '.pdb') }
            foreach ($pdb in $pdbs) {
                $pdbLocks += [IO.File]::Open($pdb, [IO.FileMode]::Open,
                    [IO.FileAccess]::Read, [IO.FileShare]::None)
            }
            if ($Cancel) {
                $cancelName = "Local\$tag-cancel-$round"
                $cancelEvent = [Threading.EventWaitHandle]::new(
                    $false, [Threading.EventResetMode]::ManualReset, $cancelName)
                $events["cancel-$round"] = $cancelEvent
                $collector = Start-OwnedProcess $Fixture (@('--external-console', $cancelName,
                    (Join-Path $OutputDirectory "$name.stdout.log"),
                    (Join-Path $OutputDirectory "$name.stderr.log"), $Tool) + $arguments) 'console'
            }
            else {
                $collector = Start-Process -FilePath $Tool -ArgumentList (
                    $arguments | ForEach-Object { '"' + $_ + '"' }) -PassThru -NoNewWindow `
                    -RedirectStandardOutput (Join-Path $OutputDirectory "$name.stdout.log") `
                    -RedirectStandardError (Join-Path $OutputDirectory "$name.stderr.log")
            }
            $deadline = [DateTime]::UtcNow.AddSeconds($AdmissionTimeoutSeconds)
            while (!$collector.HasExited -and [DateTime]::UtcNow -lt $deadline) {
                if ((Read-CollectorLog $name) -match 'cohort collection started; count=2') { break }
                Start-Sleep -Milliseconds 50
            }
            if ($collector.HasExited -or [DateTime]::UtcNow -ge $deadline) {
                throw "Collector did not admit its fixed cohort (see $name logs)."
            }
            if ($LoaderLock -and $round -eq 1) {
                if ($events['a-release'].WaitOne(0) -or $events['a-unlocked'].WaitOne(0)) {
                    throw 'The loader-lock handshake was released before bootstrap qualified.'
                }
                Write-Output 'Bootstrap completed while an original thread remained inside DllMain.'
                $null = $events['a-release'].Set()
                if (!$events['a-unlocked'].WaitOne(10000)) {
                    throw 'The original loader-lock owner did not resume and finish thread initialization.'
                }
                Write-Output 'Original loader-lock owner progressed after explicit release.'
            }
            if ($RejectDebugged) {
                $refused = Join-Path $OutputDirectory "$name.refused.log"
                & $Tool --symbol-free --processes "$tag-match-a.exe" `
                    --modules "$tag-match-*.exe" --duration 1 `
                    --export_type "binary:$(Join-Path $OutputDirectory "$name.refused.cov")" *> $refused
                if ($LASTEXITCODE -eq 0 -or
                    (Get-Content -LiteralPath $refused -Raw) -notmatch 'already has a debugger') {
                    throw 'An already-debugged target was not honestly refused.'
                }
            }
            foreach ($role in 'a', 'b', 'excluded') {
                $null = $events["$role-hit"].Reset()
                $null = $events["$role-work"].Set()
            }
            $null = $events['b-load'].Set()
            foreach ($role in 'a', 'b', 'excluded') {
                if (!$events["$role-hit"].WaitOne(30000)) {
                    throw "Fixture did not execute its coverage contributor: $role"
                }
            }
            if ($Cancel -or $ExitDuringCollection) { Start-Sleep -Milliseconds 500 }
            if ($Cancel) { $null = $cancelEvent.Set() }
            if ($ExitDuringCollection) {
                foreach ($role in 'a', 'b') { $null = $events["$role-stop"].Set() }
            }
            if (!$collector.WaitForExit(30000)) { throw 'Collector retained ownership beyond the test bound.' }
            if ($collector.ExitCode -ne 0) { throw "Collector failed: $($collector.ExitCode)" }
        }
        finally {
            foreach ($pdb in $pdbLocks) { $pdb.Dispose() }
        }
        $diagnostics = Read-CollectorLog $name
        if (!$ExitDuringCollection -and
            ($diagnostics | Select-String 'Detached existing process pid=' -AllMatches).Matches.Count -ne 2) {
            throw 'Both existing processes must detach successfully.'
        }
        foreach ($role in 'a', 'b', 'excluded') {
            if ($ExitDuringCollection -and $role -ne 'excluded') { continue }
            $null = $events["$role-checked"].Reset()
            $null = $events["$role-post"].Set()
            if (!$events["$role-checked"].WaitOne(10000)) {
                throw "Post-detach code/protection/application-exception oracle failed: $role"
            }
        }
        & $Tool --resolve $raw --export_type "cobertura:$xml" *> (Join-Path $OutputDirectory "$name.resolve.log")
        if ($LASTEXITCODE -ne 0) { throw 'Deferred resolution failed.' }
        [xml]$report = Get-Content -LiteralPath $xml -Raw
        $source = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'RvaFixture.cpp')
        foreach ($value in $(if ($LibraryOnly) { @() } else { @(17, 29) })) {
            $line = ($source | Select-String -SimpleMatch "return $value;").LineNumber
            $hits = [int]($value -eq 17)
            if (!$report.SelectNodes("//class[contains(@filename,'RvaFixture.cpp')]/lines/line[@number='$line' and @hits='$hits']").Count) {
                throw "Incorrect main-image coverage: return $value"
            }
        }
        if ($Library) {
            $source = Get-Content -LiteralPath (Join-Path $PSScriptRoot '..\TestCoverageSharedLib\TestCoverageSharedLib.cpp')
            foreach ($value in 17003, 17004, 17006) {
                $line = ($source | Select-String -SimpleMatch "return $value;").LineNumber
                $hits = [int]($value -ne 17006)
                if (!$report.SelectNodes("//class[contains(@filename,'TestCoverageSharedLib.cpp')]/lines/line[@number='$line' and @hits='$hits']").Count) {
                    throw "Incorrect shared DLL union/exclusion: return $value"
                }
            }
        }
        if ($ExpectMixedIsa) {
            $source = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'RvaFixtureX64.cpp')
            $line = ($source | Select-String -SimpleMatch 'return 31;').LineNumber
            if (!$report.SelectNodes("//class[contains(@filename,'RvaFixtureX64.cpp')]/lines/line[@number='$line' and @hits='1']").Count) {
                throw 'The emulated AMD64 path inside the ARM64EC image was not covered.'
            }
        }
        Write-Output "Existing-process round passed: $round"
    }
    $passed = $true
}
finally {
    foreach ($key in @($events.Keys)) {
        if ($key.EndsWith('-stop') -or $key.EndsWith('-release')) { $null = $events[$key].Set() }
    }
    foreach ($role in @($targetPaths.Keys)) {
        foreach ($process in @(Get-Process -Name ([IO.Path]::GetFileNameWithoutExtension($targetPaths[$role])) -ErrorAction SilentlyContinue)) {
            if (!$process.WaitForExit(5000)) {
                Write-Warning "Terminating only the disposable owned test fixture pid=$($process.Id)."
                $process.Kill()
                if (!$process.WaitForExit(3000)) {
                    Write-Warning "Disposable fixture termination is waiting for its debugger pid=$($process.Id)."
                }
            }
        }
    }
    foreach ($process in $processes) {
        if (!$process.WaitForExit(10000)) {
            Write-Warning "Owned fixture parent is waiting for its debugged child: $($process.Id)"
            continue
        }
        if ($process.ExitCode -ne 0) {
            if ($passed) { throw "Fixture did not exit correctly after detach: $($process.ExitCode)" }
            Write-Warning "Fixture exit code: $($process.ExitCode)"
        }
    }
    if ($collector -and !$collector.HasExited) {
        if (!$collector.WaitForExit(15000)) {
            $live = @()
            foreach ($path in $targetPaths.Values) {
                $live += @(Get-Process -Name ([IO.Path]::GetFileNameWithoutExtension($path)) -ErrorAction SilentlyContinue |
                    Where-Object { !$_.HasExited })
            }
            if (!$live.Count) {
                Write-Warning 'Ending only the failed test collector after all disposable target instances exited.'
                $collector.Kill()
                $null = $collector.WaitForExit(5000)
            }
            else { Write-Warning "Collector retains cleanup ownership pid=$($collector.Id)." }
        }
    }
    foreach ($event in $events.Values) { $event.Dispose() }
}
