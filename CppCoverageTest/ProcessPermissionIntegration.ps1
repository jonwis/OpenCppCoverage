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
    [switch]$Watch
)
$ErrorActionPreference = 'Stop'
$Tool = (Resolve-Path -LiteralPath $Tool).Path
$Fixture = (Resolve-Path -LiteralPath $Fixture).Path
$null = New-Item -ItemType Directory -Force -Path $OutputDirectory
$OutputDirectory = (Resolve-Path -LiteralPath $OutputDirectory).Path
$tag = 'occ-denied-' + [Guid]::NewGuid().ToString('N')
$phases = @('normal', 'query', 'attach')
if ($Watch) { $phases += 'normal-watch' }
foreach ($phase in $phases) {
    $path = Join-Path $OutputDirectory "$tag-$phase.exe"
    Copy-Item -LiteralPath $Fixture -Destination $path
    $prefix = "Local\$tag-$phase"
    $ready = [Threading.EventWaitHandle]::new(
        $false, [Threading.EventResetMode]::ManualReset, "$prefix-ready")
    $stop = [Threading.EventWaitHandle]::new(
        $false, [Threading.EventResetMode]::ManualReset, "$prefix-stop")
    $work = [Threading.EventWaitHandle]::new(
        $false, [Threading.EventResetMode]::ManualReset, "$prefix-work")
    $hit = [Threading.EventWaitHandle]::new(
        $false, [Threading.EventResetMode]::ManualReset, "$prefix-hit")
    $post = [Threading.EventWaitHandle]::new(
        $false, [Threading.EventResetMode]::ManualReset, "$prefix-post")
    $checked = [Threading.EventWaitHandle]::new(
        $false, [Threading.EventResetMode]::ManualReset, "$prefix-checked")
    $process = $null
    try {
        $start = [Diagnostics.ProcessStartInfo]::new($path)
        $start.UseShellExecute = $false
        $mode = switch ($phase) {
            'normal' { '--external-work' }
            'normal-watch' { '--external-work' }
            'query' { '--external-denied' }
            'attach' { '--external-denied-attach' }
        }
        $start.ArgumentList.Add($mode)
        $start.ArgumentList.Add($prefix)
        $process = [Diagnostics.Process]::Start($start)
        if (!$ready.WaitOne(15000)) { throw "Denied-$phase fixture was not ready." }
        $arguments = @('--symbol-free', '--processes', ([IO.Path]::GetFileName($path)),
            '--modules', ([IO.Path]::GetFileName($path)), '--duration', '1',
            '--export_type', "binary:$(Join-Path $OutputDirectory "$phase.cov")")
        if ($Watch -and $phase -ne 'normal') { $arguments += '--watch_processes' }
        $log = Join-Path $OutputDirectory "$phase.log"
        & $Fixture --external-no-debug-privilege $Tool @arguments *> $log
        $denied = $phase -in @('query', 'attach')
        $expectedExitCode = [int]$denied
        if ($LASTEXITCODE -ne $expectedExitCode) {
            throw "$phase collection must return $expectedExitCode, got $LASTEXITCODE."
        }
        $text = Get-Content -LiteralPath $log -Raw
        $boundary = if ($phase -eq 'query') { 'admission' } else { 'attach' }
        if ($denied -and
            $text -notmatch "Process $boundary failed pid=$($process.Id).*Access denied") {
            throw "Denied-$phase diagnostic is missing PID, failure boundary, or access-denied explanation."
        }
        if ($text -match 'cleanup retains debugger ownership' -or $process.HasExited) {
            throw "Denied-$phase admission must leave the fixture running without retained debugger ownership."
        }
        $null = $work.Set()
        if (!$hit.WaitOne(10000)) { throw "Denied-$phase fixture did not resume useful work." }
        $null = $post.Set()
        if (!$checked.WaitOne(10000)) { throw "Denied-$phase code/protection/application-exception oracle failed." }
        Write-Output "Process permission boundary passed: $phase (watch=$($Watch -and $phase -ne 'normal'))."
    }
    finally {
        $null = $stop.Set()
        if ($process) {
            if (!$process.WaitForExit(10000)) {
                Write-Warning "Terminating only the disposable denied-access fixture pid=$($process.Id)."
                $process.Kill()
                $null = $process.WaitForExit(5000)
            }
            if ($process.HasExited -and $process.ExitCode -ne 0) {
                Write-Warning "Denied-access fixture exit code: $($process.ExitCode)"
            }
            $process.Dispose()
        }
        $ready.Dispose()
        $stop.Dispose()
        $work.Dispose()
        $hit.Dispose()
        $post.Dispose()
        $checked.Dispose()
    }
}
