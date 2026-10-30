#requires -Version 7.2
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

<#
.SYNOPSIS
Resolves a symbol-free capture, converts it to .coverage, and opens it.
.DESCRIPTION
Requires matching images and PDBs, PowerShell 7.2+, and dotnet-coverage 18.7.0.
Missing tooling is installed with the .NET SDK into out\tools using configured
NuGet sources and credentials. Existing global tools are unchanged.
Only -Verify performs an additional round-trip and compares module/file/line/hit
tuples. -NoOpen suppresses opening for automation.
.EXAMPLE
.\ConvertTo-VsCoverage.ps1 -InputCoverage .\run.cov -ModuleDirectory C:\Build\bin
.EXAMPLE
.\ConvertTo-VsCoverage.ps1 -InputCoverage .\run.cov -Output .\run.coverage -Verify
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$InputCoverage,
    [string]$Output,
    [string]$OpenCppCoverage,
    [string]$DotnetCoverage,
    [string]$NuGetConfigFile,
    [string[]]$ModuleDirectory = @(),
    [string[]]$Sources = @(),
    [string[]]$SourcePathSubstitution = @(),
    [switch]$Verify,
    [switch]$NoOpen
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$toolVersion = '18.7.0'

function Invoke-Native([string]$Executable, [string[]]$Arguments) {
    $messages = @(& $Executable @Arguments 2>&1)
    if ($LASTEXITCODE -ne 0) {
        throw "$Executable failed (exit $LASTEXITCODE).`n$($messages -join "`n")"
    }
    Write-Verbose ($messages -join "`n")
    return $messages
}

function Resolve-Executable([string]$Name) {
    if (Test-Path -LiteralPath $Name -PathType Leaf) {
        return (Resolve-Path -LiteralPath $Name).Path
    }
    return (Get-Command -Name $Name -CommandType Application -ErrorAction Stop).Source
}

function Find-OpenCppCoverage {
    if ($OpenCppCoverage) { return Resolve-Executable $OpenCppCoverage }
    $architecture = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()
    $platform = if ($architecture -eq 'Arm64') { 'ARM64' } else { 'x64' }
    $builds = @(foreach ($configuration in 'Release', 'Debug') {
        $candidate = Join-Path $PSScriptRoot "$platform\$configuration\OpenCppCoverage.exe"
        if (Test-Path -LiteralPath $candidate -PathType Leaf) { Get-Item -LiteralPath $candidate }
    })
    if ($builds.Count) { return ($builds | Sort-Object LastWriteTimeUtc -Descending)[0].FullName }
    $onPath = Get-Command OpenCppCoverage.exe -CommandType Application -ErrorAction SilentlyContinue
    if ($onPath) { return $onPath.Source }
    throw 'OpenCppCoverage.exe was not found. Build this revision or pass -OpenCppCoverage.'
}

function Test-CoverageTool([string]$Executable) {
    $version = Invoke-Native $Executable @('--version')
    return ($version -join "`n") -match "(?<!\d)$([regex]::Escape($toolVersion))(?:\.0)?(?![\d.])"
}

function Find-CoverageTool {
    if ($DotnetCoverage) {
        $tool = Resolve-Executable $DotnetCoverage
        if (!(Test-CoverageTool $tool)) {
            throw "Use dotnet-coverage $toolVersion, the tested conversion version."
        }
        return $tool
    }
    $onPath = Get-Command dotnet-coverage.exe -CommandType Application -ErrorAction SilentlyContinue
    if ($onPath) {
        try {
            if (Test-CoverageTool $onPath.Source) { return $onPath.Source }
        }
        catch { Write-Verbose 'The PATH tool is unusable; checking the scoped installation.' }
    }
    $directory = Join-Path $PSScriptRoot "out\tools\dotnet-coverage\$toolVersion"
    $tool = Join-Path $directory 'dotnet-coverage.exe'
    if (!(Test-Path -LiteralPath $tool -PathType Leaf)) {
        $dotnet = Resolve-Executable dotnet.exe
        $sdks = @(Invoke-Native $dotnet @('--list-sdks'))
        if (!($sdks -match '^(?:[89]|[1-9]\d+)\.')) {
            throw 'Install a .NET 8 or later SDK to bootstrap dotnet-coverage.'
        }
        $arguments = @('tool', 'install', 'dotnet-coverage', '--version', $toolVersion,
            '--tool-path', $directory)
        if ($NuGetConfigFile) { $arguments += @('--configfile', $NuGetConfigFile) }
        Write-Host "Installing dotnet-coverage $toolVersion into $directory"
        Push-Location $PSScriptRoot
        try {
            $null = Invoke-Native $dotnet $arguments
        }
        finally { Pop-Location }
    }
    if (!(Test-CoverageTool $tool)) { throw "Unexpected tool version in $directory." }
    return $tool
}

function Read-LineMap([string]$Path) {
    $settings = [System.Xml.XmlReaderSettings]::new()
    $settings.DtdProcessing = [System.Xml.DtdProcessing]::Prohibit
    $settings.XmlResolver = $null
    $reader = [System.Xml.XmlReader]::Create($Path, $settings)
    $document = [System.Xml.XmlDocument]::new()
    $document.XmlResolver = $null
    try { $document.Load($reader) }
    finally { $reader.Dispose() }
    if ($document.DocumentElement.Name -ne 'coverage') {
        throw "Expected Cobertura coverage in $Path."
    }
    $lines = [System.Collections.Generic.Dictionary[string, bool]]::new(
        [System.StringComparer]::OrdinalIgnoreCase)
    foreach ($package in $document.SelectNodes('/coverage/packages/package')) {
        $module = $package.GetAttribute('name')
        if ($module.EndsWith('.coverage-module', [System.StringComparison]::Ordinal)) {
            $module = $module.Substring(0, $module.Length - '.coverage-module'.Length)
        }
        foreach ($file in $package.SelectNodes('classes/class')) {
            $filename = $file.GetAttribute('filename').Replace('/', '\')
            foreach ($line in $file.SelectNodes('lines/line')) {
                $number = 0L
                $hits = 0L
                if (!$module -or !$filename -or
                    ![long]::TryParse($line.GetAttribute('number'), [ref]$number) -or $number -le 0 -or
                    ![long]::TryParse($line.GetAttribute('hits'), [ref]$hits) -or $hits -lt 0) {
                    throw "Invalid module/file/line/hit entry in $Path."
                }
                $key = "$module`u{001f}$filename`u{001f}$number"
                if (!$lines.TryAdd($key, $hits -gt 0)) {
                    throw "Duplicate module/file/line identity in $Path."
                }
            }
        }
    }
    if (!$lines.Count) { throw "No source lines were resolved in $Path. Check images, PDBs, and source filters." }
    return ,$lines
}

function Assert-RoundTrip($Expected, $Actual) {
    if ($Expected.Count -ne $Actual.Count) {
        throw "Coverage round-trip changed the line count ($($Expected.Count) to $($Actual.Count))."
    }
    foreach ($entry in $Expected.GetEnumerator()) {
        $hit = $false
        if (!$Actual.TryGetValue($entry.Key, [ref]$hit) -or $hit -ne $entry.Value) {
            throw "Coverage round-trip changed a module/file/line/hit tuple: $($entry.Key.Replace("`u{001f}", ' | '))"
        }
    }
}

function Open-CoverageReport([string]$Path) {
    $vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
    if (Test-Path -LiteralPath $vswhere -PathType Leaf) {
        $installations = @(Invoke-Native $vswhere @('-latest', '-products', '*',
            '-version', '[18.0,19.0)', '-property', 'installationPath'))
        if ($installations.Count) {
            $devenv = Join-Path ([string]$installations[0]) 'Common7\IDE\devenv.exe'
            if (Test-Path -LiteralPath $devenv -PathType Leaf) {
                Start-Process -FilePath $devenv -ArgumentList "`"$Path`""
                return
            }
        }
    }
    Write-Warning 'Visual Studio 2026 was not found; opening through the Windows file association.'
    try { Start-Process -FilePath $Path }
    catch { Write-Warning "Created $Path. Opening failed: $($_.Exception.Message) Open it with Visual Studio 2026." }
}

$InputCoverage = (Resolve-Path -LiteralPath $InputCoverage).Path
if (!$Output) { $Output = [System.IO.Path]::ChangeExtension($InputCoverage, '.coverage') }
$Output = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Output)
if ([System.IO.Path]::GetExtension($Output) -ine '.coverage' -or $Output -ieq $InputCoverage) {
    throw 'Output must be a .coverage file distinct from the input capture.'
}
if ($NuGetConfigFile) { $NuGetConfigFile = (Resolve-Path -LiteralPath $NuGetConfigFile).Path }
$resolver = Find-OpenCppCoverage
$converter = Find-CoverageTool
$directory = [System.IO.Path]::GetDirectoryName($Output)
$null = New-Item -ItemType Directory -Path $directory -Force
$temporary = Join-Path $directory ('.vscoverage-' + [guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $temporary
$resolved = Join-Path $temporary 'resolved.xml'
$converted = Join-Path $temporary 'converted.coverage'
$roundTrip = Join-Path $temporary 'roundtrip.xml'
try {
    $arguments = @('--resolve', $InputCoverage, '--export_type', "cobertura-vs:$resolved")
    foreach ($path in $ModuleDirectory) { $arguments += @('--module_dir', $path) }
    foreach ($pattern in $Sources) { $arguments += @('--sources', $pattern) }
    foreach ($substitution in $SourcePathSubstitution) {
        $arguments += @('--substitute_pdb_source_path', $substitution)
    }
    $null = Invoke-Native $resolver $arguments
    $expected = Read-LineMap $resolved
    $null = Invoke-Native $converter @('merge', $resolved, '--output', $converted,
        '--output-format', 'coverage')
    if (!(Test-Path -LiteralPath $converted -PathType Leaf) -or
        (Get-Item -LiteralPath $converted).Length -eq 0) {
        throw 'dotnet-coverage did not produce a nonempty .coverage file.'
    }
    if ($Verify) {
        $null = Invoke-Native $converter @('merge', $converted, '--output', $roundTrip,
            '--output-format', 'cobertura')
        Assert-RoundTrip $expected (Read-LineMap $roundTrip)
        Write-Host "Verified $($expected.Count) module/file/line/hit tuples."
    }
    Move-Item -LiteralPath $converted -Destination $Output -Force
}
finally {
    Remove-Item -LiteralPath $temporary -Recurse -Force
}
Write-Host "Created $Output"
if (!$NoOpen) { Open-CoverageReport $Output }
$Output
