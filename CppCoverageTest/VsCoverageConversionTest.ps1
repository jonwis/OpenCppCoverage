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

[CmdletBinding()]
param([string]$DotnetCoverage)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$script = Join-Path $PSScriptRoot '..\ConvertTo-VsCoverage.ps1'
$directory = Join-Path ([IO.Path]::GetTempPath()) ("occ coverage test " + [guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $directory
$savedEnvironment = @{}
foreach ($name in 'OCC_VS_TEST_XML', 'OCC_VS_TEST_LOG', 'OCC_VS_TEST_MODE') {
    $savedEnvironment[$name] = [Environment]::GetEnvironmentVariable($name)
}

function Assert([bool]$Condition, [string]$Message) {
    if (!$Condition) { throw $Message }
}

function Start-Process {
    param([string]$FilePath, [string]$ArgumentList)
    Add-Content -LiteralPath $env:OCC_VS_TEST_LOG -Value 'open'
}

try {
    $env:OCC_VS_TEST_XML = Join-Path $directory 'source.xml'
    $env:OCC_VS_TEST_LOG = Join-Path $directory 'calls.txt'
    $xml = @'
<coverage><sources><source /></sources><packages>
<package name="same.dll [module 1].coverage-module"><classes>
<class name="C:\source\same.cpp" filename="C:\source\same.cpp">
<methods><method name="[file-level coverage]" signature=""><lines><line number="11" hits="1"/></lines></method></methods>
<lines><line number="11" hits="1"/></lines></class>
<class name="D:\source\same.cpp" filename="D:\source\same.cpp">
<methods><method name="[file-level coverage]" signature=""><lines><line number="12" hits="0"/></lines></method></methods>
<lines><line number="12" hits="0"/></lines></class>
<class name="\\server\share\UNICODE &amp; source.cpp" filename="\\server\share\UNICODE &amp; source.cpp">
<methods><method name="[file-level coverage]" signature=""><lines><line number="13" hits="1"/></lines></method></methods>
<lines><line number="13" hits="1"/></lines></class>
</classes></package>
<package name="same.dll [module 2].coverage-module"><classes>
<class name="C:\source\same.cpp" filename="C:\source\same.cpp">
<methods><method name="[file-level coverage]" signature=""><lines><line number="11" hits="0"/></lines></method></methods>
<lines><line number="11" hits="0"/></lines></class>
</classes></package></packages></coverage>
'@
    $xml = $xml.Replace('UNICODE', [string][char]0x00e9)
    Set-Content -LiteralPath $env:OCC_VS_TEST_XML -Value $xml -Encoding utf8
    $resolver = Join-Path $directory 'resolver.ps1'
    Set-Content -LiteralPath $resolver -Value @'
param([Parameter(ValueFromRemainingArguments)][string[]]$Arguments)
Add-Content -LiteralPath $env:OCC_VS_TEST_LOG -Value 'resolve'
if ($env:OCC_VS_TEST_MODE -eq 'resolver-error') { exit 11 }
$destination = $Arguments[$Arguments.IndexOf('--export_type') + 1].Substring('cobertura-vs:'.Length)
Copy-Item -LiteralPath $env:OCC_VS_TEST_XML -Destination $destination
exit 0
'@
    $converter = Join-Path $directory 'converter.ps1'
    Set-Content -LiteralPath $converter -Value @'
param([Parameter(ValueFromRemainingArguments)][string[]]$Arguments)
if ($Arguments[0] -eq '--version') { '18.7.0'; exit 0 }
$format = $Arguments[$Arguments.IndexOf('--output-format') + 1]
$destination = $Arguments[$Arguments.IndexOf('--output') + 1]
Add-Content -LiteralPath $env:OCC_VS_TEST_LOG -Value $format
if ($env:OCC_VS_TEST_MODE -eq 'converter-error') { exit 12 }
if ($env:OCC_VS_TEST_MODE -eq 'empty') {
    [IO.File]::WriteAllText($destination, '')
    exit 0
}
[xml]$xml = Get-Content -LiteralPath $Arguments[1] -Raw
if ($format -eq 'cobertura') {
    $line = $xml.SelectSingleNode('/coverage/packages/package/classes/class/lines/line')
    switch ($env:OCC_VS_TEST_MODE) {
        'hit' { $line.SetAttribute('hits', '0') }
        'path' { $line.ParentNode.ParentNode.SetAttribute('filename', 'C:\wrong.cpp') }
        'missing' { $null = $line.ParentNode.RemoveChild($line) }
        'duplicate' { $null = $line.ParentNode.AppendChild($line.CloneNode($true)) }
    }
}
$xml.Save($destination)
exit 0
'@
    $input = Join-Path $directory 'input.cov'
    Set-Content -LiteralPath $input -Value 'capture'
    $output = Join-Path $directory 'output.coverage'
    $parameters = @{
        InputCoverage = $input
        Output = $output
        OpenCppCoverage = $resolver
        DotnetCoverage = $converter
    }
    foreach ($scenario in @(
        @{ Mode = 'normal'; Verify = $false; NoOpen = $false; Fails = $false; Calls = 'resolve,coverage,open' },
        @{ Mode = 'normal'; Verify = $true; NoOpen = $true; Fails = $false; Calls = 'resolve,coverage,cobertura' },
        @{ Mode = 'hit'; Verify = $true; NoOpen = $false; Fails = $true },
        @{ Mode = 'path'; Verify = $true; NoOpen = $false; Fails = $true },
        @{ Mode = 'missing'; Verify = $true; NoOpen = $false; Fails = $true },
        @{ Mode = 'duplicate'; Verify = $true; NoOpen = $false; Fails = $true },
        @{ Mode = 'resolver-error'; Verify = $false; NoOpen = $false; Fails = $true },
        @{ Mode = 'converter-error'; Verify = $false; NoOpen = $false; Fails = $true },
        @{ Mode = 'empty'; Verify = $false; NoOpen = $false; Fails = $true }
    )) {
        $env:OCC_VS_TEST_MODE = $scenario.Mode
        Set-Content -LiteralPath $env:OCC_VS_TEST_LOG -Value @()
        Set-Content -LiteralPath $output -Value 'previous good report'
        $failed = $false
        $failure = ''
        try { $null = & $script @parameters -Verify:$scenario.Verify -NoOpen:$scenario.NoOpen }
        catch { $failed = $true; $failure = $_.Exception.Message }
        Assert ($failed -eq $scenario.Fails) "Unexpected result for $($scenario.Mode)."
        $calls = @(Get-Content -LiteralPath $env:OCC_VS_TEST_LOG)
        if ($scenario.Fails) {
            $expectedError = switch ($scenario.Mode) {
                { $_ -in 'hit', 'path' } { 'changed a module/file/line/hit tuple' }
                'missing' { 'changed the line count' }
                'duplicate' { 'Duplicate module/file/line identity' }
                'resolver-error' { 'exit 11' }
                'converter-error' { 'exit 12' }
                'empty' { 'nonempty .coverage file' }
            }
            Assert ($failure.Contains($expectedError)) "Wrong failure for $($scenario.Mode): $failure"
            Assert ((Get-Content -LiteralPath $output -Raw).Trim() -eq 'previous good report') 'Failure overwrote the good output.'
            Assert ('open' -notin $calls) 'Failure opened a report.'
        }
        else {
            Assert (($calls -join ',') -eq $scenario.Calls) "Unexpected calls: $($calls -join ',')"
        }
        Assert (@(Get-ChildItem -LiteralPath $directory -Directory -Force).Count -eq 0) 'Temporary directory was not removed.'
    }

    if ($DotnetCoverage) {
        $ast = [Management.Automation.Language.Parser]::ParseFile($script, [ref]$null, [ref]$null)
        foreach ($definition in $ast.FindAll({
            param($node)
            $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
                $node.Name -in @('Invoke-Native', 'Read-LineMap', 'Assert-RoundTrip')
        }, $false)) {
            . ([scriptblock]::Create($definition.Extent.Text))
        }
        $native = Join-Path $directory 'real.coverage'
        $roundtrip = Join-Path $directory 'real.xml'
        $null = Invoke-Native $DotnetCoverage @('merge', $env:OCC_VS_TEST_XML,
            '--output', $native, '--output-format', 'coverage')
        $null = Invoke-Native $DotnetCoverage @('merge', $native,
            '--output', $roundtrip, '--output-format', 'cobertura')
        Assert-RoundTrip (Read-LineMap $env:OCC_VS_TEST_XML) (Read-LineMap $roundtrip)
    }
    Write-Host 'PASS: default opening, opt-in verification, loss detection, failure preservation, and cleanup.'
}
finally {
    foreach ($name in $savedEnvironment.Keys) {
        [Environment]::SetEnvironmentVariable($name, $savedEnvironment[$name])
    }
    Remove-Item -LiteralPath $directory -Recurse -Force
}
