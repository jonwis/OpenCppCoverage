param(
    [Parameter(Mandatory)][string]$Tool,
    [Parameter(Mandatory)][string]$Fixture,
    [Parameter(Mandatory)][string]$Pdb,
    [Parameter(Mandatory)][string]$OutputDirectory,
    [switch]$ExpectMixedIsa,
    [string]$ConsoleFixture
)

$ErrorActionPreference = 'Stop'
$null = New-Item -ItemType Directory -Force -Path $OutputDirectory
$raw = Join-Path $OutputDirectory 'fixture.cov'
$xml = Join-Path $OutputDirectory 'fixture.xml'
$hiddenPdb = "$Pdb.hidden"
Move-Item -LiteralPath $Pdb -Destination $hiddenPdb
try {
    & $Tool --symbol-free --modules (Split-Path -Leaf $Fixture) --export_type "binary:$raw" -- $Fixture
    if ($LASTEXITCODE -ne 0) { throw "Symbol-free collection failed: $LASTEXITCODE" }
    if (!(Test-Path -LiteralPath $raw)) { throw 'RVA coverage was not written.' }
}
finally {
    Move-Item -LiteralPath $hiddenPdb -Destination $Pdb
}

& $Tool --resolve $raw --sources '*RvaFixture*.cpp' --export_type "cobertura:$xml"
if ($LASTEXITCODE -ne 0) { throw "Resolution failed: $LASTEXITCODE" }
[xml]$report = Get-Content -LiteralPath $xml -Raw
$source = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'RvaFixture.cpp')
$hitLine = [array]::IndexOf($source, "`treturn 17;") + 1
$missLine = [array]::IndexOf($source, "`treturn 29;") + 1
$lines = @($report.SelectNodes('//class[contains(@filename,"RvaFixture.cpp")]/lines/line'))
if (!($lines | Where-Object { $_.number -eq "$hitLine" -and [int]$_.hits -gt 0 })) {
    throw 'The executed export did not resolve as covered.'
}
if (!($lines | Where-Object { $_.number -eq "$missLine" -and [int]$_.hits -eq 0 })) {
    throw 'The unexecuted export did not resolve as uncovered.'
}
if ($ExpectMixedIsa) {
    $x64Source = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'RvaFixtureX64.cpp')
    $x64HitLine = [array]::IndexOf($x64Source, "`treturn 31;") + 1
    $x64Lines = @($report.SelectNodes('//class[contains(@filename,"RvaFixtureX64.cpp")]/lines/line'))
    if (!($x64Lines | Where-Object { $_.number -eq "$x64HitLine" -and [int]$_.hits -gt 0 })) {
        throw 'The mixed ARM64EC process did not cover its AMD64 function.'
    }
}

& $Tool --resolve $raw --export_type "html:$(Join-Path $OutputDirectory 'html')" --export_type "binary:$(Join-Path $OutputDirectory 'resolved.cov')"
if ($LASTEXITCODE -ne 0) { throw "Resolved exports failed: $LASTEXITCODE" }
if (!(Test-Path -LiteralPath (Join-Path $OutputDirectory 'html\index.html'))) {
    throw 'HTML report was not written.'
}

$relocated = Join-Path $OutputDirectory 'relocated'
$null = New-Item -ItemType Directory -Force -Path $relocated
$relocatedImage = Join-Path $relocated (Split-Path -Leaf $Fixture)
Copy-Item -LiteralPath $Fixture -Destination $relocatedImage
$hiddenImage = "$Fixture.hidden"
Move-Item -LiteralPath $Fixture -Destination $hiddenImage
try {
    & $Tool --resolve $raw --modules $Fixture --module_dir $relocated --export_type "cobertura:$(Join-Path $OutputDirectory 'relocated.xml')"
    if ($LASTEXITCODE -ne 0) { throw 'Matching relocated image did not resolve.' }
    [xml]$relocatedReport = Get-Content -LiteralPath (Join-Path $OutputDirectory 'relocated.xml') -Raw
    if (!$relocatedReport.SelectNodes('//line[@hits="1"]').Count) {
        throw 'The module filter discarded the matching relocated image.'
    }

    $stream = [System.IO.File]::Open($relocatedImage, [System.IO.FileMode]::Append)
    try { $stream.WriteByte(0) } finally { $stream.Dispose() }
    $mismatchedReport = Join-Path $OutputDirectory 'mismatched.xml'
    if (Test-Path -LiteralPath $mismatchedReport) { Remove-Item -LiteralPath $mismatchedReport }
    & $Tool --resolve $raw --module_dir $relocated --export_type "cobertura:$mismatchedReport"
    if ($LASTEXITCODE -eq 0 -or (Test-Path -LiteralPath $mismatchedReport)) {
        throw 'Resolution accepted an image with mismatched content.'
    }
}
finally {
    Move-Item -LiteralPath $hiddenImage -Destination $Fixture
}

if ($ConsoleFixture) {
    foreach ($mode in 'before-load', 'resident') {
        $aggregateRaw = Join-Path $OutputDirectory "aggregate-$mode.cov"
        $aggregateXml = Join-Path $OutputDirectory "aggregate-$mode.xml"
        $aggregateLog = Join-Path $OutputDirectory "aggregate-$mode.log"
        $consolePdb = [IO.Path]::ChangeExtension($ConsoleFixture, '.pdb')
        $hiddenConsolePdb = "$consolePdb.hidden"
        Move-Item -LiteralPath $consolePdb -Destination $hiddenConsolePdb
        try {
            & $Tool --verbose --symbol-free --cover_children --modules (Split-Path -Leaf $ConsoleFixture) `
                --export_type "binary:$aggregateRaw" -- $ConsoleFixture ChildProcess --rva-aggregate $mode *> $aggregateLog
            if ($LASTEXITCODE -ne 0) { throw "Parent/child aggregation failed: $mode (see $aggregateLog)" }
        }
        finally {
            Move-Item -LiteralPath $hiddenConsolePdb -Destination $consolePdb
        }
        $diagnostics = Get-Content -LiteralPath $aggregateLog -Raw
        if ($diagnostics -notmatch 'discovery_cached=true') {
            throw 'The child did not reuse session discovery.'
        }
        if ($mode -eq 'resident' -and $diagnostics -notmatch 'RVA shared hits .* restored=[1-9]') {
            throw 'No resident child breakpoint was retired.'
        }
        & $Tool --resolve $aggregateRaw --sources '*RvaAggregation.cpp' --export_type "cobertura:$aggregateXml"
        if ($LASTEXITCODE -ne 0) { throw 'Parent/child aggregation did not resolve.' }
        [xml]$aggregateReport = Get-Content -LiteralPath $aggregateXml -Raw
        $aggregateSource = Get-Content -LiteralPath (Join-Path $PSScriptRoot '..\TestCoverageConsole\RvaAggregation.cpp')
        foreach ($statement in 'return 123;', 'return 456;') {
            $line = ($aggregateSource | Select-String -SimpleMatch $statement).LineNumber
            if (!$aggregateReport.SelectNodes("//class[contains(@filename,'RvaAggregation.cpp')]/lines/line[@number='$line' and @hits='1']").Count) {
                throw "The parent/child union did not cover: $statement"
            }
        }
    }

    $consoleSource = Get-Content -LiteralPath (Join-Path $PSScriptRoot '..\TestCoverageConsole\TestCoverageConsole.cpp')
    foreach ($coverChildren in $false, $true) {
        $childRaw = Join-Path $OutputDirectory "children-$coverChildren.cov"
        $childXml = Join-Path $OutputDirectory "children-$coverChildren.xml"
        $arguments = @('--symbol-free', '--modules', (Split-Path -Leaf $ConsoleFixture),
                       '--export_type', "binary:$childRaw")
        if ($coverChildren) { $arguments += '--cover_children' }
        & $Tool @arguments -- $ConsoleFixture ChildProcess TestBasic TestSharedLib
        if ($LASTEXITCODE -ne 0) { throw 'Child process collection failed.' }
        & $Tool --resolve $childRaw --sources '*TestCoverageConsole.cpp' --export_type "cobertura:$childXml"
        if ($LASTEXITCODE -ne 0) { throw 'Child process resolution failed.' }
        [xml]$childReport = Get-Content -LiteralPath $childXml -Raw
        foreach ($statement in 'TestCoverageConsole::RunTestBasic();', 'TestCoverageSharedLib::IsOdd(42);') {
            $line = ($consoleSource | Select-String -SimpleMatch $statement).LineNumber
            $hits = [int]$coverChildren
            if (!$childReport.SelectNodes("//line[@number='$line' and @hits='$hits']").Count) {
                throw "Incorrect child-only coverage with cover_children=$coverChildren`: $statement"
            }
        }
    }

    $reloadRaw = Join-Path $OutputDirectory 'reload.cov'
    $reloadXml = Join-Path $OutputDirectory 'reload.xml'
    & $Tool --symbol-free --modules TestHelper.dll --export_type "binary:$reloadRaw" -- $ConsoleFixture TestUnloadReloadDll
    if ($LASTEXITCODE -ne 0) { throw 'DLL unload/reload collection failed.' }
    & $Tool --resolve $reloadRaw --sources '*TestHelper*Tools.cpp' --export_type "cobertura:$reloadXml"
    if ($LASTEXITCODE -ne 0) { throw 'DLL unload/reload resolution failed.' }
    [xml]$reloadReport = Get-Content -LiteralPath $reloadXml -Raw
    $helperSource = Get-Content -LiteralPath (Join-Path $PSScriptRoot '..\TestHelper\Tools.cpp')
    $line = ($helperSource | Select-String -SimpleMatch 'void TestUnloadDll()').LineNumber + 1
    if (!$reloadReport.SelectNodes("//line[@number='$line' and @hits='1']").Count) {
        throw 'The reloaded DLL export was not covered.'
    }

    $chainDirectory = Join-Path $OutputDirectory 'chain-fixtures'
    $null = New-Item -ItemType Directory -Force -Path $chainDirectory
    $consoleDirectory = Split-Path -Parent $ConsoleFixture
    Get-ChildItem -LiteralPath $consoleDirectory -Filter '*.dll' |
        Copy-Item -Destination $chainDirectory -Force
    foreach ($name in 'chain-root', 'chain-middle', 'chain-match-a', 'chain-match-b',
                       'chain-match-grandchild', 'chain-match-excluded') {
        Copy-Item -LiteralPath $ConsoleFixture -Destination (Join-Path $chainDirectory "$name.exe") -Force
    }
    $chainConfig = Join-Path $chainDirectory 'processes.cfg'
    [IO.File]::WriteAllText($chainConfig, "processes=chain-match-a.exe`r`nprocesses=chain-match-b.exe`r`nexcluded_processes=chain-match-excluded.exe`r`n")
    $chainCases = @(
        @{ Name = 'config'; Children = $true; Hits = @(17003, 17004, 17005)
           Filters = @('--config_file', $chainConfig, '--processes', '*\chain-match-grandchild.exe',
                       '--processes', 'chain-match-excluded.exe') },
        @{ Name = 'glob'; Children = $true; Hits = @(17003, 17004, 17005)
           Filters = @('--processes', 'CHAIN-MATCH-*.EXE', '--excluded_processes', '*excluded*') },
        # Reuse the same image files: warmed emulated DLLs must still trap.
        @{ Name = 'glob-repeat'; Children = $true; Hits = @(17003, 17004, 17005)
           Filters = @('--processes', 'CHAIN-MATCH-*.EXE', '--excluded_processes', '*excluded*') },
        @{ Name = 'excludes-only'; Children = $true; Hits = @(17001, 17002, 17003, 17004, 17005)
           Filters = @('--excluded_processes', '*excluded*') },
        @{ Name = 'unfiltered'; Children = $true; Hits = @(17001, 17002, 17003, 17004, 17005, 17006)
           Filters = @() },
        @{ Name = 'root-only'; Children = $false; Hits = @(17001)
           Filters = @() }
    )
    $chainSource = Get-Content -LiteralPath (Join-Path $PSScriptRoot '..\TestCoverageSharedLib\TestCoverageSharedLib.cpp')
    $sharedPdb = Join-Path $consoleDirectory 'TestCoverageSharedLib.pdb'
    $copiedPdb = Join-Path $chainDirectory 'TestCoverageSharedLib.pdb'
    foreach ($case in $chainCases) {
        $chainRaw = Join-Path $OutputDirectory "chain-$($case.Name).cov"
        $chainXml = Join-Path $OutputDirectory "chain-$($case.Name).xml"
        $chainLog = Join-Path $OutputDirectory "chain-$($case.Name).log"
        if (Test-Path -LiteralPath $copiedPdb) { Remove-Item -LiteralPath $copiedPdb }
        $arguments = @('--verbose', '--symbol-free', '--modules', 'chain-*.exe',
                       '--modules', 'TestCoverageSharedLib.dll', '--export_type', "binary:$chainRaw")
        if ($case.Children) { $arguments += '--cover_children' }
        $arguments += $case.Filters
        $pdbLocks = @()
        try {
            # Embedded original PDB paths are inaccessible as well as adjacent copies.
            foreach ($originalPdb in [IO.Path]::ChangeExtension($ConsoleFixture, '.pdb'), $sharedPdb) {
                $pdbLocks += [IO.File]::Open($originalPdb, [IO.FileMode]::Open,
                                           [IO.FileAccess]::Read, [IO.FileShare]::None)
            }
            & $Tool @arguments -- (Join-Path $chainDirectory 'chain-root.exe') ChildProcess --rva-aggregate chain *> $chainLog
            if ($LASTEXITCODE -ne 0) { throw "Process-chain collection failed: $($case.Name) (see $chainLog)" }
        }
        finally {
            foreach ($pdbLock in $pdbLocks) { $pdbLock.Dispose() }
        }
        $diagnostics = Get-Content -LiteralPath $chainLog -Raw
        if ($case.Name -in 'config', 'glob', 'glob-repeat') {
            foreach ($unselected in 'chain-root', 'chain-middle', 'chain-match-excluded') {
                if ($diagnostics -notmatch "$unselected.exe main_trap=false") {
                    throw "An unselected main image was instrumented or never ran: $unselected"
                }
            }
            if ($diagnostics -notmatch 'chain-match-a.exe main_trap=true' -or
                $diagnostics -notmatch 'module=TestCoverageSharedLib\.dll[^\r\n]*discovery_cached=true') {
                throw 'Selected children did not install and reuse shared-image discovery.'
            }
        }
        Copy-Item -LiteralPath $sharedPdb -Destination $copiedPdb
        & $Tool --resolve $chainRaw --sources '*TestCoverageSharedLib.cpp' --export_type "cobertura:$chainXml"
        if ($LASTEXITCODE -ne 0) { throw "Process-chain resolution failed: $($case.Name)" }
        [xml]$chainReport = Get-Content -LiteralPath $chainXml -Raw
        foreach ($value in 17001..17006) {
            $line = ($chainSource | Select-String -SimpleMatch "return $value;").LineNumber
            $hits = [int]($value -in $case.Hits)
            if (!$line -or !$chainReport.SelectNodes("//class[contains(@filename,'TestCoverageSharedLib.cpp')]/lines/line[@number='$line' and @hits='$hits']").Count) {
                throw "Incorrect process-chain coverage: $($case.Name), return $value, expected hits=$hits"
            }
        }
        Write-Output "Process-chain case passed: $($case.Name)"
    }
}
