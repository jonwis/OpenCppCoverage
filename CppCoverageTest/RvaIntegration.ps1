param(
    [Parameter(Mandatory)][string]$Tool,
    [Parameter(Mandatory)][string]$Fixture,
    [Parameter(Mandatory)][string]$Pdb,
    [Parameter(Mandatory)][string]$OutputDirectory,
    [switch]$ExpectMixedIsa
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
