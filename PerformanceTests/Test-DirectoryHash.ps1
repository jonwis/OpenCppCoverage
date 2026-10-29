#requires -Version 7.0
param(
    [Parameter(Mandatory)][string]$App,
    [Parameter(Mandatory)][string]$OutputDirectory
)

$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false
$App = (Resolve-Path -LiteralPath $App).Path
$OutputDirectory = [IO.Path]::GetFullPath($OutputDirectory)
if (Test-Path -LiteralPath $OutputDirectory) { throw 'Test output directory already exists.' }
$inputDirectory = Join-Path $OutputDirectory 'input with spaces'
$null = New-Item -ItemType Directory -Path $inputDirectory

function Check-Hashes {
    $paths = [string[]][IO.Directory]::GetFiles($inputDirectory, '*', [IO.SearchOption]::AllDirectories)
    [Array]::Sort($paths, [StringComparer]::Ordinal)
    $bytes = 0
    $aggregate = [Security.Cryptography.IncrementalHash]::CreateHash([Security.Cryptography.HashAlgorithmName]::SHA256)
    try {
        foreach ($path in $paths) {
            $data = [IO.File]::ReadAllBytes($path)
            $bytes += $data.Length
            $aggregate.AppendData([Security.Cryptography.SHA256]::HashData($data))
        }
        $digest = [Convert]::ToHexString($aggregate.GetHashAndReset()).ToLowerInvariant()
    }
    finally { $aggregate.Dispose() }
    $json = & $App $inputDirectory 2
    if ($LASTEXITCODE) { throw 'Directory hashing failed.' }
    $result = $json | ConvertFrom-Json
    if ($result.passes.Count -ne 2) { throw 'Incorrect pass count.' }
    foreach ($pass in $result.passes) {
        if ($pass.files -ne $paths.Count -or $pass.bytes -ne $bytes -or $pass.digest -ne $digest) {
            throw 'SHA-256, byte count or file count mismatch.'
        }
    }
}

Check-Hashes
[IO.File]::WriteAllText((Join-Path $inputDirectory 'abc.txt'), 'abc', [Text.Encoding]::ASCII)
Check-Hashes
$nested = Join-Path $inputDirectory ('nested-' + [char]0xE9)
$null = New-Item -ItemType Directory -Path $nested
[IO.File]::WriteAllBytes((Join-Path $nested 'empty.bin'), [byte[]]::new(0))
$data = [byte[]]::new(262147)
[Random]::new(7).NextBytes($data)
[IO.File]::WriteAllBytes((Join-Path $nested 'multiple buffers.bin'), $data)
Check-Hashes
$outside = Join-Path $OutputDirectory 'outside'
$null = New-Item -ItemType Directory -Path $outside
[IO.File]::WriteAllText((Join-Path $outside 'excluded.txt'), 'excluded')
$null = New-Item -ItemType Junction -Path (Join-Path $inputDirectory 'junction') -Target $outside
$json = & $App $inputDirectory 2
if ($LASTEXITCODE) { throw 'Reparse-point test failed.' }
$result = $json | ConvertFrom-Json
if ($result.passes[0].files -ne 3 -or $result.passes[0].skippedReparsePoints -ne 1) {
    throw 'Directory junction was followed.'
}
foreach ($arguments in @(
    @((Join-Path $OutputDirectory 'missing'), '1'),
    @((Join-Path $inputDirectory 'abc.txt'), '1'),
    @($inputDirectory, '0'),
    @($inputDirectory, '129'),
    @($inputDirectory, '-4294967295'),
    @($inputDirectory, 'invalid')
)) {
    & $App @arguments *> $null
    if ($LASTEXITCODE -eq 0) { throw 'Invalid input was accepted.' }
}
$locked = [IO.File]::Open((Join-Path $inputDirectory 'abc.txt'),
    [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::None)
try {
    & $App $inputDirectory 1 *> $null
    if ($LASTEXITCODE -eq 0) { throw 'An unreadable file was silently skipped.' }
}
finally { $locked.Dispose() }
Write-Output 'Directory SHA-256, empty input, repeated passes, Unicode paths, reparse exclusion and error cases passed.'
exit 0
