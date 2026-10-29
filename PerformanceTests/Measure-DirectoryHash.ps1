#requires -Version 7.0
param(
    [Parameter(Mandatory)][string]$Tool,
    [Parameter(Mandatory)][string]$App,
    [Parameter(Mandatory)][string]$OutputDirectory,
    [ValidateRange(1, 512)][int]$DataMiB = 128,
    [ValidateRange(2, 128)][int]$Passes = 33,
    [ValidateRange(2, 10)][int]$Pairs = 2
)

$ErrorActionPreference = 'Stop'
$Tool = (Resolve-Path -LiteralPath $Tool).Path
$App = (Resolve-Path -LiteralPath $App).Path
$OutputDirectory = [IO.Path]::GetFullPath($OutputDirectory)
if (Test-Path -LiteralPath $OutputDirectory) { throw 'Output directory already exists.' }
$null = New-Item -ItemType Directory -Path $OutputDirectory

function Save-Json($Path, $Value) {
    $text = ($Value | ConvertTo-Json -Depth 12) + "`n"
    [IO.File]::WriteAllText($Path, $text.Replace("`r`n", "`n").Replace("`n", "`r`n"))
}

function Read-RvaString([IO.BinaryReader]$Reader) {
    $length = $Reader.ReadUInt32()
    if ($length -gt 32767) { throw 'Invalid raw coverage string.' }
    return [Text.Encoding]::Unicode.GetString($Reader.ReadBytes([int]($length * 2)))
}

function Read-RvaModules($Path, $ExpectedNames) {
    $reader = [IO.BinaryReader]::new([IO.File]::OpenRead($Path))
    try {
        if ([Convert]::ToHexString($reader.ReadBytes(8)) -ne '4F43435256414300' -or
            $reader.ReadUInt32() -ne 1) { throw 'Invalid raw coverage header.' }
        $null = Read-RvaString $reader
        if ($reader.ReadInt32() -ne 0) { throw 'Nonzero target exit code in raw coverage.' }
        $count = $reader.ReadUInt32()
        if ($count -ne $ExpectedNames.Count) { throw 'Incorrect selected module count.' }
        $modules = @()
        $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        for ($i = 0; $i -lt $count; ++$i) {
            $path = Read-RvaString $reader
            $name = [IO.Path]::GetFileName($path)
            if ($name -notin $ExpectedNames -or !$seen.Add($name)) { throw "Unexpected module: $name" }
            $machine = $reader.ReadUInt16()
            $null = $reader.ReadBytes(32)
            $hash = [Convert]::ToHexString($reader.ReadBytes(32))
            if ((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -ne $hash) {
                throw "Module image hash mismatch: $path"
            }
            $blocks = $reader.ReadUInt32()
            if (!$blocks -or $blocks -gt 16MB -or $blocks * 11 -gt $reader.BaseStream.Length - $reader.BaseStream.Position) {
                throw "Invalid raw block count: $name"
            }
            $records = $reader.ReadBytes([int]($blocks * 11))
            $hits = 0
            for ($offset = 10; $offset -lt $records.Length; $offset += 11) {
                if ($records[$offset] -eq 1) { ++$hits }
                elseif ($records[$offset] -ne 0) { throw 'Invalid raw execution flag.' }
            }
            if (!$hits) { throw "No covered blocks in $name" }
            $modules += [pscustomobject]@{
                name = $name; path = $path; machine = ('0x{0:x4}' -f $machine)
                imageSha256 = $hash; blocks = $blocks; executedBlocks = $hits
            }
        }
        if ($reader.BaseStream.Position -ne $reader.BaseStream.Length) { throw 'Trailing raw coverage data.' }
        return $modules
    }
    finally { $reader.Dispose() }
}

$inputDirectory = Join-Path $OutputDirectory 'input'
$bin = Join-Path $OutputDirectory 'bin'
$null = New-Item -ItemType Directory -Path $inputDirectory, $bin
$workload = Join-Path $bin ([IO.Path]::GetFileName($App))
Copy-Item -LiteralPath $App -Destination $workload
$names = @('kernelbase.dll', 'shcore.dll', 'bcrypt.dll', [IO.Path]::GetFileName($workload))
$random = [Random]::new(42)
$buffer = [byte[]]::new($DataMiB * 1MB / 256)
for ($i = 0; $i -lt 256; ++$i) {
    $directory = Join-Path $inputDirectory ('part-{0:D2}' -f ($i % 16))
    $null = New-Item -ItemType Directory -Force -Path $directory
    $random.NextBytes($buffer)
    [IO.File]::WriteAllBytes((Join-Path $directory ('file-{0:D4}.bin' -f $i)), $buffer)
}

# Verify the workload and warm the filesystem cache before either timed mode.
$paths = [string[]][IO.Directory]::GetFiles($inputDirectory, '*', [IO.SearchOption]::AllDirectories)
[Array]::Sort($paths, [StringComparer]::Ordinal)
$aggregate = [Security.Cryptography.IncrementalHash]::CreateHash([Security.Cryptography.HashAlgorithmName]::SHA256)
try {
    foreach ($path in $paths) {
        $stream = [IO.File]::OpenRead($path)
        try { $aggregate.AppendData([Security.Cryptography.SHA256]::HashData($stream)) }
        finally { $stream.Dispose() }
    }
    $expectedDigest = [Convert]::ToHexString($aggregate.GetHashAndReset()).ToLowerInvariant()
}
finally { $aggregate.Dispose() }

$settings = [ordered]@{
    dataMiB = $DataMiB; files = $paths.Count; passes = $Passes; pairs = $Pairs
    expectedDigest = $expectedDigest; tracingEnabled = $false; symbolFree = $true
    osArchitecture = [Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()
    osVersion = [Environment]::OSVersion.VersionString
    tool = $Tool; toolSha256 = (Get-FileHash -LiteralPath $Tool).Hash
    collectorDllSha256 = (Get-FileHash -LiteralPath (Join-Path (Split-Path $Tool) 'CppCoverage.dll')).Hash
    app = $workload; appSha256 = (Get-FileHash -LiteralPath $workload).Hash
}
$results = [Collections.Generic.List[object]]::new()
foreach ($pair in 1..$Pairs) {
    $modes = if ($pair % 2) { @('collector', 'baseline') } else { @('baseline', 'collector') }
    foreach ($mode in $modes) {
        $directory = Join-Path $OutputDirectory ("pair-$pair-$mode")
        $null = New-Item -ItemType Directory -Path $directory
        $raw = Join-Path $directory 'coverage.cov'
        $info = [Diagnostics.ProcessStartInfo]::new()
        $info.FileName = if ($mode -eq 'collector') { $Tool } else { $workload }
        $info.WorkingDirectory = $directory
        $info.UseShellExecute = $false
        $info.RedirectStandardOutput = $true
        $info.RedirectStandardError = $true
        $info.Environment['_NT_SYMBOL_PATH'] = ''
        $info.Environment['_NT_ALT_SYMBOL_PATH'] = ''
        if ($mode -eq 'collector') {
            $info.ArgumentList.Add('--symbol-free')
            foreach ($name in $names) {
                $info.ArgumentList.Add('--modules')
                $info.ArgumentList.Add($name)
            }
            foreach ($argument in @('--export_type', "binary:$raw", '--', $workload)) {
                $info.ArgumentList.Add($argument)
            }
        }
        $info.ArgumentList.Add($inputDirectory)
        $info.ArgumentList.Add("$Passes")
        $process = [Diagnostics.Process]::new()
        $process.StartInfo = $info
        $launched = $false
        $started = [DateTime]::UtcNow.ToString('o')
        $watch = [Diagnostics.Stopwatch]::StartNew()
        try {
            if (!$process.Start()) { throw 'Failed to launch benchmark.' }
            $launched = $true
            $stdout = $process.StandardOutput.ReadToEndAsync()
            $stderr = $process.StandardError.ReadToEndAsync()
            if (!$process.WaitForExit(300000)) {
                Stop-Process -Id $process.Id -Force
                throw 'Benchmark exceeded five minutes.'
            }
            $wall = $watch.Elapsed.TotalSeconds
            $cpu = $process.TotalProcessorTime.TotalSeconds
            $text = $stdout.GetAwaiter().GetResult()
            [IO.File]::WriteAllText((Join-Path $directory 'stdout.log'), $text)
            [IO.File]::WriteAllText((Join-Path $directory 'stderr.log'), $stderr.GetAwaiter().GetResult())
            if ($process.ExitCode -ne 0) { throw "Benchmark failed: $mode, exit $($process.ExitCode). See $directory" }
        }
        finally {
            if ($launched -and !$process.HasExited) { Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue }
            $process.Dispose()
        }
        $json = @($text -split '\r?\n' | Where-Object { $_.StartsWith('{"startupSeconds":') })
        if ($json.Count -ne 1) { throw 'Missing workload measurements.' }
        $appResult = $json[0] | ConvertFrom-Json
        if ($appResult.passes.Count -ne $Passes) { throw 'Incorrect pass count.' }
        foreach ($pass in $appResult.passes) {
            if ($pass.files -ne 256 -or $pass.bytes -ne $DataMiB * 1MB -or
                $pass.digest -ne $expectedDigest -or $pass.skippedReparsePoints -ne 0) {
                throw 'Workload output does not match the independent SHA-256 calculation.'
            }
        }
        $warm = @($appResult.passes | Select-Object -Skip 1)
        $warmSeconds = ($warm.seconds | Measure-Object -Sum).Sum
        $modules = @()
        if ($mode -eq 'collector') { $modules = @(Read-RvaModules $raw $names) }
        $record = [pscustomobject]@{
            pair = $pair; mode = $mode; startedUtc = $started
            endToEndSeconds = $wall; launchedProcessCpuSeconds = $cpu
            startupSeconds = $appResult.startupSeconds
            firstPassSeconds = $appResult.passes[0].seconds
            warmSeconds = $warmSeconds
            warmMiBPerSecond = $DataMiB * ($Passes - 1) / $warmSeconds
            warmCpuSeconds = ($warm.cpuSeconds | Measure-Object -Sum).Sum
            app = $appResult; modules = @($modules)
        }
        Save-Json (Join-Path $directory 'measurements.json') $record
        $results.Add($record)
        Save-Json (Join-Path $OutputDirectory 'measurements.json') @{ settings = $settings; runs = @($results.ToArray()) }
        Write-Output ("Pair {0} {1}: startup {2:F3}s; first pass {3:F3}s; warm {4:F3}s ({5:F1} MiB/s); end-to-end {6:F3}s" -f
            $pair, $mode, $record.startupSeconds, $record.firstPassSeconds,
            $record.warmSeconds, $record.warmMiBPerSecond, $wall)
    }
}
$summary = foreach ($mode in @('baseline', 'collector')) {
    $runs = @($results | Where-Object mode -eq $mode)
    [pscustomobject]@{
        mode = $mode
        startupSeconds = ($runs.startupSeconds | Measure-Object -Average).Average
        firstPassSeconds = ($runs.firstPassSeconds | Measure-Object -Average).Average
        warmSeconds = ($runs.warmSeconds | Measure-Object -Average).Average
        warmMiBPerSecond = $DataMiB * ($Passes - 1) / ($runs.warmSeconds | Measure-Object -Average).Average
        endToEndSeconds = ($runs.endToEndSeconds | Measure-Object -Average).Average
    }
}
Save-Json (Join-Path $OutputDirectory 'summary.json') @($summary)
$summary | Format-Table -AutoSize
