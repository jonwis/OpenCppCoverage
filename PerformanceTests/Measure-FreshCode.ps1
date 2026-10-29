#requires -Version 7.0
param(
    [Parameter(Mandatory)][string]$Tool,
    [Parameter(Mandatory)][string]$Fixture,
    [Parameter(Mandatory)][string]$OutputDirectory,
    [string]$ControlTool,
    [ValidateRange(2, 20)][int]$Pairs = 4
)

$ErrorActionPreference = 'Stop'
$Tool = (Resolve-Path -LiteralPath $Tool).Path
$Fixture = (Resolve-Path -LiteralPath $Fixture).Path
if ($ControlTool) { $ControlTool = (Resolve-Path -LiteralPath $ControlTool).Path }
$OutputDirectory = [IO.Path]::GetFullPath($OutputDirectory)
if (Test-Path -LiteralPath $OutputDirectory) { throw 'Output directory already exists.' }
$bin = Join-Path $OutputDirectory 'bin'
$null = New-Item -ItemType Directory -Path $bin
Copy-Item -LiteralPath $Fixture -Destination $bin
Get-ChildItem -LiteralPath (Split-Path -Parent $Fixture) -Filter '*.dll' |
    Copy-Item -Destination $bin
$app = Join-Path $bin (Split-Path -Leaf $Fixture)
$results = [Collections.Generic.List[object]]::new()
& $app ChildProcess --rva-aggregate fresh *> (Join-Path $OutputDirectory 'warmup.log')
if ($LASTEXITCODE) { throw 'Fresh-code warmup failed.' }

for ($pair = 1; $pair -le $Pairs; ++$pair) {
    $modes = @('baseline')
    if ($ControlTool) { $modes += 'control' }
    $modes += 'collector'
    if ($pair % 2 -eq 0) { [array]::Reverse($modes) }
    foreach ($mode in $modes) {
        $stem = Join-Path $OutputDirectory "$pair-$mode"
        $raw = "$stem.cov"
        $info = [Diagnostics.ProcessStartInfo]::new()
        $info.FileName = if ($mode -eq 'baseline') { $app }
            elseif ($mode -eq 'control') { $ControlTool } else { $Tool }
        $info.UseShellExecute = $false
        $info.RedirectStandardOutput = $true
        $info.RedirectStandardError = $true
        $info.Environment['_NT_SYMBOL_PATH'] = ''
        $info.Environment['_NT_ALT_SYMBOL_PATH'] = ''
        if ($mode -ne 'baseline') {
            foreach ($argument in @('--symbol-free', '--modules', (Split-Path -Leaf $app),
                                   '--export_type', "binary:$raw", '--', $app)) {
                $info.ArgumentList.Add($argument)
            }
        }
        foreach ($argument in @('ChildProcess', '--rva-aggregate', 'fresh')) {
            $info.ArgumentList.Add($argument)
        }
        $process = [Diagnostics.Process]::new()
        $process.StartInfo = $info
        $launched = $false
        try {
            if (!$process.Start()) { throw 'Failed to launch fresh-code fixture.' }
            $launched = $true
            $stdout = $process.StandardOutput.ReadToEndAsync()
            $stderr = $process.StandardError.ReadToEndAsync()
            if (!$process.WaitForExit(60000)) {
                Stop-Process -Id $process.Id -Force
                throw 'Fresh-code fixture timed out.'
            }
            $text = $stdout.GetAwaiter().GetResult()
            [IO.File]::WriteAllText("$stem.stdout.log", $text)
            [IO.File]::WriteAllText("$stem.stderr.log", $stderr.GetAwaiter().GetResult())
            if ($process.ExitCode) { throw "Fresh-code fixture failed; see $stem.stderr.log" }
            $cpu = $process.TotalProcessorTime.TotalSeconds
        }
        finally {
            if ($launched -and !$process.HasExited) { Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue }
            $process.Dispose()
        }
        $json = @($text -split '\r?\n' | Where-Object { $_.StartsWith('{"freshSeconds":') })
        if ($json.Count -ne 1) { throw 'Missing fresh-code measurements.' }
        $record = $json[0] | ConvertFrom-Json
        if ($record.workers -ne 4 -or $record.rvas.Count -ne 1024) { throw 'Incorrect fresh-code workload.' }
        if ($mode -ne 'baseline') {
            $reader = [IO.BinaryReader]::new([IO.File]::OpenRead($raw))
            try {
                if ([Convert]::ToHexString($reader.ReadBytes(8)) -ne '4F43435256414300' -or
                    $reader.ReadUInt32() -ne 1) { throw 'Invalid raw coverage header.' }
                $null = $reader.ReadBytes([int]($reader.ReadUInt32() * 2))
                if ($reader.ReadInt32() -ne 0 -or $reader.ReadUInt32() -ne 1) {
                    throw 'Incorrect raw exit code or selected module count.'
                }
                $null = $reader.ReadBytes([int]($reader.ReadUInt32() * 2))
                $null = $reader.ReadBytes(66)
                $count = $reader.ReadUInt32()
                $hits = [Collections.Generic.HashSet[uint32]]::new()
                for ($index = 0; $index -lt $count; ++$index) {
                    $rva = $reader.ReadUInt32()
                    $null = $reader.ReadBytes(6)
                    if ($reader.ReadByte() -eq 1) { $null = $hits.Add($rva) }
                }
                foreach ($rva in $record.rvas) {
                    if (!$hits.Contains([uint32]$rva)) {
                        throw "Fresh function entry RVA $rva was not covered. Use a Release fixture without incremental linking."
                    }
                }
            }
            finally { $reader.Dispose() }
        }
        $results.Add([pscustomobject]@{
            pair = $pair; mode = $mode; freshSeconds = $record.freshSeconds
            warmSeconds = $record.warmSeconds; launchedProcessCpuSeconds = $cpu
        })
    }
}
$text = ($results.ToArray() | ConvertTo-Json) + "`r`n"
[IO.File]::WriteAllText((Join-Path $OutputDirectory 'measurements.json'), $text.Replace("`r`n", "`n").Replace("`n", "`r`n"))
$results | Group-Object mode | ForEach-Object {
    [pscustomobject]@{
        mode = $_.Name
        freshMilliseconds = [Math]::Round(1000 * ($_.Group.freshSeconds | Measure-Object -Average).Average, 3)
        freshMinMilliseconds = [Math]::Round(1000 * ($_.Group.freshSeconds | Measure-Object -Minimum).Minimum, 3)
        freshMaxMilliseconds = [Math]::Round(1000 * ($_.Group.freshSeconds | Measure-Object -Maximum).Maximum, 3)
        warmMilliseconds = [Math]::Round(1000 * ($_.Group.warmSeconds | Measure-Object -Average).Average, 3)
        launchedProcessCpuSeconds = ($_.Group.launchedProcessCpuSeconds | Measure-Object -Average).Average
    }
} | Format-Table -AutoSize
