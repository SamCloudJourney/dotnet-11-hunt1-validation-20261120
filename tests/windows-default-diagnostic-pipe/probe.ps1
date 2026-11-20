param(
    [Parameter(Mandatory = $true)][int]$TargetPid,
    [Parameter(Mandatory = $true)][string]$ResultPath
)

$ErrorActionPreference = 'Stop'
$pipeName = "dotnet-diagnostic-$TargetPid"
$result = 'UNSET'
try {
    $client = [System.IO.Pipes.NamedPipeClientStream]::new(
        '.', $pipeName, [System.IO.Pipes.PipeDirection]::InOut,
        [System.IO.Pipes.PipeOptions]::None)
    try {
        $client.Connect(2500)
        $result = if ($client.IsConnected) { 'CONNECTED' } else { 'NOT_CONNECTED' }
    }
    finally {
        $client.Dispose()
    }
}
catch {
    $baseError = $_.Exception.GetBaseException()
    $result = "DENIED_OR_FAILED:$($baseError.GetType().Name):$($baseError.HResult)"
}
Set-Content -LiteralPath $ResultPath -Value $result -NoNewline
