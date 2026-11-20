$ErrorActionPreference = 'Stop'
$testDir = $PSScriptRoot
$targetDll = Join-Path $testDir 'bin/Release/net11.0/Target.dll'
$dotnet = (Get-Command dotnet).Source
$nonce = [Guid]::NewGuid().ToString('N').Substring(0, 8)
$publicDir = Join-Path $env:PUBLIC "diag-pipe-$nonce"
$userName = "dprobe$nonce"
$probeScript = Join-Path $publicDir 'probe.ps1'
$probeShell = Join-Path $env:WINDIR 'System32/WindowsPowerShell/v1.0/powershell.exe'
$ownerResult = Join-Path $publicDir 'owner.txt'
$lowResult = Join-Path $publicDir 'low.txt'
$target = $null
$createdUser = $false

try {
    New-Item -ItemType Directory -Path $publicDir | Out-Null
    Copy-Item -LiteralPath (Join-Path $testDir 'probe.ps1') -Destination $probeScript

    $target = Start-Process -FilePath $dotnet -ArgumentList ('"' + $targetDll + '"') `
        -PassThru -RedirectStandardOutput (Join-Path $publicDir 'target-out.txt') `
        -RedirectStandardError (Join-Path $publicDir 'target-err.txt')

    $ownerConnected = $false
    for ($attempt = 0; $attempt -lt 25; $attempt++) {
        if ($target.HasExited) { throw 'Inert target exited before pipe probe.' }
        & $probeShell -NoProfile -ExecutionPolicy Bypass -File $probeScript `
            -TargetPid $target.Id -ResultPath $ownerResult
        if ($LASTEXITCODE -ne 0) { throw 'Owner probe setup failed.' }
        if ((Get-Content -LiteralPath $ownerResult -Raw) -eq 'CONNECTED') {
            $ownerConnected = $true
            break
        }
        Start-Sleep -Milliseconds 300
    }
    if (-not $ownerConnected) { throw 'Owner control could not connect to the default pipe.' }

    $passwordText = [Guid]::NewGuid().ToString('N') + 'aA1!'
    $password = ConvertTo-SecureString $passwordText -AsPlainText -Force
    New-LocalUser -Name $userName -Password $password -PasswordNeverExpires `
        -UserMayNotChangePassword | Out-Null
    $createdUser = $true
    & icacls.exe $publicDir /grant "$($userName):(OI)(CI)(M)" | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Could not grant probe output directory access.' }

    $credential = [pscredential]::new("$env:COMPUTERNAME\$userName", $password)
    $argumentLine = '-NoProfile -ExecutionPolicy Bypass -File "' + $probeScript + `
        '" -TargetPid ' + $target.Id + ' -ResultPath "' + $lowResult + '"'
    $probeProcess = Start-Process `
        -FilePath $probeShell `
        -ArgumentList $argumentLine -Credential $credential -WorkingDirectory $env:PUBLIC `
        -Wait -PassThru
    if ($probeProcess.ExitCode -ne 0 -or -not (Test-Path -LiteralPath $lowResult)) {
        throw "Distinct-user probe setup failed with exit code $($probeProcess.ExitCode)."
    }

    $owner = Get-Content -LiteralPath $ownerResult -Raw
    $lower = Get-Content -LiteralPath $lowResult -Raw
    $targetRuntime = Get-Content -LiteralPath (Join-Path $publicDir 'target-out.txt') -Raw
    $isAdmin = [Security.Principal.WindowsPrincipal]::new(
        [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
    Write-Output "RUNNER_ADMIN=$isAdmin"
    Write-Output "TARGET_PID=$($target.Id)"
    Write-Output "OWNER_CONNECT=$owner"
    Write-Output "DISTINCT_USER_CONNECT=$lower"
    Write-Output $targetRuntime.Trim()
}
finally {
    if ($target -and -not $target.HasExited) {
        Stop-Process -Id $target.Id -Force -ErrorAction SilentlyContinue
    }
    if ($createdUser) {
        Remove-LocalUser -Name $userName -ErrorAction SilentlyContinue
    }
    if (Test-Path -LiteralPath $publicDir) {
        Remove-Item -LiteralPath $publicDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}
