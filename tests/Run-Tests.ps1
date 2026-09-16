#Requires -Version 5.1
#Requires -RunAsAdministrator
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0
$root = Split-Path $PSScriptRoot -Parent
$count = 0
function Assert-True {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) { throw "FAILED: $Message" }
    $script:count++
    Write-Host "PASS: $Message"
}
foreach ($file in Get-ChildItem $root -Recurse -Include *.ps1, *.psm1) {
    $tokens = $null; $parseErrors = $null
    $null = [System.Management.Automation.Language.Parser]::ParseFile($file.FullName, [ref]$tokens, [ref]$parseErrors)
    Assert-True ($parseErrors.Count -eq 0) "Parse $($file.Name): $parseErrors"
}
Import-Module (Join-Path $root 'src/Preflight.psm1') -Force
Initialize-Probe
foreach ($cloud in @('US-1','US-2','EU-1')) {
    $targets = @(Get-PreflightTargets -Cloud $cloud)
    Assert-True ($targets.Count -eq 3 -and @($targets | Where-Object { -not $_.Required }).Count -eq 0) "$cloud sensor targets"
}
$us3 = @(Get-PreflightTargets -Cloud US-3)
Assert-True (($us3.Hostname -join ',') -eq 'ts01.us-3.cloudsink.net,lfodown01.us-3.cloudsink.net') 'US-3 uses explicit dot-separated public baseline endpoints'
Assert-True (@($us3 | Where-Object { -not $_.Required }).Count -eq 0) 'US-3 baseline endpoints are required'
$us3Console = @(Get-PreflightTargets -Cloud US-3 -IncludeConsole)
Assert-True ($us3Console.Count -eq 4 -and @($us3Console | Where-Object { -not $_.Required }).Count -eq 2 -and $us3Console.Hostname -contains 'api.us-3.crowdstrike.com' -and $us3Console.Hostname -contains 'falcon.us-3.crowdstrike.com') 'US-3 optional console/API targets'
$us3Additional = @(Get-PreflightTargets -Cloud US-3 -AdditionalHost 'tenant-endpoint.example.com')
Assert-True ($us3Additional.Count -eq 3 -and $us3Additional[2].Required) 'US-3 supports required tenant-specific endpoints'
$entryAst = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $root 'Test-CrowdStrikeConnection.ps1'), [ref]$null, [ref]$null)
$cloudParameter = $entryAst.ParamBlock.Parameters | Where-Object { $_.Name.VariablePath.UserPath -eq 'Cloud' }
$cloudValues = $cloudParameter.Attributes | Where-Object { $_.TypeName.Name -eq 'ValidateSet' }
Assert-True (@($cloudValues.PositionalArguments | ForEach-Object { $_.Value }) -contains 'US-3') 'CLI accepts US-3'
$extra = @(Get-PreflightTargets -Cloud US-2 -IncludeConsole -AdditionalHost 'example.com')
Assert-True ($extra.Count -eq 6 -and @($extra | Where-Object { -not $_.Required }).Count -eq 2) 'Optional console/API and required additional target'
foreach ($name in @('https://example.com', '*.example.com', 'example.com:443', 'bad.example.com/path', "bad.example.com`r`nInjected")) {
    $rejected = $false
    try { $null = Get-PreflightTargets -Cloud US-1 -AdditionalHost $name } catch { $rejected = $true }
    Assert-True $rejected "Reject invalid hostname: $($name.Replace("`r",'').Replace("`n",''))"
}
Assert-True ((Get-EndpointStatus @([pscustomobject]@{Success=$true},[pscustomobject]@{Success=$false})) -eq 'WARN') 'Mixed IPv4/IPv6 results are warnings'
Assert-True ((Get-EndpointStatus @([pscustomobject]@{Success=$false})) -eq 'FAIL') 'No working address fails'
Assert-True ((Get-PreflightExitCode @([pscustomobject]@{Required=$true;Status='PASS'})) -eq 0) 'All pass exit code'
Assert-True ((Get-PreflightExitCode @([pscustomobject]@{Required=$true;Status='FAIL'})) -eq 1) 'Required failure exit code'
Assert-True ((Get-PreflightExitCode @([pscustomobject]@{Required=$false;Status='FAIL'})) -eq 2) 'Optional failure exit code'
Assert-True ((Get-PreflightExitCode @([pscustomobject]@{Required=$true;Status='WARN'})) -eq 2) 'Partial connectivity exit code'
Add-Type -Path (Join-Path $PSScriptRoot 'TestServer.cs')
$loopback = [Net.IPAddress]::Loopback
$server = New-Object PreflightTestServer -ArgumentList $null, 'proxy407'
try {
    $result = [FalconPreflight.NetworkProbe]::Test('localhost', 443, $loopback, [uri]("http://localhost:{0}" -f $server.Port), 2000, $false)
    Assert-True (-not $result.Success -and $result.Stage -eq 'ProxyCONNECT' -and $result.Error -match '407') 'Proxy authentication rejection is a failure'
} finally { $server.Dispose() }
$server = New-Object PreflightTestServer -ArgumentList $null, 'silent'
try {
    $result = [FalconPreflight.NetworkProbe]::Test('localhost', $server.Port, $loopback, $null, 250, $false)
    Assert-True (-not $result.Success -and $result.Stage -eq 'TLS' -and $result.ElapsedMs -lt 4000) 'Silent TLS server times out'
} finally { $server.Dispose() }
# Create a disposable localhost certificate. Only tests modify certificate stores; the machine root store avoids interactive trust prompts.
$certificate = New-SelfSignedCertificate -DnsName 'localhost' -CertStoreLocation 'Cert:\CurrentUser\My' -NotAfter (Get-Date).AddDays(1)
$store = New-Object Security.Cryptography.X509Certificates.X509Store 'Root', 'LocalMachine'
try {
    $server = New-Object PreflightTestServer -ArgumentList $certificate, 'tls'
    try {
        $result = [FalconPreflight.NetworkProbe]::Test('localhost', $server.Port, $loopback, $null, 5000, $false)
        Assert-True (-not $result.Success -and $result.CertificateErrors -match 'RemoteCertificateChainErrors') 'Untrusted certificate is rejected'
    } finally { $server.Dispose() }
    $store.Open([Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
    $store.Add($certificate)
    foreach ($mode in @('tls','proxy200')) {
        $server = New-Object PreflightTestServer -ArgumentList $certificate, $mode
        try {
            $proxy = if ($mode -eq 'proxy200') { [uri]("http://localhost:{0}" -f $server.Port) } else { $null }
            $result = [FalconPreflight.NetworkProbe]::Test('localhost', $server.Port, $loopback, $proxy, 5000, $false)
            Assert-True ($result.Success -and $result.Protocol -eq 'Tls12' -and $result.Issuer) "Trusted TLS 1.2 over $mode"
            $roundTrip = $result | ConvertTo-Json -Depth 6 | ConvertFrom-Json
            Assert-True ($roundTrip.Success -and $roundTrip.Thumbprint) 'Certificate evidence survives JSON export'
        } finally { $server.Dispose() }
    }
    $server = New-Object PreflightTestServer -ArgumentList $certificate, 'tls'
    try {
        $result = [FalconPreflight.NetworkProbe]::Test('wrong.example.com', $server.Port, $loopback, $null, 5000, $false)
        Assert-True (-not $result.Success -and $result.CertificateErrors -match 'RemoteCertificateNameMismatch') 'Wrong hostname is rejected even with a trusted certificate'
    } finally { $server.Dispose() }
} finally {
    try { $store.Remove($certificate) } catch { Write-Warning $_.Exception.Message }
    $store.Close()
    Remove-Item -LiteralPath "Cert:\CurrentUser\My\$($certificate.Thumbprint)" -Force
}
Write-Host "$count checks passed on PowerShell $($PSVersionTable.PSVersion)."
