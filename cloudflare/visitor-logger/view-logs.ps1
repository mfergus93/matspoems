param (
    [int]$Limit = 100,
    [string]$IpAddress = ""
)

$SecretPath = Join-Path $PSScriptRoot "visitor-log-token.secret.clixml"

if (-not (Test-Path $SecretPath)) {
    Write-Host "Token file not found. Creating new token file..." -ForegroundColor Yellow
    $PlainToken = Read-Host -Prompt "Enter LOG_API_TOKEN secret" -AsSecureString
    $PlainToken | Export-Clixml -Path $SecretPath
}

$SecureToken = Import-Clixml -Path $SecretPath
$BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureToken)
$Token = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)

$Url = "https://matspoems.com/_visitor-logs?limit=$Limit"
if ($IpAddress) {
    $Url += "&ip=$IpAddress"
}

$Headers = @{
    "Authorization" = "Bearer $Token"
}

try {
    $Response = Invoke-RestMethod -Uri $Url -Headers $Headers -Method Get
    $Response.visits | Format-Table -Property visited_at, ip_address, city, region, postal_code, country, path, user_agent -AutoSize
} catch {
    Write-Error "Failed to fetch logs: $_"
}
