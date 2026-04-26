param(
  [Parameter(Mandatory=$true)][string]$TargetIp,
  [int]$Port = 8000,
  [switch]$Medium,
  [switch]$High
)

$ErrorActionPreference = "Stop"

function Test-PrivateIPv4 {
  param([string]$Ip)
  if ($Ip -match "^10\.") { return $true }
  if ($Ip -match "^192\.168\.") { return $true }
  if ($Ip -match "^172\.(1[6-9]|2[0-9]|3[0-1])\.") { return $true }
  if ($Ip -eq "127.0.0.1") { return $true }
  return $false
}

if (-not (Test-PrivateIPv4 -Ip $TargetIp)) {
  throw "Refusing to run: target must be local/private IP (127.x, 10.x, 172.16-31.x, 192.168.x)."
}

$baseUrl = "http://$TargetIp`:$Port"

try {
  Invoke-RestMethod -Method Get -Uri "$baseUrl/health" -TimeoutSec 4 | Out-Null
} catch {
  throw "Backend health check failed at $baseUrl/health. Start backend first."
}

$rate = 30
$burstSeconds = 10
$rounds = 1

if ($Medium) {
  $rate = 45
  $burstSeconds = 15
}

if ($High) {
  $rate = 60
  $burstSeconds = 20
}

Write-Host "[SAFE TEST] Target: $baseUrl" -ForegroundColor Cyan
Write-Host "[SAFE TEST] Profile: rate=$rate/s burst=$burstSeconds s rounds=$rounds" -ForegroundColor Cyan
Write-Host "[SAFE TEST] Close heavy apps and stop immediately if system becomes unstable." -ForegroundColor Yellow

python .\burst_traffic.py `
  --target $TargetIp `
  --port $Port `
  --rounds $rounds `
  --burst-seconds $burstSeconds `
  --cooldown-seconds 15 `
  --workers 20 `
  --endpoint-paths "/health,/events?limit=20" `
  --request-rate $rate `
  --jitter-ms 6

Write-Host "[SAFE TEST] Complete. Check dashboard metrics/events." -ForegroundColor Green
