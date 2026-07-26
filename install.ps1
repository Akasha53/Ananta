<#
    Installation d'Ananta sur Windows.

        .\install.ps1              # pile Docker Desktop
        .\install.ps1 -BareMetal   # environnement Python local

    Le moteur d'IA est un choix indépendant : Ollama sur ce poste, la CLI
    `claude`, une API compatible OpenAI, ou aucun. Voir docs/deployment.md.
#>
[CmdletBinding()]
param(
    [switch]$BareMetal,
    [switch]$WithOllama
)

$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

function Write-Info($m) { Write-Host "> $m" -ForegroundColor Cyan }
function Write-Ok($m)   { Write-Host "OK $m" -ForegroundColor Green }
function Write-Warn($m) { Write-Host "!  $m" -ForegroundColor Yellow }

function New-EnvFile {
    if (Test-Path ".env") { Write-Ok "Fichier .env déjà présent — conservé."; return }

    Write-Info "Génération du fichier .env"
    $bytes = New-Object byte[] 24
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
    $password = -join ($bytes | ForEach-Object { $_.ToString("x2") })
    $bootstrapBytes = New-Object byte[] 24
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bootstrapBytes)
    $bootstrapToken = -join ($bootstrapBytes | ForEach-Object { $_.ToString("x2") })

    @"
POSTGRES_USER=ananta
POSTGRES_PASSWORD=$password
POSTGRES_DB=ananta

ENVIRONMENT=production
AUTH_REQUIRED=true
ANANTA_BOOTSTRAP_TOKEN=$bootstrapToken
ANANTA_PORT=8010
CORS_ORIGINS=http://localhost:8010
TRUSTED_PROXY_IPS=127.0.0.1,::1
RATE_LIMIT_ENABLED=true
WORKER_CONCURRENCY=4
INSTALL_ML=0

# none | ollama | claude_cli | codex_cli | anthropic | openai_api | webui
LLM_PROVIDER=none
OLLAMA_HOST=
OLLAMA_MODEL=llama3.1:8b
LLM_API_URL=
LLM_API_KEY=
LLM_MODEL=
LLM_TIMEOUT=420
ANTHROPIC_API_KEY=
ANTHROPIC_MODEL=claude-sonnet-4-5

OPENSANCTIONS_API_KEY=
OPENSANCTIONS_API_URL=
COMPANIES_HOUSE_API_KEY=
OPENCORPORATES_API_KEY=
PAPPERS_API_KEY=
HIBP_API_KEY=
GITHUB_TOKEN=
SEC_EDGAR_CONTACT=
CENSYS_API_KEY=
VIRUSTOTAL_API_KEY=
SHODAN_API_KEY=
SECURITYTRAILS_API_KEY=
"@ | Set-Content -Path ".env" -Encoding UTF8

    Write-Ok "Fichier .env créé (secrets PostgreSQL et initialisation aléatoires)."
}

function Ensure-AuthConfig {
    $content = Get-Content ".env" -Raw
    $lines = @()
    if ($content -notmatch '(?m)^AUTH_REQUIRED=') { $lines += "AUTH_REQUIRED=true" }
    if ($content -notmatch '(?m)^ANANTA_BOOTSTRAP_TOKEN=.+$') {
        $bytes = New-Object byte[] 24
        [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
        $token = -join ($bytes | ForEach-Object { $_.ToString("x2") })
        if ($content -match '(?m)^ANANTA_BOOTSTRAP_TOKEN=') {
            (Get-Content ".env") -replace '^ANANTA_BOOTSTRAP_TOKEN=.*$', "ANANTA_BOOTSTRAP_TOKEN=$token" |
                Set-Content ".env"
        } else {
            $lines += "ANANTA_BOOTSTRAP_TOKEN=$token"
        }
    }
    if ($lines.Count -gt 0) {
        Add-Content -Path ".env" -Value ("`n" + ($lines -join "`n"))
        Write-Ok "Configuration d'authentification ajoutée à .env."
    }
}

if ($BareMetal) {
    if (-not (Get-Command python -ErrorAction SilentlyContinue)) { throw "Python 3.10+ est requis." }
    New-EnvFile
    Ensure-AuthConfig
    Write-Info "Création de l'environnement virtuel (.venv)"
    python -m venv .venv
    & ".\.venv\Scripts\python.exe" -m pip install --upgrade pip | Out-Null
    Write-Info "Installation des dépendances"
    & ".\.venv\Scripts\python.exe" -m pip install -r requirements-lock.txt
    & ".\.venv\Scripts\alembic.exe" upgrade head
    Write-Ok "Ananta est prêt."
    Write-Host "   API      : .\.venv\Scripts\python.exe -m uvicorn main:app --port 8010"
    Write-Host "   Interface: http://localhost:8010/web/html/entity.html"
    exit 0
}

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    throw "Docker Desktop est requis. https://docs.docker.com/desktop/install/windows-install/"
}

New-EnvFile
Ensure-AuthConfig

$composeArgs = @()
if ($WithOllama) {
    $composeArgs = @("--profile", "ollama")
    (Get-Content .env) `
        -replace '^OLLAMA_HOST=$', 'OLLAMA_HOST=http://ollama:11434' `
        -replace '^LLM_PROVIDER=none$', 'LLM_PROVIDER=ollama' |
        Set-Content .env
    Write-Ok "LLM_PROVIDER=ollama configuré."
}

Write-Info "Construction de l'image (quelques minutes la première fois)"
docker compose @composeArgs build

Write-Info "Démarrage de la pile"
docker compose @composeArgs up -d

$port = (Select-String -Path .env -Pattern '^ANANTA_PORT=(.*)$').Matches.Groups[1].Value
if (-not $port) { $port = "8010" }

Write-Info "Attente de l'API"
for ($i = 0; $i -lt 60; $i++) {
    try {
        Invoke-WebRequest -Uri "http://127.0.0.1:$port/health" -UseBasicParsing -TimeoutSec 3 | Out-Null
        Write-Ok "API opérationnelle."
        break
    } catch { Start-Sleep -Seconds 2 }
}

Write-Host ""
Write-Ok "Ananta est installé."
Write-Host "   Interface : http://localhost:$port/web/html/index.html"
Write-Host "   Entités   : http://localhost:$port/web/html/entity.html"
Write-Host "   API docs  : http://localhost:$port/docs"
Write-Host ""
Write-Host "   Premier accès : ouvrez « Accès » et utilisez ANANTA_BOOTSTRAP_TOKEN depuis .env"
Write-Host ""
Write-Host "   Moteur IA : Entités > Options > Moteur IA, ou LLM_PROVIDER dans .env"
Write-Host "   Journaux  : docker compose logs -f api worker"
