<# 
.SYNOPSIS
    Install Knox Suite on Windows

.DESCRIPTION
    Downloads and installs the latest Knox Suite release for Windows

.USAGE
    PowerShell -ExecutionPolicy Bypass -c "irm https://raw.githubusercontent.com/yourusername/knox-suite/main/scripts/install.ps1 | iex"
#>

$ErrorActionPreference = "Stop"

$Repo = "yourusername/knox-suite"
$Binary = "knox.exe"
$InstallDir = "$env:USERPROFILE\scoop\shims"  # or add to PATH manually

# Get latest release
Write-Host "Fetching latest release..." -ForegroundColor Cyan
$Latest = (Invoke-RestMethod "https://api.github.com/repos/$Repo/releases/latest").tag_name
if (-not $Latest) {
    Write-Error "Failed to get latest release"
    exit 1
}

Write-Host "Latest version: $Latest" -ForegroundColor Green

# Download
$Archive = "${Binary}-${Latest}-windows-amd64.zip"
$DownloadUrl = "https://github.com/$Repo/releases/download/$Latest/$Archive"
$TempPath = "$env:TEMP\$Archive"

Write-Host "Downloading $DownloadUrl..." -ForegroundColor Cyan
Invoke-WebRequest -Uri $DownloadUrl -OutFile $TempPath

# Extract
Write-Host "Extracting..." -ForegroundColor Cyan
Expand-Archive -Path $TempPath -DestinationPath "$env:TEMP\knox-suite" -Force

# Install
$BinaryPath = "$env:TEMP\knox-suite\$Binary"
if (Test-Path $BinaryPath) {
    # Add to user PATH
    $UserPath = [Environment]::GetEnvironmentVariable("Path", "User")
    $InstallPath = "$env:USERPROFILE\.knox\bin"
    New-Item -ItemType Directory -Force -Path $InstallPath | Out-Null
    Move-Item -Path $BinaryPath -Destination "$InstallPath\$Binary" -Force
    
    if ($UserPath -notlike "*$InstallPath*") {
        [Environment]::SetEnvironmentVariable("Path", "$UserPath;$InstallPath", "User")
        Write-Host "Added $InstallPath to user PATH" -ForegroundColor Green
        Write-Host "Restart your terminal or run: \$env:PATH += ';$InstallPath'" -ForegroundColor Yellow
    }
    
    Write-Host "`n✅ $Binary installed successfully!" -ForegroundColor Green
    Write-Host "Run: $Binary --help" -ForegroundColor Cyan
} else {
    Write-Error "Binary not found after extraction"
    exit 1
}

# Cleanup
Remove-Item -Path $TempPath -Force
Remove-Item -Path "$env:TEMP\knox-suite" -Recurse -Force

# Check for security tools
Write-Host "`nChecking for security tools..." -ForegroundColor Cyan
$Tools = @("nmap", "nuclei", "subfinder", "httpx", "dnsx", "sslscan", "whatweb", "nikto", "dirsearch", "ffuf", "katana", "gau", "waybackurls", "amass")
$Missing = @()

foreach ($tool in $Tools) {
    if (-not (Get-Command $tool -ErrorAction SilentlyContinue)) {
        $Missing += $tool
    }
}

if ($Missing.Count -gt 0) {
    Write-Warning "Missing tools: $($Missing -join ', ')"
    Write-Host "Install with Scoop:" -ForegroundColor Yellow
    Write-Host "  scoop install $($Missing -join ' ')" -ForegroundColor Cyan
    Write-Host "Or Chocolatey:" -ForegroundColor Yellow
    Write-Host "  choco install $($Missing -join ' ')" -ForegroundColor Cyan
} else {
    Write-Host "✅ All security tools found!" -ForegroundColor Green
}