# =============================================================================
# Installer for LinuxHabbitOnWindows
# =============================================================================

$ErrorActionPreference = "Stop"

# 1. 定义安装路径 (~/.linux_habbit)
$InstallDir = Join-Path $HOME ".linux_habbit"
$ModuleFile = Join-Path $InstallDir "LinuxHabbit.psm1"
$SourceUrl  = "https://raw.githubusercontent.com/Fatty911/LinuxHabbitOnWindows/main/src/LinuxHabbit.psm1"

Write-Host "`n🚀 Installing Linux Habbit on Windows..." -ForegroundColor Cyan

# 2. 创建目录
if (-not (Test-Path $InstallDir)) {
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
}

# 3. 下载模块文件 (如果是本地测试，直接复制；如果是远程安装，使用 Invoke-WebRequest)
# 这里假设用户从本地运行 install.ps1，或者你之后把这个推送到 GitHub
# 为了演示，我们假设脚本和 src 文件夹在同一级
$LocalSource = Join-Path $PSScriptRoot "src\LinuxHabbit.psm1"

if (Test-Path $LocalSource) {
    Copy-Item -Path $LocalSource -Destination $ModuleFile -Force
    Write-Host "✅ Module files copied to $InstallDir" -ForegroundColor Green
} else {
    # 既然是 GitHub 项目，用户可能直接下载 install.ps1 运行，这里预留网络下载逻辑
    try {
        Write-Host "⬇️  Downloading module from GitHub..." -ForegroundColor Yellow
        Invoke-WebRequest -Uri $SourceUrl -OutFile $ModuleFile
        Write-Host "✅ Download complete." -ForegroundColor Green
    } catch {
        Write-Error "Failed to download module. Please clone the repo and run install.ps1 locally."
    }
}

# 4. 配置 PowerShell Profile
$ProfilePath = $PROFILE
if (-not (Test-Path $ProfilePath)) {
    New-Item -ItemType File -Path $ProfilePath -Force | Out-Null
}

$ImportLine = "`n# Added by LinuxHabbitOnWindows`nImport-Module `"$ModuleFile`" -Force"
$CurrentContent = Get-Content $ProfilePath -Raw -ErrorAction SilentlyContinue

if ($CurrentContent -notmatch "LinuxHabbit.psm1") {
    Add-Content -Path $ProfilePath -Value $ImportLine
    Write-Host "✅ Added to PowerShell Profile ($ProfilePath)" -ForegroundColor Green
} else {
    Write-Host "ℹ️  Already installed in Profile." -ForegroundColor Gray
}

# 5. 刷新环境变量/提示
Write-Host "`n🎉 Installation Complete!" -ForegroundColor Cyan
Write-Host "👉 Please restart your terminal or run: . `$PROFILE" -ForegroundColor Yellow
