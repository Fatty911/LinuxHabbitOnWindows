# =============================================================================
# Module: LinuxHabbitOnWindows
# Description: Map Linux commands to Windows Native Resources
# Author: YourName
# =============================================================================

# 1. 端口占用查看 (lsof)
function lsof {
    <#
    .SYNOPSIS
        模拟 Linux lsof 命令查看端口占用
    .EXAMPLE
        lsof -i :8080
        lsof -i 8080
    #>
    param([Parameter(ValueFromRemainingArguments=$true)]$ArgsList)
    
    $inputString = $ArgsList -join " "
    if ($inputString -match '(\d+)') {
        $port = $matches[1]
    } else {
        Write-Host "Usage: lsof -i :3333 or lsof 3333" -ForegroundColor Yellow
        return
    }

    $connections = Get-NetTCPConnection -LocalPort $port -ErrorAction SilentlyContinue 
    
    if (-not $connections) {
        Write-Host "No process is listening on port $port" -ForegroundColor Gray
        return
    }

    $connections | ForEach-Object {
        $connection = $_
        $proc = Get-Process -Id $connection.OwningProcess -ErrorAction SilentlyContinue
        
        [PSCustomObject]@{
            COMMAND = if ($proc) { $proc.ProcessName } else { "Unknown" }
            PID     = $connection.OwningProcess
            USER    = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
            TYPE    = if ($connection.LocalAddress.AddressFamily -eq 'InterNetwork') { "IPv4" } else { "IPv6" }
            NODE    = $connection.State
            NAME    = "$($connection.LocalAddress):$($connection.LocalPort)"
        }
    } | Format-Table -AutoSize
}

# 2. 内存查看 (free)
function free {
    param([string]$h) # 兼容 -h 参数
    
    $os = Get-CimInstance Win32_OperatingSystem
    $total = $os.TotalVisibleMemorySize / 1KB
    $free = $os.FreePhysicalMemory / 1KB
    $used = $total - $free
    
    Write-Host "              total        used        free"
    Write-Host "Mem:    $("{0,10:N0}" -f $total)  $("{0,10:N0}" -f $used)  $("{0,10:N0}" -f $free) (MB)" -ForegroundColor Green
}

# 3. 防火墙 (ufw) -> 映射 Windows Defender Firewall
function ufw {
    param(
        [string]$Action,
        [string]$Port
    )

    if ($Action -eq "status") {
        Write-Host "Status: active (Listing top 10 inbound rules)" -ForegroundColor Cyan
        Get-NetFirewallRule | Where-Object { $_.Enabled -eq 'True' -and $_.Direction -eq 'Inbound' } | 
        Select-Object DisplayName, Action, Profile | Select-Object -First 10 | Format-Table -AutoSize
    }
    elseif ($Action -eq "allow" -and $Port) {
        if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
            Write-Warning "Permission Denied: Please run terminal as Administrator to change firewall rules."
            return
        }
        New-NetFirewallRule -DisplayName "UFW_Allow_$Port" -Direction Inbound -LocalPort $Port -Protocol TCP -Action Allow | Out-Null
        Write-Host "Rule added: Allow $Port (TCP)" -ForegroundColor Green
    }
    else {
        Write-Host "Usage: ufw status | ufw allow <port>" -ForegroundColor Yellow
    }
}

# 4. 服务管理 (systemctl) -> 映射 Windows Services
function systemctl {
    param(
        [string]$Action,
        [string]$ServiceName
    )

    switch ($Action) {
        "status" { Get-Service -Name $ServiceName }
        "start"  { Start-Service -Name $ServiceName; Write-Host "Service $ServiceName started." -ForegroundColor Green }
        "stop"   { Stop-Service -Name $ServiceName; Write-Host "Service $ServiceName stopped." -ForegroundColor Red }
        "restart"{ Restart-Service -Name $ServiceName; Write-Host "Service $ServiceName restarted." -ForegroundColor Yellow }
        Default  { Write-Host "Usage: systemctl [status|start|stop|restart] <service_name>" -ForegroundColor Yellow }
    }
}

# 5. 进程查杀 (pkill / killall)
function pkill {
    param([string]$Name)
    if (-not $Name) { Write-Error "Usage: pkill <process_name>"; return }
    Stop-Process -Name $Name -Force -ErrorAction SilentlyContinue
    Write-Host "Sent kill signal to process: $Name" -ForegroundColor Red
}

# 6. 文件搜索 (grep) -> 映射 Select-String
Set-Alias -Name grep -Value Select-String -Scope Global -ErrorAction SilentlyContinue

# 7. 提权 (sudo) -> 简单检测 gsudo，如果没有则提示
function sudo {
    param([Parameter(ValueFromRemainingArguments=$true)]$ArgsList)
    if (Get-Command "gsudo" -ErrorAction SilentlyContinue) {
        gsudo $ArgsList
    } else {
        Write-Host "Error: 'gsudo' is not installed. Please install it via: winget install gsudo" -ForegroundColor Red
        Write-Host "Fallback: Attempting to run as standard command..." -ForegroundColor DarkGray
        & $ArgsList
    }
}

# 8. 创建文件 (touch)
function touch {
    param([string]$Path)
    if (Test-Path $Path) {
        (Get-Item $Path).LastWriteTime = Get-Date
    } else {
        New-Item -ItemType File -Path $Path -Force | Out-Null
    }
}

# 导出函数供外部调用
Export-ModuleMember -Function lsof, free, ufw, systemctl, pkill, sudo, touch
Export-ModuleMember -Alias grep
