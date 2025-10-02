
# ----------------------------------------------------------------------
# Disables defender's ability to start its 'threat service' component
# Must be run from a system booted in safe mode.
# ----------------------------------------------------------------------

function New-Dir {
    param([string]$newDir)
    
    if (!(Test-Path -Path $newDir)) { 
        New-Item -Type Directory -Path $newDir
    }
}

function Override-Platform-ACLs {
    param ([string]$backupPath)
    
    $target = "C:\ProgramData\Microsoft\Windows Defender\Platform"    
    
    $acl = Get-Acl -Path $target
    $acl.Owner, $acl.Access | Out-File -FilePath "$backupPath\PlatformACLBackup.txt"
    
    $newOwner = "BUILTIN\Administrators"
    $idents = @(
        "NT SERVICE\TrustedInstaller"
        "NT AUTHORITY\SYSTEM"
    )
    
    $owner = New-Object System.Security.Principal.NTAccount($newOwner)
    $acl.SetAccessRuleProtection($true, $false)
    
    foreach ($i in $idents) {
        $match = $acl.Access | Where-Object { $_.IdentityReference -eq $i }
        foreach ($m in $match) {
            $acl.RemoveAccessRule($m)
        }
    }

    $acl.SetOwner($owner)
    $argList = $newOwner,"FullControl","Allow"
    $fsAccessRuleParams = @{
        TypeName = 'System.Security.AccessControl.FileSystemAccessRule'
        ArgumentList = $argList
    }
    $fsAccessRule = New-Object @fsAccessRuleParams
    $acl.SetAccessRule($fsAccessRule)

    Set-Acl -Path $target -AclObject $acl
    Get-Acl $target
}

function Disable-Wd-Startup {
    param ([string]$backupPath)
    
    $backupParentDir = "$backupPath\reg"
    New-Dir $backupParentDir

    $key = "Start"
    $val = 4
    $targets = @(
        "Sense"
        "WdBoot"
        "WdFilter"
        "WdNisDrv"
        "WdNisSvc"
        "WinDefend"
    )
        
    $servicesPath = "HKLM\SYSTEM\CurrentControlSet\Services"

    foreach($t in $targets) {
        $path = "$servicesPath\$t"
        REG EXPORT "$path" "$backupParentDir\$t-backup.reg"
        Set-ItemProperty -Path $path -Name $key -Value $val
    }
}

$backupDir = "$env:USERPROFILE\Desktop\windef-backups"
New-Dir $backupDir

Override-Platform-ACLs $backupDir
Disable-Wd-Startup $backupDir
