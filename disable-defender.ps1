# ----------------------------------------------------------------------
# Disables defender's ability to start its 'threat service' component
# Must be run from a system booted in safe mode.
# ----------------------------------------------------------------------

# removes SYSTEM and TrustedInstaller permissions from 
# defender's `Platform` directory; replaces them with the system's
# `BUILTIN\Administrators` user
function SetPlatformPermissions {
    $target = "C:\ProgramData\Microsoft\Windows Defender\Platform"    
    $idents = @(
        "NT SERVICE\TrustedInstaller"
        "NT AUTHORITY\SYSTEM"
    )

    $acl = Get-Acl -Path $target
    
    # backup the original ruleset
    $acl.Owner, $acl.Access | Out-File -FilePath "$(Get-Location)\platform_acl_backup.txt"

    $replacement = "BUILTIN\Administrators"
    $owner = New-Object System.Security.Principal.NTAccount($replacement)
    $acl.SetAccessRuleProtection($true, $false)

    # remove access rule entries for the given user
    foreach ($i in $idents) {
        $matching = $acl.Access | Where-Object { $_.IdentityReference -eq $i }
        foreach ($r in $matching) {
            $acl.RemoveAccessRule($r)
        }
    }

    $acl.SetOwner($owner)
    $argList = $replacement, "FullControl", "Allow"
    $fsAccessRuleParams = @{
        TypeName = 'System.Security.AccessControl.FileSystemAccessRule'
        ArgumentList = $argList
    }
    $fsAccessRule = New-Object @fsAccessRuleParams
    $acl.SetAccessRule($fsAccessRule)

    Set-Acl -Path $target -AclObject $acl
    Get-Acl $target
}

# sets the `Start` values for defender-related startup keys to `4` (disabled) 
function SetRegistryKVs {
    $baseDir = "HKLM:\SYSTEM\CurrentControlSet\Services"

    # backup original registry K/V pairs
    $backupName = "services_backup.reg"
    REG EXPORT "HKLM\SYSTEM\CurrentControlSet\Services" "$(Get-Location)\$backupName"

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

    foreach($t in $targets) {
        $path = "$($baseDir)\$($t)"
        Set-ItemProperty -Path $path -Name $key -Value $val
    }
}

Set-Location "$env:USERPROFILE\Desktop"
New-Item -Name "defender-backups" -ItemType Directory
Set-Location ".\defender-backups"

SetPlatformPermissions
SetRegistryKVs
