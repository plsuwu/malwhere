function Get-CurrentDir {
    Get-ChildItem -Path ${ Get-Location }
}

Set-Alias -Name "la" -Value Get-CurrentDir  
Invoke-Expression (& { (zoxide init powershell | Out-String) })

Set-Alias -Name cd -Value __zoxide_z -Option AllScope -Scope Global -Force
Set-Alias -Name cdi -Value __zoxide_zi -Option AllScope -Scope Global -Force
