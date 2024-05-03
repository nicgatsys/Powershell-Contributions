I've been looking for scripts for this for some time and found a few that did not work in practice but looked functionally correct
I've appended the script I got working in case it helps any one else reading - hope you got yours working OP and hope this helps if you haven't already.
#	FVE - Set GP Settings for Bitlocker key backup via Powershell
# The following settings are what get affected by the Group Policy that enables Bitlocker key backup to A/AD
#The last segment of this script tries to run gpupdate before backing up the bitlocker key to local AD - both of which it can only do if connected to VPN or local domain network
#in my environment the settings below are applied to everyone via GP but there are many users who work remotely so I applied this to make this backup functional
New-Item "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -force -ea SilentlyContinue
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Policies\Microsoft\FVE' -Name 'ActiveDirectoryBackup' -Value '1' -PropertyType dword -Force -ea SilentlyContinue;
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Policies\Microsoft\FVE' -Name 'RequireActiveDirectoryBackup' -Value '1' -PropertyType dword -Force -ea SilentlyContinue;
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Policies\Microsoft\FVE' -Name 'ActiveDirectoryInfoToStore' -Value '1' -PropertyType dword -Force -ea SilentlyContinue;
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Policies\Microsoft\FVE' -Name 'OSRecovery' -Value '1' -PropertyType dword -Force -ea SilentlyContinue;
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Policies\Microsoft\FVE' -Name 'OSManageDRA' -Value '1' -PropertyType dword -Force -ea SilentlyContinue;
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Policies\Microsoft\FVE' -Name 'OSRecoveryPassword' -Value '2' -PropertyType dword -Force -ea SilentlyContinue;
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Policies\Microsoft\FVE' -Name 'OSRecoveryKey' -Value '2' -PropertyType dword -Force -ea SilentlyContinue;
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Policies\Microsoft\FVE' -Name 'OSHideRecoveryPage' -Value '0' -PropertyType dword -Force -ea SilentlyContinue;
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Policies\Microsoft\FVE' -Name 'OSActiveDirectoryBackup' -Value '1' -PropertyType dword -Force -ea SilentlyContinue;
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Policies\Microsoft\FVE' -Name 'OSActiveDirectoryInfoToStore' -Value '1' -PropertyType dword -Force -ea SilentlyContinue;
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Policies\Microsoft\FVE' -Name 'OSRequireActiveDirectoryBackup' -Value '1' -PropertyType dword -Force -ea SilentlyContinue;
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Policies\Microsoft\FVE' -Name 'FDVRecovery' -Value '1' -PropertyType dword -Force -ea SilentlyContinue;
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Policies\Microsoft\FVE' -Name 'FDVRecoveryPassword' -Value '0' -PropertyType dword -Force -ea SilentlyContinue;
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Policies\Microsoft\FVE' -Name 'FDVRecoveryKey' -Value '2' -PropertyType dword -Force -ea SilentlyContinue;
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Policies\Microsoft\FVE' -Name 'FDVManageDRA' -Value '1' -PropertyType dword -Force -ea SilentlyContinue;
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Policies\Microsoft\FVE' -Name 'FDVHideRecoveryPage' -Value '0' -PropertyType dword -Force -ea SilentlyContinue;
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Policies\Microsoft\FVE' -Name 'FDVActiveDirectoryBackup' -Value '0' -PropertyType dword -Force -ea SilentlyContinue;
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Policies\Microsoft\FVE' -Name 'FDVRequireActiveDirectoryBackup' -Value '0' -PropertyType dword -Force -ea SilentlyContinue;
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Policies\Microsoft\FVE' -Name 'FDVActiveDirectoryInfoToStore' -Value '1' -PropertyType dword -Force -ea SilentlyContinue;

timeout 2

#	Bitlocker key - store in AzureAD

$DriveLetter = $env:SystemDrive
function Test-Bitlocker ($BitlockerDrive) {
    try {
        Get-BitLockerVolume -MountPoint $BitlockerDrive -ErrorAction Stop
    } catch {
        Write-Output "Bitlocker was not found protecting the $BitlockerDrive drive. Terminating script!"
        exit 0
    }
}
function Get-KeyProtectorId ($BitlockerDrive) {
    $BitLockerVolume = Get-BitLockerVolume -MountPoint $BitlockerDrive
    $KeyProtector = $BitLockerVolume.KeyProtector | Where-Object { $_.KeyProtectorType -eq 'RecoveryPassword' }
    return $KeyProtector.KeyProtectorId
}
function Invoke-BitlockerEscrow ($BitlockerDrive,$BitlockerKey) {
    foreach ($Key in $BitlockerKey) {
        try {
            BackupToAAD-BitLockerKeyProtector -MountPoint $BitlockerDrive -KeyProtectorId "$Key" #-ErrorAction SilentlyContinue
            Write-Output "Attempted to escrow key in Azure AD - Please verify manually!"
        } catch {
            Write-Error "This should never have happend? Debug me!"
            exit 1
        }
    }
    exit 0
}

Test-Bitlocker -BitlockerDrive $DriveLetter
$KeyProtectorId = Get-KeyProtectorId -BitlockerDrive $DriveLetter
Invoke-BitlockerEscrow -BitlockerDrive $DriveLetter -BitlockerKey $KeyProtectorId


#	Bitlocker key - store in local AD

gpupdate 
$keyID = Get-BitLockerVolume -MountPoint c: | select -ExpandProperty keyprotector | where {$_.KeyProtectorType -eq 'RecoveryPassword'}
Backup-BitLockerKeyProtector -MountPoint c: -KeyProtectorId $keyID.KeyProtectorId