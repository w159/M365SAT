# Benchmark: CIS Microsoft Azure v3.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

# Call the OutPath Variable here
$path = @($OutPath)

function Build-CISAz338
{
    param(
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )

    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISAz338"
        ID               = "3.3.8"
        Title            = "(L2) Ensure Automatic Key Rotation is Enabled Within Azure Key Vault for the Supported Services"
        ProductFamily    = "Microsoft Azure"
        DefaultValue     = "By default, Automatic Key Rotation is not enabled."
        ExpectedValue    = "Automatic Key Rotation is enabled."
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "Once set up, Automatic Private Key Rotation removes the need for manual administration when keys expire at intervals determined by your organization's policy. The recommended key lifetime is 2 years. Your organization should determine its own key expiration policy."
        Impact           = "There are an additional costs per operation in running the needed applications."
        Remediation      = 'Use the PowerShell Script to remediate the issue: Set-AzKeyVaultKeyRotationPolicy -VaultName test-kv -Name test-key -PolicyPath rotation_policy.json'
        References       = @(
            @{ 'Name' = 'Configure cryptographic key auto-rotation in Azure Key Vault'; 'URL' = 'https://learn.microsoft.com/en-us/azure/key-vault/keys/how-to-configure-key-rotation' },
            @{ 'Name' = 'Update the key version'; 'URL' = 'https://learn.microsoft.com/en-us/azure/storage/common/customer-managed-keys-overview#update-the-key-version' },
            @{ 'Name' = 'Set up an Azure Key Vault and DiskEncryptionSet optionally with automatic key rotation'; 'URL' = 'https://learn.microsoft.com/en-us/azure/virtual-machines/windows/disks-enable-customer-managed-keys-powershell#set-up-an-azure-key-vault-and-diskencryptionset-optionally-with-automatic-key-rotation' },
            @{ 'Name' = 'Public preview: Automatic key rotation of customer-managed keys for encrypting Azure managed disks'; 'URL' = 'https://learn.microsoft.com/en-us/azure/key-vault/keys/how-to-configure-key-rotation' },
            @{ 'Name' = 'DP-6: Use a secure key management process'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-data-protection#dp-6-use-a-secure-key-management-process' }
        )
    }
    return $inspectorobject
}

# Audit Script
function Audit-CISAz338
{
    try
    {
        $Violation = @()
        $AzKeyVaults = Get-AzKeyVault -ErrorAction SilentlyContinue
        foreach ($AzKeyVault in $AzKeyVaults){
            $AzKeys = Get-AzKeyVaultKey -VaultName $AzKeyVault.VaultName -ErrorAction SilentlyContinue
            foreach ($AzKey in $AzKeys){
                $RotationPolicy = Get-AzKeyVaultKeyRotationPolicy -VaultName $AzKeyVault.VaultName -Name $AzKey.Name -ErrorAction SilentlyContinue
                if ([string]::IsNullOrEmpty($RotationPolicy)){
                    $Violation += $AzKeyVault.VaultName
                }
            }
        }

        if ($Violation.count -gt 0)
        {
            $finalobject = Build-CISAz338 -ReturnedValue ($Violation) -Status "FAIL" -RiskScore "0" -RiskRating "Informational"
            return $finalobject
        }
        else
        {
            $finalobject = Build-CISAz338 -ReturnedValue "No violations found" -Status "PASS" -RiskScore "0" -RiskRating "None"
            return $finalobject
        }

        return $null
    }
    catch
    {
        $endobject = Build-CISAz338 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
        Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
        Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
        return $endobject
    }
}

return Audit-CISAz338
