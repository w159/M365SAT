# Benchmark: CIS Microsoft 365 v4.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISAz613
{
    param (
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )

    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISAz613"
        ID               = "6.1.3"
        Title            = "(L2) Ensure the storage account containing the container with activity logs is encrypted with Customer Managed Key (CMK)"
        ProductFamily    = "Microsoft Azure"
        DefaultValue     = "KeySource: Microsoft.Storage"
        ExpectedValue    = "KeySource: Microsoft.Keyvault"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "Configuring the storage account with the activity log export container to use CMKs provides additional confidentiality controls on log data, as a given user must have read permission on the corresponding storage account and must be granted decrypt permission by the CMK."
        Impact           = "You must have your key vault setup to utilize this. All Audit Logs will be encrypted with a key you provide. You will need to set up customer managed keys separately, and you will select which key to use via the instructions here. You will be responsible for the lifecycle of the keys, and will need to manually replace them at your own determined intervals to keep the data secure."
        Remediation      = "Use the following PowerShell command to remediate the issue: Set-AzStorageAccount -ResourceGroupName <ResourceGroupName> -Name <StorageAccountName> -IdentityType SystemAssigned -KeySource Microsoft.Keyvault"
        References       = @(
            @{ 'Name' = 'DP-5: Use customer-managed key option in data at rest encryption when required'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-data-protection#dp-5-use-customer-managed-key-option-in-data-at-rest-encryption-when-required' },
            @{ 'Name' = 'Managing legacy log profiles'; 'URL' = 'https://learn.microsoft.com/en-us/azure/azure-monitor/essentials/activity-log?tabs=cli#managing-legacy-log-profiles' }
        )
    }

    return $inspectorobject
}


function Audit-CISAz613
{
    try
    {
        # Subscription-Based Checking
        $Violation = @()
        $SubscriptionId = Get-AzContext
        $StorageAccounts = Get-AzStorageAccount

        foreach ($StorageAccount in $StorageAccounts)
        {
            if ([string]::IsNullOrEmpty($StorageAccount.Encryption.KeyVaultProperties) -or $StorageAccount.Encryption.KeySource -eq "Microsoft.Storage")
            {
                $Violation += $StorageAccount.Name
            }
        }

        if ($Violation.Count -gt 0)
        {
            $FinalObject = Build-CISAz613 -ReturnedValue $Violation -Status "FAIL" -RiskScore "2" -RiskRating "Low"
            return $FinalObject
        }
        else
        {
            $FinalObject = Build-CISAz613 -ReturnedValue "No violations found" -Status "PASS" -RiskScore "0" -RiskRating "None"
            return $FinalObject
        }

        return $null
    }
    catch
    {
        $EndObject = Build-CISAz613 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
        Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
        Write-ErrorLog 'An error occurred on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
        return $EndObject
    }
}

return Audit-CISAz613
