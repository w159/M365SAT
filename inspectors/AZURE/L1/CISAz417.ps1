# Benchmark: CIS Microsoft 365 v4.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISAz417
{
    param(
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )

    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISAz417"
        ID               = "4.17"
        Title            = "(L1) Ensure that 'Allow Blob Anonymous Access' is set to 'Disabled'"
        ProductFamily    = "Microsoft Azure"
        DefaultValue     = "Disabled"
        ExpectedValue    = "Disabled"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "If 'Allow Blob Anonymous Access' is enabled, blobs can be accessed by adding the blob name to the URL to see the contents. An attacker can enumerate a blob using methods, such as brute force, and access them. Exfiltration of data by brute force enumeration of items from a storage account may occur if this setting is set to 'Enabled'"
        Impact           = "Additional consideration may be required for exceptional circumstances where elements of a storage account require public accessibility. In these circumstances, it is highly recommended that all data stored in the public facing storage account be reviewed for sensitive or potentially compromising data, and that sensitive or compromising data is never stored in these storage accounts."
        Remediation      = 'You can change the settings by executing the following PowerShell command: Set-AzStorageAccount -ResourceGroupName <resource group name> -Name <storage account name> -allowBlobAnonymousAccess $false'
        References       = @(
            @{ 'Name' = 'Remediate anonymous read access to blob data (Azure Resource Manager deployments)'; 'URL' = 'https://learn.microsoft.com/en-us/azure/storage/blobs/anonymous-read-access-prevent?tabs=portal' },
            @{ 'Name' = 'Remediate anonymous read access to blob data (classic deployments)'; 'URL' = 'https://learn.microsoft.com/en-us/azure/storage/blobs/anonymous-read-access-prevent-classic?tabs=portal' }
        )
    }

    return $inspectorobject
}


function Audit-CISAz417
{
    try
    {
        $Violation = @()
        $StorageAccounts = Get-AzStorageAccount

        foreach ($StorageAccount in $StorageAccounts) {
            if ($StorageAccount.AllowBlobPublicAccess -eq $true) {
                $Violation += $StorageAccount.StorageAccountName
            }
        }

        if ($Violation.Count -gt 0) {
            $FinalObject = Build-CISAz417 -ReturnedValue $Violation -Status "FAIL" -RiskScore "2" -RiskRating "Low"
            return $FinalObject
        }
        else {
            $FinalObject = Build-CISAz417 -ReturnedValue "No violations found" -Status "PASS" -RiskScore "0" -RiskRating "None"
            return $FinalObject
        }

        return $null
    }
    catch
    {
        $EndObject = Build-CISAz417 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
        Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
        Write-ErrorLog 'An error occurred on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
        return $EndObject
    }
}
return Audit-CISAz417