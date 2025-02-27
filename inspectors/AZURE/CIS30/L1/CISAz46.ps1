# Benchmark: CIS Microsoft 365 v4.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISAz46
{
    param(
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )

    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISAz46"
        ID               = "4.6"
        Title            = "(L1) Ensure that 'Public Network Access' is 'Disabled' for storage accounts"
        ProductFamily    = "Microsoft Azure"
        DefaultValue     = "Enabled"
        ExpectedValue    = "Disabled"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "Public network access for storage accounts should be disabled to minimize the exposure to unauthorized access."
        Impact           = "Access will have to be managed using shared access signatures or via Azure AD RBAC."
        Remediation      = 'Use the following PowerShell command to disable public network access: Set-AzStorageAccount -ResourceGroupName <resource group name> -Name <storage account name> -PublicNetworkAccess Disabled'
        References       = @(
            @{ 'Name' = 'Configure anonymous read access for containers and blobs'; 'URL' = 'https://learn.microsoft.com/en-us/azure/storage/blobs/anonymous-read-access-configure?tabs=portal' },
            @{ 'Name' = 'GS-2: Define and implement enterprise segmentation/separation of duties strategy'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-governance-strategy#gs-2-define-and-implement-enterprise-segmentationseparation-of-duties-strategy' },
            @{ 'Name' = 'NS-2: Secure cloud native services with network controls'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-network-security#ns-2-secure-cloud-native-services-with-network-controls' },
            @{ 'Name' = 'Assign an Azure role for access to blob data'; 'URL' = 'https://learn.microsoft.com/en-us/azure/storage/blobs/assign-azure-role-data-access?tabs=portal' },
            @{ 'Name' = 'Configure Azure Storage firewalls and virtual networks'; 'URL' = 'https://learn.microsoft.com/en-us/azure/storage/common/storage-network-security?tabs=azure-portal' }
        )
    }

    return $inspectorobject
}


function Audit-CISAz46
{
    try
    {
        $Violation = @()
        $StorageAccounts = Get-AzStorageAccount -ErrorAction SilentlyContinue | Select-Object StorageAccountName, ResourceGroupName, PublicNetworkAccess

        foreach ($StorageAccount in $StorageAccounts) {
            if ($StorageAccount.PublicNetworkAccess -eq 'Enabled') {
                $Violation += $StorageAccount.StorageAccountName
            }
        }

        if ($Violation.Count -gt 0) {
            $FinalObject = Build-CISAz46 -ReturnedValue $Violation -Status "FAIL" -RiskScore "2" -RiskRating "Low"
            return $FinalObject
        } else {
            $FinalObject = Build-CISAz46 -ReturnedValue "No violations found" -Status "PASS" -RiskScore "0" -RiskRating "None"
            return $FinalObject
        }

        return $null
    }
    catch
    {
        $EndObject = Build-CISAz46 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
        Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
        Write-ErrorLog 'An error occurred on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
        return $EndObject
    }
}
return Audit-CISAz46
