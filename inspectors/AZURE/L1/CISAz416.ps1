# Benchmark: CIS Microsoft 365 v4.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISAz416
{
    param(
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )

    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISAz416"
        ID               = "4.16"
        Title            = "(L1) Ensure 'Cross Tenant Replication' is not enabled"
        ProductFamily    = "Microsoft Azure"
        DefaultValue     = "Enabled on accounts before Dec 15 2023, else disabled"
        ExpectedValue    = "Disabled"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "Disabling Cross Tenant Replication minimizes the risk of unauthorized data access and ensures that data governance policies are strictly adhered to. This control is especially critical for organizations with stringent data security and privacy requirements, as it prevents the accidental sharing of sensitive information."
        Impact           = "Disabling Cross Tenant Replication may affect data availability and sharing across different Azure tenants. Ensure that this change aligns with your organizational data sharing and availability requirements."
        Remediation      = 'You can change the settings by executing the following PowerShell command: Set-AzStorageAccount -ResourceGroupName <resource group name> -Name <storage account name> -allowCrossTenantReplication $false'
        References       = @(
            @{ 'Name' = 'Prevent object replication across Microsoft Entra tenants'; 'URL' = 'https://learn.microsoft.com/en-us/azure/storage/blobs/object-replication-prevent-cross-tenant-policies?tabs=portal' }
        )
    }

    return $inspectorobject
}


function Audit-CISAz416
{
    try
    {
        $Violation = @()
        $StorageAccounts = Get-AzStorageAccount

        foreach ($StorageAccount in $StorageAccounts) {
            if ($StorageAccount.AllowCrossTenantReplication -ne $false) {
                $Violation += $StorageAccount.StorageAccountName
            }
        }

        if ($Violation.Count -gt 0) {
            $FinalObject = Build-CISAz416 -ReturnedValue $Violation -Status "FAIL" -RiskScore "2" -RiskRating "Low"
            return $FinalObject
        }
        else {
            $FinalObject = Build-CISAz416 -ReturnedValue "No violations found" -Status "PASS" -RiskScore "0" -RiskRating "None"
            return $FinalObject
        }

        return $null
    }
    catch
    {
        $EndObject = Build-CISAz416 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
        Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
        Write-ErrorLog 'An error occurred on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
        return $EndObject
    }
}
return Audit-CISAz416
