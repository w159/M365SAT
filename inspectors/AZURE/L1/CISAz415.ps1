# Benchmark: CIS Microsoft 365 v4.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISAz415
{
    param(
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )

    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISAz415"
        ID               = "4.15"
        Title            = "(L1) Ensure the 'Minimum TLS version' for storage accounts is set to 'Version 1.2'"
        ProductFamily    = "Microsoft Azure"
        DefaultValue     = "TLS1_2 if created via portal. Else TLS1_0"
        ExpectedValue    = "TLS1_2"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "TLS 1.0 has known vulnerabilities and has been replaced by later versions of the TLS protocol. Continued use of this legacy protocol affects the security of data in transit."
        Impact           = "When set to TLS 1.2 all requests must leverage this version of the protocol. Applications leveraging legacy versions of the protocol will fail."
        Remediation      = 'You can change the settings by executing the following PowerShell command: Set-AzStorageAccount -ResourceGroupName <resource group name> -Name <storage account name> -MinimumTlsVersion TLS1_2'
        References       = @(
            @{ 'Name' = 'Enforce a minimum required version of Transport Layer Security (TLS) for requests to a storage account'; 'URL' = 'https://learn.microsoft.com/en-us/azure/storage/common/transport-layer-security-configure-minimum-version?tabs=portal' },
            @{ 'Name' = 'DP-3: Encrypt sensitive data in transit'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-data-protection#dp-3-encrypt-sensitive-data-in-transit' }
        )
    }

    return $inspectorobject
}


function Audit-CISAz415
{
    try
    {
        $Violation = @()
        $StorageAccounts = Get-AzStorageAccount

        foreach ($StorageAccount in $StorageAccounts) {
            if ($StorageAccount.MinimumTlsVersion -ne "TLS1_2") {
                $Violation += $StorageAccount.StorageAccountName
            }
        }

        if ($Violation.Count -gt 0) {
            $FinalObject = Build-CISAz415 -ReturnedValue $Violation -Status "FAIL" -RiskScore "2" -RiskRating "Low"
            return $FinalObject
        }
        else {
            $FinalObject = Build-CISAz415 -ReturnedValue "No violations found" -Status "PASS" -RiskScore "0" -RiskRating "None"
            return $FinalObject
        }

        return $null
    }
    catch
    {
        $EndObject = Build-CISAz415 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
        Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
        Write-ErrorLog 'An error occurred on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
        return $EndObject
    }
}
return Audit-CISAz415
