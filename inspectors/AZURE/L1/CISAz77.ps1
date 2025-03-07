# Benchmark: CIS Microsoft 365 v4.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISAz77
{
    param (
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )

    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISAz77"
        ID               = "7.7"
        Title            = "(L1) Ensure that Public IP addresses are Evaluated on a Periodic Basis"
        ProductFamily    = "Microsoft Azure"
        DefaultValue     = "Disabled"
        ExpectedValue    = "Disabled"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "Public IP Addresses allocated to the tenant should be periodically reviewed for necessity. Public IP Addresses that are not intentionally assigned and controlled present a publicly facing vector for threat actors and significant risk to the tenant."
        Impact           = "Failure to periodically review Public IP addresses may increase the risk of unintended exposure to threat actors."
        Remediation      = "No PowerShell Script Available"
        References       = @(
            @{ 'Name' = 'Security Control: Network security'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-network-security' }
        )
    }

    return $inspectorobject
}


function Audit-CISAz77
{
    try
    {
        # Public IP address evaluation
        $Violation = @()
        $PublicIpAddresses = Get-AzPublicIpAddress

        foreach ($PublicIpAddress in $PublicIpAddresses)
        {
            # Check if the public IP address has any issues (you can modify the condition here if needed)
            $Violation += $PublicIpAddress.Name
        }

        if ($Violation.Count -gt 0) {
            $FinalObject = Build-CISAz77 -ReturnedValue $Violation -Status "FAIL" -RiskScore "0" -RiskRating "Informational"
            return $FinalObject
        }
        else {
            $FinalObject = Build-CISAz77 -ReturnedValue "No violations found" -Status "PASS" -RiskScore "0" -RiskRating "Informational"
            return $FinalObject
        }

        return $null
    }
    catch
    {
        $EndObject = Build-CISAz77 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
        Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
        Write-ErrorLog 'An error occurred on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
        return $EndObject
    }
}
return Audit-CISAz77
