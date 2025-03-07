# Benchmark: CIS Microsoft 365 v4.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISAz88
{
    param (
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )

    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISAz88"
        ID               = "8.8"
        Title            = "(L2) Ensure that Endpoint Protection for all Virtual Machines is installed"
        ProductFamily    = "Microsoft Azure"
        DefaultValue     = "By default Endpoint Protection is disabled."
        ExpectedValue    = "Endpoint Protection is enabled."
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "Installing endpoint protection systems (like anti-malware for Azure) provides for real-time protection capability that helps identify and remove viruses, spyware, and other malicious software. These also offer configurable alerts when known-malicious or unwanted software attempts to install itself or run on Azure systems."
        Impact           = "Endpoint protection will incur an additional cost to you."
        Remediation      = "Use the following PowerShell script to remediate this issue: Remove-AzVMExtension -ResourceGroupName <ResourceGroupName> -Name <ExtensionName> -VMName <VirtualMachineName>"
        References       = @(
            @{ 'Name' = 'Containers support matrix in Defender for Cloud'; 'URL' = 'https://learn.microsoft.com/en-us/azure/defender-for-cloud/support-matrix-defender-for-containers?tabs=features-windows#supported-endpoint-protection-solutions-' },
            @{ 'Name' = 'Microsoft Antimalware for Azure Cloud Services and Virtual Machines'; 'URL' = 'https://learn.microsoft.com/en-us/azure/security/fundamentals/antimalware' },
            @{ 'Name' = 'ES-1: Use Endpoint Detection and Response (EDR)'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-endpoint-security#es-1-use-endpoint-detection-and-response-edr' }
        )
    }

    return $inspectorobject
}

function Audit-CISAz88
{
    try
    {
        # Checking for Virtual Machines that lack Endpoint Detection and Response (EDR) solution installed
        $Violation = @()
        $AzVMs = Get-AzVM

        foreach ($AzVM in $AzVMs)
        {
            $Check = Get-AzAdvisorRecommendation -ResourceId $AzVM.Id | Where-Object {
                $_.ImpactedField -eq "Microsoft.Compute/virtualMachines" -and 
                $_.Category -eq "Security" -and 
                $_.ShortDescriptionProblem.Contains("EDR solution should be installed on Virtual Machines")
            }

            # Check if the recommendation ID matches for missing EDR solution
            if ($Check.RecommendationTypeId -eq "06e3a6db-6c0c-4ad9-943f-31d9d73ecf6c")
            {
                $Violation += $AzVM.Name
            }
        }

        if ($Violation.Count -gt 0)
        {
            $FinalObject = Build-CISAz88 -ReturnedValue $Violation -Status "FAIL" -RiskScore "6" -RiskRating "Medium"
            return $FinalObject
        }
        else
        {
            $FinalObject = Build-CISAz88 -ReturnedValue "No violations found" -Status "PASS" -RiskScore "0" -RiskRating "None"
            return $FinalObject
        }

        return $null
    }
    catch
    {
        $EndObject = Build-CISAz88 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
        Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
        Write-ErrorLog 'An error occurred on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
        return $EndObject
    }
}
return Audit-CISAz88
