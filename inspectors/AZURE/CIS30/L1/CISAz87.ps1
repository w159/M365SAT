# Benchmark: CIS Microsoft 365 v4.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CISAz87
{
    param (
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )

    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISAz87"
        ID               = "8.7"
        Title            = "(L1) Ensure that Only Approved Extensions Are Installed"
        ProductFamily    = "Microsoft Azure"
        DefaultValue     = "By default, no extensions are added to the virtual machines."
        ExpectedValue    = "Only approved Extensions"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "Azure virtual machine extensions are small applications that provide post-deployment configuration and automation tasks on Azure virtual machines. These extensions run with administrative privileges and could potentially access anything on a virtual machine. The Azure Portal and community provide several such extensions. Each organization should carefully evaluate these extensions and ensure that only those that are approved for use are actually implemented."
        Impact           = "Functionality by unsupported extensions will be disabled."
        Remediation      = "Remove-AzVMExtension -ResourceGroupName <ResourceGroupName> -Name <ExtensionName> -VMName <VirtualMachineName>"
        References       = @(
            @{ 'Name' = 'Virtual machine extensions and features for Windows'; 'URL' = 'https://learn.microsoft.com/en-us/azure/virtual-machines/extensions/features-windows' },
            @{ 'Name' = 'AM-2: Use only approved services'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-asset-management#am-2-use-only-approved-services' },
            @{ 'Name' = 'AM-5: Use only approved applications in virtual machine'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-asset-management#am-5-use-only-approved-applications-in-virtual-machine' }
        )
    }

    return $inspectorobject
}

function Audit-CISAz87
{
    try
    {
        # Checking for VM extensions that are not approved
        $Violation = @()
        $AzVMs = Get-AzVM

        foreach ($AzVM in $AzVMs)
        {
            $Extensions = Get-AzVMExtension -ResourceGroupName $AzVM.ResourceGroupName -VMName $AzVM.Name | Select-Object Name, ExtensionType, ProvisioningState
            foreach ($Extension in $Extensions)
            {
                $Violation += "$($AzVM.Name): $($Extension.Name)"
            }
        }

        if ($Violation.Count -gt 0)
        {
            $FinalObject = Build-CISAz87 -ReturnedValue $Violation -Status "FAIL" -RiskScore "6" -RiskRating "Medium"
            return $FinalObject
        }
        else
        {
            $FinalObject = Build-CISAz87 -ReturnedValue "No violations found" -Status "PASS" -RiskScore "0" -RiskRating "None"
            return $FinalObject
        }

        return $null
    }
    catch
    {
        $EndObject = Build-CISAz87 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
        Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
        Write-ErrorLog 'An error occurred on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
        return $EndObject
    }
}
return Audit-CISAz87
