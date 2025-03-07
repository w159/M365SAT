# Benchmark: CIS Microsoft 365 v4.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISAz811
{
    param (
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )

    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISAz811"
        ID               = "8.11"
        Title            = "(L1) Ensure Trusted Launch is enabled on Virtual Machines"
        ProductFamily    = "Microsoft Azure"
        DefaultValue     = "No Encryption"
        ExpectedValue    = "Encryption"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "Secure Boot and vTPM work together to protect your VM from a variety of boot attacks, including bootkits, rootkits, and firmware rootkits. Not enabling Trusted Launch in Azure VM can lead to increased vulnerability to rootkits and boot-level malware, reduced ability to detect and prevent unauthorized changes to the boot process, and a potential compromise of system integrity and data security."
        Impact           = "Secure Boot and vTPM are not currently supported for Azure Generation 1 VMs. IMPORTANT: Before enabling Secure Boot and vTPM on a Generation 2 VM which does not already have both enabled, it is highly recommended to create a restore point of the VM prior to remediation.."
        Remediation      = 'Use the following PowerShell script to enable Trusted Launch: Set-AzVMSecurityProfile -VM $VM -SecurityType "<TrustedLaunch/ConfidentialVM>"'
        References       = @(
            @{ 'Name' = 'Enable Trusted launch on existing Azure VMs'; 'URL' = 'https://learn.microsoft.com/en-us/azure/virtual-machines/trusted-launch-existing-vm?tabs=portal' },
            @{ 'Name' = 'Secure Boot'; 'URL' = 'https://learn.microsoft.com/en-us/azure/virtual-machines/trusted-launch#secure-boot' }
        )
    }

    return $inspectorobject
}


function Audit-CISAz811
{
    try
    {
        $Violation = @()
        $AzVMs = Get-AzVM | Select-Object Name, SecurityProfile

        foreach ($AzVM in $AzVMs)
        {
            if ($null -eq $AzVM.SecurityProfile.SecurityType -or $AzVM.SecurityProfile.SecurityType -eq "Standard")
            {
                $Violation += $AzVM.Name
            }
        }

        if ($Violation.Count -gt 0)
        {
            $FinalObject = Build-CISAz811 -ReturnedValue $Violation -Status "FAIL" -RiskScore "6" -RiskRating "Medium"
            return $FinalObject
        }
        else
        {
            $FinalObject = Build-CISAz811 -ReturnedValue "No violations found" -Status "PASS" -RiskScore "0" -RiskRating "None"
            return $FinalObject
        }

        return $null
    }
    catch
    {
        $EndObject = Build-CISAz811 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
        Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
        Write-ErrorLog 'An error occurred on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
        return $EndObject
    }
}
return Audit-CISAz811
