# Benchmark: CIS Microsoft 365 v4.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISAz72
{
    param (
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )

    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{ 
        UUID             = "CISAz72"
        ID               = "7.2"
        Title            = "(L1) Ensure that SSH access from the Internet is evaluated and restricted"
        ProductFamily    = "Microsoft Azure"
        DefaultValue     = "Disabled"
        ExpectedValue    = "Disabled"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "The potential security problem with using SSH over the Internet is that attackers can use various brute force techniques to gain access to Azure Virtual Machines. Once the attackers gain access, they can use a virtual machine as a launch point for compromising other machines on the Azure Virtual Network or even attack networked devices outside of Azure."
        Impact           = "Failure to restrict SSH access from the Internet increases the risk of unauthorized access and potential lateral movement within the network."
        Remediation      = "No PowerShell Script Available"
        References       = @(
            @{ 'Name' = 'Azure best practices for network security'; 'URL' = 'https://learn.microsoft.com/en-us/azure/security/fundamentals/network-best-practices#disable-rdpssh-access-to-azure-virtual-machines' },
            @{ 'Name' = 'NS-1: Establish network segmentation boundaries'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-network-security#ns-1-establish-network-segmentation-boundaries' },
            @{ 'Name' = 'ExpressRoute documentation'; 'URL' = 'https://learn.microsoft.com/en-us/azure/expressroute/' },
            @{ 'Name' = 'Tutorial: Create a site-to-site VPN connection in the Azure portal'; 'URL' = 'https://learn.microsoft.com/en-us/azure/vpn-gateway/tutorial-site-to-site-portal' },
            @{ 'Name' = 'Configure server settings for P2S VPN Gateway certificate authentication'; 'URL' = 'https://learn.microsoft.com/en-us/azure/vpn-gateway/vpn-gateway-howto-point-to-site-resource-manager-portal' }
        )
    }

    return $inspectorobject
}


function Audit-CISAz72
{
    try
    {
        $Violation = @()
        $azNsgs = Get-AzNetworkSecurityGroup

        foreach ($azNsg in $azNsgs) {
            $SecurityRuleConfig = Get-AzNetworkSecurityRuleConfig -NetworkSecurityGroup $azNsg | Where-Object { 
                $_.Access -contains "Allow" -and
                ($_.DestinationPortRange -contains 22 -or $_.DestinationPortRange -contains '*') -and 
                $_.Direction -contains "Inbound" -and 
                ($_.Protocol -contains "TCP" -or $_.Protocol -contains '*') -and
                ($_.SourceAddressPrefix -contains '*' -or 
                $_.SourceAddressPrefix -contains "0.0.0.0" -or 
                $_.SourceAddressPrefix -contains "<nw>/0" -or 
                $_.SourceAddressPrefix -contains "/0" -or 
                $_.SourceAddressPrefix -contains "internet" -or 
                $_.SourceAddressPrefix -contains "any")
            }

            if (-not [string]::IsNullOrEmpty($SecurityRuleConfig)) {
                $Violation += $azNsg.Name
            }
        }

        if ($Violation.Count -gt 0) {
            $FinalObject = Build-CISAz72 -ReturnedValue $Violation -Status "FAIL" -RiskScore "6" -RiskRating "Medium"
            return $FinalObject
        }
        else {
            $FinalObject = Build-CISAz72 -ReturnedValue "No violations found" -Status "PASS" -RiskScore "0" -RiskRating "None"
            return $FinalObject
        }

        return $null
    }
    catch
    {
        $EndObject = Build-CISAz72 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
        Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
        Write-ErrorLog 'An error occurred on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
        return $EndObject
    }
}
return Audit-CISAz72
