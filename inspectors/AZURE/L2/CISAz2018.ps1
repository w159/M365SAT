#Requires -module Az.Accounts
# Benchmark: CIS Microsoft Azure v3.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CISAz2018
{
    param(
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )
    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISAz2018"
        ID               = "2.18"
        Title            = "(L2) Ensure that 'Restrict user ability to access groups features in the Access Pane' is Set to 'Yes'"
        ProductFamily    = "Microsoft Azure"
        DefaultValue     = "True"
        ExpectedValue    = "False"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "Self-service group management enables users to create and manage security groups or Microsoft 365 groups in Microsoft Entra ID. This feature allows non-admin users to control access to various resources. Unless a business explicitly requires this functionality, self-service group management should be disabled to prevent unauthorized privilege escalation or security misconfigurations."
        Impact           = "Setting to Yes could create administrative overhead by customers seeking certain group memberships that will have to be manually managed by administrators with appropriate permissions."
        Remediation      = "To mitigate this issue, set 'Restrict user ability to access groups features in My Groups' in the Microsoft Entra portal to 'Yes': https://portal.azure.com/#view/Microsoft_AAD_IAM/GroupsManagementMenuBlade/~/General"
        References       = @(
            @{ 'Name' = 'Set up self-service group management in Microsoft Entra ID'; 'URL' = 'https://learn.microsoft.com/en-us/entra/identity/users/groups-self-service-management' },
            @{ 'Name' = 'PA-1: Separate and limit highly privileged/administrative users'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/security-controls-v3-privileged-access#pa-1-separate-and-limit-highly-privilegedadministrative-users' },
            @{ 'Name' = 'PA-3: Manage lifecycle of identities and entitlements'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-privileged-access#pa-3-manage-lifecycle-of-identities-and-entitlements' },
            @{ 'Name' = 'GS-2: Define and implement enterprise segmentation/separation of duties strategy'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/security-controls-v3-governance-strategy#gs-2-define-and-implement-enterprise-segmentationseparation-of-duties-strategy' },
            @{ 'Name' = 'GS-6: Define and implement identity and privileged access strategy'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/security-controls-v3-governance-strategy#gs-6-define-and-implement-identity-and-privileged-access-strategy' }
        )
    }
    return $inspectorobject
}
#5medium

function Audit-CISAz2018
{
	try
	{
		$AffectedOptions = @()
		# Actual Script 
		$SsgmProperties = Invoke-MultiMicrosoftAPI -Url 'https://main.iam.ad.ext.azure.com/api/Directories/SsgmProperties/' -Resource "74658136-14ec-4630-ad9b-26e160ff0fc6" -Method 'GET'
		
		# Validation
		if ($SsgmProperties.groupsInAccessPanelEnabled -eq $true)
		{
			$AffectedOptions += "Restrict user ability to access groups features in the Access Panel is Set to : $($SsgmProperties.groupsInAccessPanelEnabled)"
		}
		if ($AffectedOptions.count -igt 0)
		{
			$endobject = Build-CISAz2018 -ReturnedValue ($AffectedOptions) -Status "FAIL" -RiskScore "5" -RiskRating "Medium"
			return $endobject
		}
		else
		{
			$endobject = Build-CISAz2018 -ReturnedValue "Restrict user ability to access groups features in the Access Panel is Set to : $($SsgmProperties.groupsInAccessPanelEnabled)" -Status "PASS" -RiskScore "0" -RiskRating "None"
			Return $endobject
		}
		return $null
	}
	catch
	{
		$endobject = Build-CISAz2018 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
		return $endobject
	}
}

function Invoke-MultiMicrosoftAPI
{
	param (
		#The whole URL to call
		[Parameter()]
		[String]$Url,
		#The Name of the Resource
		[Parameter()]
		[String]$Resource,
		[Parameter()]
		#Body if a POST or PUT
		[Object]$Body,
		[Parameter()]
		#Specify the HTTP Method you wish to use. Defaults to GET
		[ValidateSet("GET", "POST", "OPTIONS", "DELETE", "PUT")]
		[String]$Method = "GET"
	)
	
	try
	{
		[Microsoft.Azure.Commands.Profile.Models.Core.PSAzureContext]$Context = (Get-AzContext | Select-Object -first 1)
	}
	catch
	{
		Connect-AzAccount -ErrorAction Stop
		[Microsoft.Azure.Commands.Profile.Models.Core.PSAzureContext]$Context = (Get-AzContext | Select-Object -first 1)
	}
	
	#Specify Resource
	$apiToken = [Microsoft.Azure.Commands.Common.Authentication.AzureSession]::Instance.AuthenticationFactory.Authenticate($context.Account, $context.Environment, $context.Tenant.Id, $null, "Never", $null, $Resource)
	
	# Creating the important header
	$header = [ordered]@{
		'Authorization' = 'Bearer ' + $apiToken.AccessToken.ToString()
		'Content-Type'  = 'application/json'
		'X-Requested-With' = 'XMLHttpRequest'
		'x-ms-client-request-id' = [guid]::NewGuid()
		'x-ms-correlation-id' = [guid]::NewGuid()
	}
	# URL Where PUT Request is being done. You can extract this from F12 
	
	$method = 'GET'
	
	#In Case your Method is PUT or POST to edit something. Change things here
	
	if ($method -eq 'PUT')
	{
		# Remediation Scripts HERE
		$contentpart1 = '{"restrictNonAdminUsers":false}'
		
		#Convert the content (DUMMY)
		$Body = $contentpart1
		
		#Execute Request
		$Response = Invoke-RestMethod -Uri $Url -Headers $header -Method $Method -Body $Body -ErrorAction Stop
	}
	elseif ($method -eq 'POST')
	{
		#Execute Request
		$Response = Invoke-RestMethod -Uri $Url -Headers $header -Method $Method -Body $Body -ErrorAction Stop
	}
	elseif ($method -eq 'GET')
	{
		#Execute Request
		$Response = Invoke-RestMethod -Uri $Url -Headers $header -Method $Method -ErrorAction Stop
	}
	return $Response
}
return Audit-CISAz2018