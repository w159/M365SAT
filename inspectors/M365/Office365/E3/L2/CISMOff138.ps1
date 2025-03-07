#Requires -module Az.Accounts
# Benchmark: CIS Microsoft 365 v4.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CISMOff138
{
    param(
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )
    #Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISMOff138"
        ID               = "1.3.8"
        Title            = "(L2) Ensure that Sways cannot be shared with people outside of your organization"
        ProductFamily    = "Microsoft Office 365"
        DefaultValue     = "True"
        ExpectedValue    = "False"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "Disabling external sharing of Sway documents reduces the risk of sensitive information being accidentally or intentionally shared outside the organization."
        Impact           = "Allowing external sharing of Sways could result in sensitive data being inadvertently exposed to unauthorized individuals."
        Remediation      = "Disable external sharing of Sway documents by unchecking the setting 'Let people in your organization share their Sways with people outside your organization' in the Admin Portal. Use the following URL to access the settings: `https://admin.microsoft.com/Adminportal/Home#/Settings/Services/:/Settings/L1/Sway`."
        References       = @(
            @{ 'Name' = 'Administrator settings for Microsoft Forms'; 'URL' = 'https://learn.microsoft.com/en-US/microsoft-forms/administrator-settings-microsoft-forms' },
            @{ 'Name' = 'Review and unblock forms or users detected and blocked for potential phishing'; 'URL' = 'https://learn.microsoft.com/en-US/microsoft-forms/review-unblock-forms-users-detected-blocked-potential-phishing' }
        )
    }
    return $inspectorobject
}

function Audit-CISMOff138
{
	try
	{
		$AffectedSettings = @()
		# Actual Script
		$SwaySetting = Invoke-MultiMicrosoftAPI -Url "https://admin.microsoft.com/admin/api/settings/apps/Sway" -Resource "https://admin.microsoft.com" -Method 'GET'
		
		# Validation
		if ($SwaySetting.ExternalSharingEnabled -eq $true)
		{
			$AffectedSettings += "ExternalSharingEnabled: $($SwaySetting.ExternalSharingEnabled)"
		}
		if ($AffectedSettings.Count -igt 0)
		{
			$endobject = Build-CISMOff138 -ReturnedValue $AffectedSettings -Status "FAIL" -RiskScore "3" -RiskRating "Low"
			return $endobject
		}
		else
		{
			$endobject = Build-CISMOff138 -ReturnedValue $SwaySetting.ExternalSharingEnabled -Status "PASS" -RiskScore "0" -RiskRating "None"
			Return $endobject
		}
	}
	catch
	{
		$endobject = Build-CISMOff138 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
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
return Audit-CISMOff138