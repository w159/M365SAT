#Global Variables
$Username = ""
$Credential = $Username

if ($PSVersionTable.PSVersion.Major -igt 5)
{
    Import-Module Microsoft.Online.SharePoint.PowerShell -UseWindowsPowershell
}

#Azure
$AzEnvironment = "AzureCloud"
Connect-AzAccount -AccountId $Username -Environment $AzEnvironment
if ($null -ne (Get-AzContext))
{
    Write-Host "Connected to Microsoft Azure Powershell!" -ForegroundColor DarkYellow -BackgroundColor Black
    return $true
}
else
{
    Write-ErrorLog 'Failed to Connect to Microsoft Azure Powershell' -ErrorRecord $_
    return $false
}

#Graph
$global:graphURI = 'graph.microsoft.com'
$GraphEnvironment = 'Global'
Connect-MgGraph -Environment $GraphEnvironment -ContextScope Process -Scopes "Directory.Read.All", "RoleManagement.Read.Directory", "DeviceManagementServiceConfig.Read.All", "DeviceManagementConfiguration.Read.All", "User.Read.All", "Policy.Read.All", "DeviceManagementManagedDevices.Read.All", "DeviceManagementApps.Read.All", "Group.Read.All", "UserAuthenticationMethod.Read.All", "GroupMember.Read.All", "Organization.Read.All", "Domain.Read.All", "AccessReview.Read.All", "SecurityEvents.Read.All"
if ($null -ne (Get-MgContext))
{
    Write-Host "Connected to Microsoft Graph Powershell!" -ForegroundColor DarkYellow -BackgroundColor Black
}
else
{
    Write-ErrorLog 'Failed to Connect to Microsoft Graph Powershell' -ErrorRecord $_
    return $null
}

#IPPS
$IPPSEnvironment = 'https://ps.compliance.protection.outlook.com/powershell-liveid/'
$AADUri = 'https://login.microsoftonline.com/common' 
Connect-IPPSSession -ConnectionUri $IPPSEnvironment -AzureADAuthorizationEndpointUri $AADUri -UserPrincipalName $Username -ShowBanner:$false
if ($null -ne (Get-PolicyConfig))
{
    Write-Host "Connected to Microsoft Security & Compliance!" -ForegroundColor DarkYellow -BackgroundColor Black
    return $true
}
else
{
    Write-ErrorLog 'Failed to Connect to Microsoft Security & Compliance' -ErrorRecord $_
    return $false
}

#Exchange
$ExEnvironment = 'O365Default' 
Connect-ExchangeOnline -ExchangeEnvironmentName $ExEnvironment -UserPrincipalName $Username -ShowBanner:$false
if ($null -ne (Get-ConnectionInformation))
{
    Write-Host "Connected to Microsoft Exchange!" -ForegroundColor DarkYellow -BackgroundColor Black
    return $OrgName
}
else
{
    Write-ErrorLog 'Failed to Connect to Microsoft Exchange' -ErrorRecord $_
    return $false
}

#Sharepoint
$SpEnvironment = 'Default'
$TenantName = (((Get-MgOrganization).VerifiedDomains |  Where-Object { ($_.Name -like "*.onmicrosoft.com") -and ($_.Name -notlike "*mail.onmicrosoft.com") }).Name -split '.onmicrosoft.com')[0]
Connect-SPOService -Credential $Username -Url "https://$TenantName-admin.sharepoint.com" -Region $SpEnvironment -ModernAuth $true
if ($null -ne (Get-SPOTenant) )
		{
			Write-Host "Connected to Microsoft Sharepoint Powershell!" -ForegroundColor DarkYellow -BackgroundColor Black
			return $true
		}
		else
		{
			Write-ErrorLog 'Failed to Connect to Microsoft Sharepoint Powershell' -ErrorRecord $_
			return $false
		}

#Teams
Connect-MicrosoftTeams -AccountId $Username
if ($null -ne (Get-CsTenant))
{
    Write-Host "Connected to Microsoft Teams Powershell!" -ForegroundColor DarkYellow -BackgroundColor Black
    return $true
}
else
{
    Write-ErrorLog 'Failed to Connect to Microsoft Teams Powershell' -ErrorRecord $_
    return $false
}


Disconnect-AzAccount | Out-Null
Invoke-MgBetaInvalidateAllUserRefreshToken -UserId (Get-MgContext).Account
Disconnect-MgGraph | Out-Null
Disconnect-ExchangeOnline -Confirm:$false
Disconnect-SPOService
Disconnect-MicrosoftTeams