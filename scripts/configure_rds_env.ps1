#
# configure_rds_env.ps1
#

param(
	[string] [Parameter(Mandatory=$false)] $FQDNDomain,
	[string] [Parameter(Mandatory=$false)] $Cred_User,
	[string] [Parameter(Mandatory=$false)] $Cred_Psswd,
	[string] [Parameter(Mandatory=$false)] $Pri_RDCB,
	[string] [Parameter(Mandatory=$false)] $Sec_RDCB,
	[string] [Parameter(Mandatory=$false)] $Pri_RDGW,
	[string] [Parameter(Mandatory=$false)] $Sec_RDGW,
	[string] [Parameter(Mandatory=$false)] $Pri_RDSH,
	[string] [Parameter(Mandatory=$false)] $Sec_RDSH,
	[string] [Parameter(Mandatory=$false)] $IPLBBroker,
	[string] [Parameter(Mandatory=$false)] $DBServer,
	[string] [Parameter(Mandatory=$false)] $DBName,
	[string] [Parameter(Mandatory=$false)] $DBUser,
	[string] [Parameter(Mandatory=$false)] $DBPasswd,
	[string] [Parameter(Mandatory=$false)] $RDBrokerDNS,
	[string] [Parameter(Mandatory=$false)] $RDGatewayDNS,
	[string] [Parameter(Mandatory=$false)] $CertifcatePFXName,
	[string] [Parameter(Mandatory=$false)] $CertifcatePFXPassword,
	[string] [Parameter(Mandatory=$false)] $RDSessionCollectionName,
	[string] [Parameter(Mandatory=$false)] $ClsSofsName,
	[string] [Parameter(Mandatory=$false)] $ClsSofsShare,
	[int] [Parameter(Mandatory=$false)] $RDSessionCollectionUPDSize,
	[int] [Parameter(Mandatory=$false)] $RDSessionCollectionIdleSession,
	[string] [Parameter(Mandatory=$false)] $FQDNDomainExt
)

Write-Output 'Enable File/Print Sharing on Servers' | Out-File -FilePath 'C:\WINDOWS\Temp\rds_deployment.log' -Append
netsh advfirewall firewall set rule group="File and Printer Sharing" new enable=Yes

Write-Output 'Enable WinRM and opening the firewall' | Out-File -FilePath 'C:\WINDOWS\Temp\rds_deployment.log' -Append
winrm quickconfig -q
netsh advfirewall firewall set rule name="Windows Remote Management (HTTP-In)" new enable=Yes

Write-Output 'Enable WMI Firewall Exception on Servers' | Out-File -FilePath 'C:\WINDOWS\Temp\rds_deployment.log' -Append
netsh advfirewall firewall set rule group="Windows Management Instrumentation (WMI)" new enable=Yes

$AllServers    = @()
$RDCB_Servers  = @()
$RDSH_Servers  = @()
$RDGW_Servers  = @()

$Pri_RDCB_FQDN = $Pri_RDCB+"."+$FQDNDomain
$Sec_RDCB_FQDN = $Sec_RDCB+"."+$FQDNDomain
$AllServers += $Pri_RDCB_FQDN
$AllServers += $Sec_RDCB_FQDN
$RDCB_Servers += $Pri_RDCB_FQDN
$RDCB_Servers += $Sec_RDCB_FQDN

$Pri_RDGW_FQDN = $Pri_RDGW+"."+$FQDNDomain
$Sec_RDGW_FQDN = $Sec_RDGW+"."+$FQDNDomain
$AllServers += $Pri_RDGW_FQDN
$AllServers += $Sec_RDGW_FQDN
$RDGW_Servers += $Pri_RDGW_FQDN
$RDGW_Servers += $Sec_RDGW_FQDN

$Pri_RDSH_FQDN = $Pri_RDSH+"."+$FQDNDomain
$Sec_RDSH_FQDN = $Sec_RDSH+"."+$FQDNDomain
$AllServers += $Pri_RDSH_FQDN
$AllServers += $Sec_RDSH_FQDN
$RDSH_Servers += $Pri_RDSH_FQDN
$RDSH_Servers += $Sec_RDSH_FQDN

$RDBrokerDNS_FQDN = $RDBrokerDNS+"."+$FQDNDomainExt
$RDGatewayDNS_FQDN = $RDGatewayDNS+"."+$FQDNDomainExt
$UpdShare = "\\"+$ClsSofsName+"\"+$ClsSofsShare

#Check if servers are Up!
foreach($server in $AllServers) {
	$timeout = 0

	while(!(Test-Connection -Cn $server -BufferSize 16 -Count 1 -ea 0 -quiet)) {
		Write-Output "$server - Connection is Down" | Out-File -FilePath 'C:\WINDOWS\Temp\rds_deployment.log' -Append
		
		Start-Sleep -s 15

		if($timeout -eq 5) {
			Restart-Computer -ComputerName $server -Wait -For PowerShell -Timeout 300 -Delay 2
			$timeout = 0
		} else {
			$timeout++
		}
	}

	Write-Output "$server - Connection is UP" | Out-File -FilePath 'C:\WINDOWS\Temp\rds_deployment.log' -Append
}

$secpasswd     = ConvertTo-SecureString $Cred_Psswd -AsPlainText -Force
$cred          = New-Object System.Management.Automation.PSCredential ($Cred_User, $secpasswd)
$certificate   = $PSScriptRoot+'\'+$CertifcatePFXName

Invoke-Command -ComputerName $Pri_RDCB_FQDN -Credential $cred -ScriptBlock {
	$delegate = '*.'+$Using:FQDNDomain
	$wsman    = 'wsman/*.'+$Using:FQDNDomain

	Write-Output "Starting enabling CredSSP on $Using:Pri_RDCB_FQDN" | Out-File -FilePath 'C:\WINDOWS\Temp\rds_deployment.log' -Append	
	Enable-WSManCredSSP -Role Client -DelegateComputer $delegate -Force
	Enable-WSManCredSSP -Role Server -Force
	
	Write-Output "Set TrustedHosts on $Using:Pri_RDCB_FQDN" | Out-File -FilePath 'C:\WINDOWS\Temp\rds_deployment.log' -Append
	Set-item wsman:localhost\client\trustedhosts -value $delegate -Force

	Write-Output "Enable CredSSP Fresh NTLM Only on $Using:Pri_RDCB_FQDN" | Out-File -FilePath 'C:\WINDOWS\Temp\rds_deployment.log' -Append
	New-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation -Name AllowFreshCredentialsWhenNTLMOnly -Value 1 -PropertyType DWORD -Force | Out-Null
	New-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation -Name ConcatenateDefaults_AllowFreshNTLMOnly -Value 1 -PropertyType DWORD -Force | Out-Null
	New-Item -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation -Name AllowFreshCredentialsWhenNTLMOnly -Force | Out-Null
	New-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation\AllowFreshCredentialsWhenNTLMOnly -Name 1 -Value $wsman -PropertyType String -Force | Out-Null
}

Invoke-Command $RDCB_Servers -Credential $cred -ScriptBlock {
	Write-Output "Starting installing SQL Native Client" | Out-File -FilePath 'C:\WINDOWS\Temp\rds_deployment.log' -Append
	
	#SQL ODBC Driver Url
	$url    = 'http://go.microsoft.com/fwlink/?LinkID=239648&clcid=0x409'
	$output = 'C:\Windows\temp\sqlncli.msi'

	(New-Object System.Net.WebClient).DownloadFile($url, $output)

	Start-Process $output -ArgumentList "IACCEPTSQLNCLILICENSETERMS=YES /qn /l*v .\install_sqlncli.txt" -PassThru | Wait-Process
}


Invoke-Command -ComputerName $Pri_RDCB_FQDN -Credential $cred -ScriptBlock {
	Write-Output "Starting Installation and Configuration of Remote Desktop Services" | Out-File -FilePath 'C:\WINDOWS\Temp\rds_deployment.log' -Append
	Import-Module RemoteDesktop

	try {
		Write-Output "Starting Initial Installation of RDS roles" | Out-File -FilePath 'C:\WINDOWS\Temp\rds_deployment.log' -Append
		
		# Install the initial environment
		New-RDSessionDeployment –ConnectionBroker $Using:Pri_RDCB_FQDN –WebAccessServer $Using:Pri_RDGW_FQDN –SessionHost $Using:Pri_RDSH_FQDN | Out-File -FilePath 'C:\WINDOWS\Temp\rds_deployment.log' -Append
	} Catch {
		$ErrorMessage = $_.Exception.Message | Out-File -FilePath 'C:\WINDOWS\Temp\rds_deployment.log' -Append
		$FailedItem = $_.Exception.ItemName | Out-File -FilePath 'C:\WINDOWS\Temp\rds_deployment.log' -Append
		Break
	}
	Start-Sleep -s 15

	try {
		Write-Output "Starting Configuring of High Availability of RD Roles" | Out-File -FilePath 'C:\WINDOWS\Temp\rds_deployment.log' -Append
		# Configure RD High Availability
		$ConnectionString = 'Driver={SQL Server Native Client 11.0};Server=tcp:'+$Using:DBServer+'.database.windows.net,1433;Database='+$Using:DBName+';Uid='+$Using:DBuser+'@'+$Using:DBServer+';Pwd='+$Using:DBPasswd+';Encrypt=yes;TrustServerCertificate=no;Connection Timeout=30;'
	    Set-RDConnectionBrokerHighAvailability -ConnectionBroker $Using:Pri_RDCB_FQDN -DatabaseConnectionString $ConnectionString -ClientAccessName $Using:RDBrokerDNS_FQDN | Out-File -FilePath 'C:\WINDOWS\Temp\rds_deployment.log' -Append

		Write-Output "Adding the 2nd RD Connection Broker to the deployment" | Out-File -FilePath 'C:\WINDOWS\Temp\rds_deployment.log' -Append
		Add-RDServer -Role RDS-CONNECTION-BROKER -Server $Using:Sec_RDCB_FQDN -ConnectionBroker $Using:Pri_RDCB_FQDN
	} Catch {
		$ErrorMessage = $_.Exception.Message | Out-File -FilePath 'C:\WINDOWS\Temp\rds_deployment.log' -Append
		$FailedItem = $_.Exception.ItemName | Out-File -FilePath 'C:\WINDOWS\Temp\rds_deployment.log' -Append
		Break
	}
	Start-Sleep -s 15

	try {
		Write-Output "Installing RD roles" | Out-File -FilePath 'C:\WINDOWS\Temp\rds_deployment.log' -Append
		
		Write-Output "Adding the 2nd RD Web Access Servers to the deployment" | Out-File -FilePath 'C:\WINDOWS\Temp\rds_deployment.log' -Append
		Add-RDServer -Role  RDS-WEB-ACCESS -Server $Using:Sec_RDGW_FQDN -ConnectionBroker $Using:Pri_RDCB_FQDN

		Write-Output "Adding the RD Licensing to RD Connection Broker Servers" | Out-File -FilePath 'C:\WINDOWS\Temp\rds_deployment.log' -Append
		Add-RDServer -Role  RDS-LICENSING -Server $Using:Pri_RDCB_FQDN -ConnectionBroker $Using:Pri_RDCB_FQDN
		Add-RDServer -Role  RDS-LICENSING -Server $Using:Sec_RDCB_FQDN -ConnectionBroker $Using:Pri_RDCB_FQDN
		Set-RDLicenseConfiguration -Mode PerUser -Force

		Write-Output "Adding the RD Gateway Role to the RD WebAccess Servers" | Out-File -FilePath 'C:\WINDOWS\Temp\rds_deployment.log' -Append
		Add-RDServer -Role RDS-GATEWAY -Server $Using:Pri_RDGW_FQDN -ConnectionBroker $Using:Pri_RDCB_FQDN -GatewayExternalFqdn $Using:RDGatewayDNS_FQDN
		Add-RDServer -Role RDS-GATEWAY -Server $Using:Sec_RDGW_FQDN -ConnectionBroker $Using:Pri_RDCB_FQDN -GatewayExternalFqdn $Using:RDGatewayDNS_FQDN

		Write-Output "Adding the 2nd RD Session Server to the deployment" | Out-File -FilePath 'C:\WINDOWS\Temp\rds_deployment.log' -Append
		Add-RDServer -Role  RDS-RD-SERVER -Server $Using:Sec_RDSH_FQDN -ConnectionBroker $Using:Pri_RDCB_FQDN
	} Catch {
		$ErrorMessage = $_.Exception.Message | Out-File -FilePath 'C:\WINDOWS\Temp\rds_deployment.log' -Append
		$FailedItem = $_.Exception.ItemName | Out-File -FilePath 'C:\WINDOWS\Temp\rds_deployment.log' -Append
		Break
	}
	Start-Sleep -s 15

	try {
		Write-Output "Installing RD certificates" | Out-File -FilePath 'C:\WINDOWS\Temp\rds_deployment.log' -Append

		$Using:certificate | Out-File -FilePath 'C:\WINDOWS\Temp\rds_deployment.log' -Append
		$Password = ConvertTo-SecureString -String $Using:CertifcatePFXPassword -AsPlainText -Force

		Write-Output "Installing SingleSingnOn Certificate" | Out-File -FilePath 'C:\WINDOWS\Temp\rds_deployment.log' -Append
		Set-RDCertificate -Role RDRedirector -ImportPath $Using:certificate -Password $Password -ConnectionBroker $Using:Pri_RDCB_FQDN -Force
		
		Write-Output "Installing RDGateway Certificate" | Out-File -FilePath 'C:\WINDOWS\Temp\rds_deployment.log' -Append
		Set-RDCertificate -Role RDGateway -ImportPath $Using:certificate -Password $Password -ConnectionBroker $Using:Pri_RDCB_FQDN -Force

		Write-Output "Installing RD Web Access Certificate" | Out-File -FilePath 'C:\WINDOWS\Temp\rds_deployment.log' -Append
		Set-RDCertificate -Role RDWebAccess -ImportPath $Using:certificate -Password $Password -ConnectionBroker $Using:Pri_RDCB_FQDN -Force

		Write-Output "Installing RD Signing Certificate" | Out-File -FilePath 'C:\WINDOWS\Temp\rds_deployment.log' -Append
		Set-RDCertificate -Role RDPublishing -ImportPath $Using:certificate -Password $Password -ConnectionBroker $Using:Pri_RDCB_FQDN -Force
	} Catch {
		$ErrorMessage = $_.Exception.Message | Out-File -FilePath 'C:\WINDOWS\Temp\rds_deployment.log' -Append
		$FailedItem = $_.Exception.ItemName | Out-File -FilePath 'C:\WINDOWS\Temp\rds_deployment.log' -Append
		Break
	}
	Start-Sleep -s 15

	try {
		Write-Output "Creating and configuring the RD Session Collection" | Out-File -FilePath 'C:\WINDOWS\Temp\rds_deployment.log' -Append
		
		Write-Output "Create Collection $Using:RDSessionCollectionName" | Out-File -FilePath 'C:\WINDOWS\Temp\rds_deployment.log' -Append
		New-RDSessionCollection -Collectionname $Using:RDSessionCollectionName -SessionHost $Using:RDSH_Servers -ConnectionBroker $Using:Pri_RDCB_FQDN -Verbose | Out-File -FilePath 'C:\WINDOWS\Temp\rds_deployment.log' -Append
		
		Write-Output "Enable User Profiledisk ($using:UpdShare) for Collection $Using:RDSessionCollectionName" | Out-File -FilePath 'C:\WINDOWS\Temp\rds_deployment.log' -Append
		Set-RDSessionCollectionConfiguration -CollectionName $Using:RDSessionCollectionName -EnableUserProfileDisk -DiskPath $using:UpdShare -MaxUserProfileDiskSizeGB $Using:RDSessionCollectionUPDSize -ConnectionBroker $Using:Pri_RDCB_FQDN -Verbose | Out-File -FilePath 'C:\WINDOWS\Temp\rds_deployment.log' -Append

		Write-Output "Setting additional options for Collection $Using:RDSessionCollectionName" | Out-File -FilePath 'C:\WINDOWS\Temp\rds_deployment.log' -Append
		Set-RDSessionCollectionConfiguration -CollectionName $Using:RDSessionCollectionName -AutomaticReconnectionEnabled $true -BrokenConnectionAction Disconnect -IdleSessionLimitMin $Using:RDSessionCollectionIdleSession -TemporaryFoldersDeletedOnExit $true | Out-File -FilePath 'C:\WINDOWS\Temp\rds_deployment.log' -Append

		
	} Catch {
		$ErrorMessage = $_.Exception.Message | Out-File -FilePath 'C:\WINDOWS\Temp\rds_deployment.log' -Append
		$FailedItem = $_.Exception.ItemName | Out-File -FilePath 'C:\WINDOWS\Temp\rds_deployment.log' -Append
		Break
	}
	Start-Sleep -s 15
	
} -Authentication Credssp

Invoke-Command $RDGW_Servers -Credential $cred -ScriptBlock {
	Write-Output "Configuring RD Gateway" | Out-File -FilePath 'C:\WINDOWS\Temp\rds_deployment.log' -Append
	
	Import-Module RemoteDesktopServices 

	#Remove All Domain Computers Group
	Remove-Item -Path RDS:\GatewayServer\RAP\RDG_AllDomainComputers -Recurse -Force

	#Add Second RD Connection Broker
	New-Item -Path RDS:\GatewayServer\GatewayManagedComputerGroups\RDG_RDCBComputers\Computers -Name $Using:Sec_RDCB_FQDN -ItemType 'String'

	$UserGroup = 'Domain Users@'+$Using:FQDNDomain
	#Create RDSH Gateway Group and policy
	New-Item -Path RDS:\GatewayServer\GatewayManagedComputerGroups -Name 'RDG_RDSessionHostServers' -Description 'All RDSH Servers' -Computers $Using:RDSH_Servers
	New-Item -Path RDS:\GatewayServer\RAP -Name 'RDG_RDSessionHostServers' -UserGroups $UserGroup -ComputerGroupType 0 -Port 3389 -ComputerGroup 'RDG_RDSessionHostServers'
}

Invoke-Command -ComputerName $Pri_RDCB_FQDN -Credential $cred -ScriptBlock {
	Disable-WSManCredSSP -Role Client
	Disable-WSManCredSSP -Role Server
}