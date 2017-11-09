Function Test-SentryOneTarget 
{
<#
.SYNOPSIS 
Tests a remote machine to make sure all the firewall ports, permissions, WMI, perfmon is accessible to allow SentryOne to monitor it.

.DESCRIPTION
The function Test-SentryOneTarget is designed to test the requirements are met for SentryOne to be able to connect to a SQL Server target in Full Mode. If the tests Pass this means that Sentry One will be able to display and save both Windows performance metrics and SQL Server metrics.

If the SQLSysadmin test Passes but others fail, then SentryOne will be able to connect in **Limited Mode** which means that the Windows performance metrics will not be gathered, only the SQL Server ones.

.PARAMETER ServerName
The host name where SQL Server is being hosted.

.PARAMETER InstanceName
If a named instance then specify it here including the server name, e.g. SERVER1\INSTANCEA

.PARAMETER UserName
If this is specified then SQL Authentication will be used. If blank then Windows Authentication will be used

.PARAMETER Password
The SQL Authentication Password

.PARAMETER SQLPort
The port SQL Server is listening on. If none supplied, 1433 is tried.

.NOTES
Before running the function you will need to install and import the SQL Server module so you can connect to SQL Servers with: Import-Module SQLServer
See https://docs.microsoft.com/en-us/sql/ssms/download-sql-server-ps-module

Author: Mark Allison, Sabin.IO <mark.allison@sabin.io>

.EXAMPLE   
Test-SentryOneTarget -ServerName SQLSERVERBOX

#>    
    [cmdletbinding()]
    param (
        [parameter(Mandatory=$true,Position=0,ValueFromPipeline)]
        [string] $ServerName,
        
        [parameter(Mandatory=$false,Position=1)]
        [string] $InstanceName,

        [parameter(Mandatory=$false,Position=2)]
        [string] $UserName,

        [parameter(Mandatory=$false,Position=3)]
        [string] $Password,

        [parameter(Mandatory=$false,Position=4)]
        [int] $SQLPort
    )
    Process {
        if ([string]::IsNullOrEmpty($InstanceName)) {
            $InstanceName = $ServerName
        }

        if ($SQLPort -eq 0) {
            $SQLPort = 1433
        }
        
        # https://cdn.sentryone.com/help/qs/webframe.html?Performance%20Advisor%20Required%20Ports.html#Performance%20Advisor%20Required%20Ports.html#Performance%20Advisor%20Required%20Ports.html
        Write-Verbose "Resolving IP Address ..."
        $ip = [string](Resolve-DnsName -Name "$ServerName" -ErrorAction 'Stop' -Verbose:$False).IPAddress
        
        Write-Verbose "Testing SQL Port $SQLPort ..."
        $IsSqlPortOpen = "FAIL - Unknown error" 
        try {
            if (Test-TcpPort -ip $ip -port $SQLPort) {
                $IsSqlPortOpen = "Pass"
            }    
        }
        catch {
            $IsSqlPortOpen = $Error[0].Exception.InnerException.Message
        }

        Write-Verbose "Testing SMB/RPC Port 445 ..."
        $IsPort445Open = "FAIL"
        try {
            if (Test-TcpPort -ip $ip -port 445) { 
                $IsPort445Open = "Pass"
            }
        }
        catch {
            $IsPort445Open = $Error[0].Exception.InnerException.Message
        }
        
        Write-Verbose "Testing RPC Port 135 ..."
        $IsPort135Open = "FAIL"
        try {
            if (Test-TcpPort -ip $ip -port 135) { 
                $IsPort135Open = "Pass"
            }
        }
        catch {
            $IsPort135Open = $Error[0].Exception.InnerException.Message
        }

        # test SQL Connection has sysadmin role
        $IsSQLSysAdmin = "FAIL"
        if ($IsSqlPortOpen -eq "Pass")
        {
            Write-Verbose "Testing sysadmin rights in SQL Server ..."
            $SqlCmdArgs = @{
                ServerInstance = $InstanceName
                Query = "select is_srvrolemember('sysadmin') as IsSysAdmin"
                IncludeSqlUserErrors = $true
                ErrorAction = 'SilentlyContinue'
                ErrorVariable = 'SQLError'
            }
            if (-not [string]::IsNullOrEmpty($UserName)) {
                $SqlCmdArgs += @{
                    UserName = $UserName
                    Password = $Password 
                }
            }

            try {
                if ((Invoke-Sqlcmd @SqlCmdArgs).IsSysAdmin -eq 1) {
                    $IsSQLSysAdmin = "Pass"
                }
            }
            catch {
                if (-not [string]::IsNullOrEmpty($Error[0].Exception.InnerException.Message)) 
                {
                    $IsSQLSysAdmin = $Error[0].Exception.InnerException.Message
                }
            }
            # let's catch the uncatcheable
            if (-not [string]::IsNullOrEmpty($SQLError))
            {
                $IsSQLSysAdmin = $SQLError.Exception.Message
            }        
        }

        # test Windows connection is in local admins group
        # TODO: Convert this test so that WinRM is not used. WinRM is not a requirement for Sentry One so it needs to work without it        
        Write-Verbose "Testing is Windows Local Admin using WinRM ..."
        $IsLocalAdmin = "FAIL"
        try {
            $IsLocalAdmin = Invoke-Command -ComputerName $ServerName -ErrorVariable LocalAdminError -ErrorAction SilentlyContinue {
                ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
            }
            if ($IsLocalAdmin) {
                $IsLocalAdmin = "Pass"
            }
        }
        catch
        {
            $IsLocalAdmin = $Error[0].Exception.Message
        }

        # let's catch the uncatcheable
        if (-not [string]::IsNullOrEmpty($LocalAdminError))
        {
            $IsLocalAdmin = $LocalAdminError
        }

        # test WMI connection
        
        if ($IsSqlPortOpen -eq "Pass")
        {        
            Write-Verbose "Testing WMI Connection ..."
            $WMITest = "FAIL"
            try {
                if (-not ([string]::IsNullOrEmpty((Get-WmiObject -class Win32_OperatingSystem -computername $ServerName).Caption)))
                {
                    $WMITest = "Pass"
                }
            }
            catch
            {
                $WMITest = $Error[0].Exception.Message
            }
        }
        # test perfmon
        if ($IsSqlPortOpen -eq "Pass")
        {
            Write-Verbose "Testing Perfmon Counters (takes a while) ..."
            $PerfmonTest = "FAIL"
            try {
                if(((get-counter -ListSet Processor -ComputerName $ServerName -ErrorAction SilentlyContinue -ErrorVariable PerfmonError).Counter.Count) -gt 0)
                {
                    $PerfmonTest = "Pass"
                }
            }
            catch{
                $PerfmonTest = $Error[0].Exception.Message
            }
            # let's catch the uncatcheable
            if (-not [string]::IsNullOrEmpty($PerfmonError))
            {
                $PerfmonTest = $PerfmonError
            }
        }
        $SentryOneMode = "Not monitored"
        if (
            ($IsSQLSysadmin -eq "Pass") -and
            ($PerfmonTest -eq "Pass") -and 
            ($IsLocalAdmin -eq "Pass") -and
            ($WMITest -eq "Pass")
        )
        {
            $SentryOneMode = "Full"
        }

        if (
            ($IsSQLSysadmin -eq "Pass") -and
            (($PerfmonTest -ne "Pass") -or
            ($IsLocalAdmin -ne "Pass") -or
            ($WMITest -ne "Pass"))
        )
        {
            $SentryOneMode = "Limited"
        }

        return [PSCustomObject]@{
            ServerName = $ServerName
            InstanceName = $InstanceName
            IpAddress = $ip
            SentryOneMode = $SentryOneMode
            IsSqlPortOpen = $IsSqlPortOpen
            IsPort445Open = $IsPort445Open
            IsPort135Open = $IsPort135Open
            IsSQLSysAdmin = $IsSQLSysAdmin
            IsLocalAdmin = $IsLocalAdmin
            PerfmonTest = $PerfmonTest
            WMITest = $WMITest
        }
    }
}

Function Test-TcpPort 
{
    [cmdletbinding()]
    param (
        $ip,
        $port
    )

    $socket = new-object System.Net.Sockets.TcpClient($ip, $port)
    If($socket.Connected)
    {
        $socket.Close()
        return $true
    } else {
        return $false
    }
}
