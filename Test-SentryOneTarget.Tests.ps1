. .\Test-SentryOneTarget.ps1
$servers = Get-Content .\serverlist.json -Raw -Encoding UTF8 | ConvertFrom-Json

$ValidServerNameOnly = "WISTERIA"
$NamedInstanceSQLAuth = "daffodil\instance_a"
$NamedInstanceWindowsAuth = "daffodil\instance_b"
$UnreacheableServer = "sulphur"

Describe "Validate test json config" {
    It "Should have 4 servers to test with" {
        $servers.targets.Count | Should Be 4
    }
    
}

Describe "Test Full sentry one targets" {
    It "Should validate where json only contains servername" {
        $result = $servers.targets | ? {$_.servername -eq $ValidServerNameOnly} | % { Test-SentryOneTarget $_.ServerName $_.InstanceName $_.UserName $_.Password $_.SQLPort}
        $result.ServerName | Should Be "wisteria"
        $result.InstanceName | Should Be "wisteria"
        $result.IsPort135Open | Should Be $true
        $result.IsPort445Open | Should Be $true
        $result.IsSqlPortOpen | Should Be $true
        $result.IsLocalAdmin | Should Be $true
        $result.IsSQLSysAdmin | Should Be $true
        $result.IpAddress | Should Be "10.0.1.15"
        $result.WMITest | Should Be $true
        $result.PerfmonTest | Should Be $true
    }

    It "Should validate against named instance with SQL Authentication" {
        $result = $servers.targets | ? {$_.InstanceName -eq $NamedInstanceSQLAuth} | % { Test-SentryOneTarget $_.ServerName $_.InstanceName $_.UserName $_.Password $_.SQLPort}
        $result.ServerName | Should Be "daffodil"
        $result.InstanceName | Should Be "daffodil\instance_a"
        $result.IsPort135Open | Should Be $true
        $result.IsPort445Open | Should Be $true
        $result.IsSqlPortOpen | Should Be $true
        $result.IsLocalAdmin | Should Be $true
        $result.IsSQLSysAdmin | Should Be $true
        $result.IpAddress | Should Be "10.0.1.6"
        $result.WMITest | Should Be $true
        $result.PerfmonTest | Should Be $true
    }

    It "Should validate against named instance with Windows Authentication" {
        $result = $servers.targets | ? {$_.InstanceName -eq $NamedInstanceWindowsAuth} | % { Test-SentryOneTarget $_.ServerName $_.InstanceName $_.UserName $_.Password $_.SQLPort}
        $result.ServerName | Should Be "daffodil"
        $result.InstanceName | Should Be "daffodil\instance_b"
        $result.IsPort135Open | Should Be $true
        $result.IsPort445Open | Should Be $true
        $result.IsSqlPortOpen | Should Be $true
        $result.IsLocalAdmin | Should Be $true
        $result.IsSQLSysAdmin | Should Be $true
        $result.IpAddress | Should Be "10.0.1.6"
        $result.WMITest | Should Be $true
        $result.PerfmonTest | Should Be $true
    }
}


Describe "Test Limited Sentry One Targets" {

}

Describe "Unreachable Sentry One Targets" {
    It "Should fail to validate an unreacheable server" {
        try {
            $result = $servers.targets | ? { $_.servername -eq $UnreacheableServer} | % { Test-SentryOneTarget $_.ServerName $_.InstanceName $_.UserName $_.Password $_.SQLPort }
        } catch {
            $Error[0].Exception.InnerException.Message.StartsWith("A connection attempt failed because the connected party did not properly respond after a period of time, or established connection failed because connected host has failed to respond") | Should Be True
        }     
    }
}
