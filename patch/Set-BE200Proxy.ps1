param([ValidateSet('Apply','Rollback')][string]$Mode='Apply',[switch]$ValidateOnly)
$ErrorActionPreference='Stop'
$root=$PSScriptRoot
$installRoot='C:\Program Files\Huawei\PCManager'
$target=Join-Path $installRoot 'iphlpapi.dll'
$source=Join-Path $root 'iphlpapi.dll'
$originalHash='4c9501235b9ace2420976564de49c96dee2f2b0ceea4a56bdf6249957a9e03a4'
$serviceOrder=@('HwDistributedMainService','HiConnectivityService')
$prior=@{}
$result=[ordered]@{mode=$Mode;startedAt=(Get-Date).ToString('o');status='starting';target=$target;error=$null;recovery=$null;services=@();signature=$null;moduleLoaded=$false;ipcVerified=$false}
$resultPath=Join-Path $root ('operation-'+(Get-Date -Format 'yyyyMMdd-HHmmss')+'.json')
$candidateInstalled=$false
$stackTouched=$false
$staging=$null
function Get-Sha([string]$Path) {(Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()}
function Stop-Stack {
    foreach($name in $serviceOrder) {
        $service=Get-Service -Name $name
        if($service.Status -ne 'Stopped') {
            if($service.Status -ne 'StopPending') {$service.Stop()}
            $service.WaitForStatus([ServiceProcess.ServiceControllerStatus]::Stopped,[TimeSpan]::FromSeconds(30))
        }
    }
}
function Start-PriorStack {
    foreach($name in @('HiConnectivityService','HwDistributedMainService')) {
        if($prior[$name]) {
            $service=Get-Service -Name $name
            if($service.Status -eq 'Stopped') {$service.Start()}
            $service.WaitForStatus([ServiceProcess.ServiceControllerStatus]::Running,[TimeSpan]::FromSeconds(30))
        }
    }
}
function Remove-ReviewedCandidate {
    if(Test-Path -LiteralPath $target) {
        if((Get-Sha $target) -ne $manifest.candidate_sha256) {throw 'Refusing to remove a DLL whose identity differs.'}
        $archive=Join-Path $root ('removed-'+[guid]::NewGuid().ToString('N')+'.dll')
        # Both paths are explicit files on C:, never recursive. Keep the removed DLL as local evidence.
        Move-Item -LiteralPath $target -Destination $archive -ErrorAction Stop
        $result.removedFile=$archive
    }
}
try {
    $principal=New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if(-not $ValidateOnly -and -not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {throw 'Administrator permission is required for this application-local DLL operation.'}
    $manifest=Get-Content -LiteralPath (Join-Path $root 'manifest.json') -Raw | ConvertFrom-Json
    if($manifest.source_exe_sha256 -ne $originalHash) {throw 'Unexpected original EXE identity in manifest.'}
    if((Get-Sha $source) -ne $manifest.candidate_sha256) {throw 'Candidate DLL differs from reviewed manifest.'}
    $exe=Join-Path $installRoot 'HiConnectivityService.exe'
    if((Get-Sha $exe) -ne $originalHash) {throw 'Exact original service EXE is required.'}
    $signature=Get-AuthenticodeSignature -LiteralPath $exe
    $result.signature=$signature.Status.ToString()
    if($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Subject -notmatch 'Huawei Device Co\., Ltd\.') {throw 'Original Huawei Authenticode signature is not valid.'}
    foreach($name in $serviceOrder) {
        $config=Get-CimInstance Win32_Service -Filter ("Name='"+$name+"'")
        $expected=Join-Path $installRoot ($name+'.exe')
        if($config.PathName.Trim('"') -ne $expected) {throw ('Unexpected service executable: '+$name)}
        $prior[$name]=$config.State -eq 'Running'
        $result.services+=@{name=$name;beforePid=$config.ProcessId;wasRunning=$prior[$name]}
    }
    if($Mode -eq 'Apply') {
        if(Test-Path -LiteralPath $target) {throw 'An application-local IP Helper DLL already exists. Inspect it before applying; no file was overwritten.'}
        if(-not $prior['HiConnectivityService'] -or -not $prior['HwDistributedMainService']) {throw 'Both Huawei connection services must be running before this test.'}
        if((Get-Sha 'C:\Windows\System32\iphlpapi.dll') -ne $manifest.system_iphlpapi_sha256) {throw 'System IP Helper changed since the export/ABI checks; rebuild and revalidate first.'}
        $validation=Get-Content -LiteralPath (Join-Path $root 'validation.json') -Raw | ConvertFrom-Json
        if(-not $validation.passed -or $validation.candidate_sha256 -ne $manifest.candidate_sha256) {throw 'Matching native validation results are required.'}
        $audit=Get-Content -LiteralPath (Join-Path $root 'independent-audit.json') -Raw | ConvertFrom-Json
        if(-not $audit.passed -or $audit.candidate_sha256 -ne $manifest.candidate_sha256) {throw 'Matching independent audit is required.'}
        if($ValidateOnly) {$result.status='validated-no-changes'; return}
        $stackTouched=$true
        Stop-Stack
        $staging=Join-Path $installRoot ('be200-proxy-'+[guid]::NewGuid().ToString('N')+'.tmp')
        [IO.File]::Copy($source,$staging,$false)
        if((Get-Sha $staging) -ne $manifest.candidate_sha256) {throw 'Staged DLL verification failed.'}
        [IO.File]::Move($staging,$target)
        $candidateInstalled=$true
        $clientLaunchCutoff=Get-Date
        $result.ipcWindowStartedAt=$clientLaunchCutoff.ToString('o')
        Start-PriorStack
        Start-Sleep -Seconds 3
        $server=Get-CimInstance Win32_Service -Filter "Name='HiConnectivityService'"
        $client=Get-CimInstance Win32_Service -Filter "Name='HwDistributedMainService'"
        if($server.State -ne 'Running' -or $client.State -ne 'Running') {throw 'A connection service exited during verification.'}
        $modules=@((Get-Process -Id $server.ProcessId -ErrorAction Stop).Modules | Where-Object {$_.FileName -eq $target})
        $result.moduleLoaded=$modules.Count -eq 1
        if(-not $result.moduleLoaded) {throw 'The connection service did not load the reviewed application-local DLL.'}
        $clientLog='C:\ProgramData\Comms\PCManager\log\admin\HwDistributedMainService.log'
        $lines=@(Get-Content -LiteralPath $clientLog -Tail 6000 | Where-Object {
            if($_ -match '^(\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3}) (\d+) ') {
                $stamp=$matches[1]
                $linePid=[uint32]$matches[2]
                $time=[DateTime]::ParseExact(($clientLaunchCutoff.Year.ToString()+'-'+$stamp),'yyyy-MM-dd HH:mm:ss,fff',[Globalization.CultureInfo]::InvariantCulture)
                $linePid -eq $client.ProcessId -and $time -ge $clientLaunchCutoff
            }
        })
        $result.ipcVerified=@($lines | Where-Object {$_ -match 'RegistBtExceptionEventCallback ret: 0|is Bt Enabled ret: 1'}).Count -gt 0
        if(-not $result.ipcVerified) {throw 'Fresh client IPC success was not established in startup logs.'}
        if((Get-Sha $exe) -ne $originalHash -or (Get-AuthenticodeSignature -LiteralPath $exe).Status -ne 'Valid') {throw 'Original signed service identity changed unexpectedly.'}
        $result.serverPid=$server.ProcessId
        $result.clientPid=$client.ProcessId
        $result.installedHash=Get-Sha $target
        $result.status='applied-service-and-ipc-verified-phone-test-required'
    } else {
        if($ValidateOnly) {$result.status='validated-no-changes'; return}
        if(-not (Test-Path -LiteralPath $target)) {$result.status='already-absent'}
        else {
            if((Get-Sha $target) -ne $manifest.candidate_sha256) {throw 'Installed DLL is a different file; refusing rollback.'}
            $stackTouched=$true
            Stop-Stack
            Remove-ReviewedCandidate
            Start-PriorStack
            $result.status='removed-original-stack-restored'
        }
    }
} catch {
    $result.status='failed'
    $result.error=$_.Exception.Message
    if($stackTouched) {
        try {
            Stop-Stack
            if($Mode -eq 'Apply' -and $candidateInstalled) {Remove-ReviewedCandidate}
            Start-PriorStack
            $result.recovery='Original signed EXE retained; previous service running states restored. New DLL removed if this operation installed it.'
        } catch {$result.recovery='Recovery needs attention: '+$_.Exception.Message}
    }
} finally {
    if($staging -and (Test-Path -LiteralPath $staging)) {Remove-Item -LiteralPath $staging -Force -ErrorAction SilentlyContinue}
    $result.finishedAt=(Get-Date).ToString('o')
    $result | ConvertTo-Json -Depth 6 | Out-File -LiteralPath $resultPath -Encoding utf8
}
if($result.status -eq 'failed') {exit 1}
