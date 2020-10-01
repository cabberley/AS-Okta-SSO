﻿<#  
    Title:          Okta Data Connector
    Language:       PowerShell
    Version:        2.1.0
    Author(s):      Microsoft - Chris Abberley
    Last Modified:  8/18/2020
    Comment:        Changes from Version 2.0.0 to 2.1.0
                    -Added fix for issue: ACN_CD_OktaIssue925
                    -Modified Event log tracking to use OKTA Next URI to fix small quantity of duplicates that were occurring
                    -Fixed Total Record Counter 
                    Fixes for the following issues with Version 1
                    -Potential Data loss due to code not processing linked pages
                    -Potential Data loss due to variations in execution of Triggers
                    -Corrected Timestamp field for Okta logs which use "published"
                    Clean up of code
                    -removed timer interval which is no longer required
                    -standardised code lode logging information messages


    DESCRIPTION
    This Function App calls the Okta System Log API (https://developer.okta.com/docs/reference/api/system-log/) to pull the Okta System logs. The response from the Okta API is recieved in JSON format. 
    This function will build the signature and authorization header needed to post the data to the Log Analytics workspace via the HTTP Data Connector API. 
    The Function App will post the Okta logs to the Okta_CL table in the Log Analytics workspace.

    NOTES:
    Suggested timing trigger of no less than 10 minutes. Be aware that Azure Functions have a runtime execution time limit of 5 mins by default, at which point it will terminate the function.
    Function Timeout has been changed to 10 minutes and Function will try to gracefully exit after 9 minutes.
    If you reduce the timeout to less than 10 minutes this you may get some duplicate records in your Azure Logs as it will not commit the last datetime until the records are written to Azure logs.
#>

# Input bindings are passed in via param block.
param($Timer)
# Get the current universal time in the default string format
$currentUTCtime = (Get-Date).ToUniversalTime()
# The 'IsPastDue' porperty is 'true' when the current function invocation is later than scheduled.
#Get Telemetry workspace Environemnt Information
$TelemetryId = $env:TelemetryWorkspace
$TelemetryKey = $env:TelemetryWorkspaceKey
$TelemetryTable = "OktaSSOLogsTEST"
$Telemetry = @{}
if ($TelemetryId) { 
    $Telemetry += @{'TriggeredTime' = $currentUTCtime}
}
Else {
    if ($Timer.IsPastDue) {
        Write-Host "OKTASSO: Azure Function triggered at: $currentUTCtime - timer is running late!"
    }
    else{
        Write-Host "OKTASSO: Azure Function triggered at: $currentUTCtime - timer is ontime!"
    }
}
#Load PowerSHell Modules
Import-Module AzureCore -Force

#Azure Function State management between Executions
$AzureWebJobsStorage =$env:AzureWebJobsStorage  #Storage Account to use for table to maintain state for log queries between executions
$Tablename = "OKTA"      #This is NOT the Azure Sentinel Log Analytics Table #Tablename which will hold datetime record between executions
$TotalRecordCount = 0
$ConfigName = 'Okta1' 

$Telemetry += @{'OktaConfig' = $ConfigName}

# variables needed for the Okta API request
$apiToken = $env:apiToken  #Okta API Token required to authenticate to the Okta API
$uri = $env:uri  #Your unique FQDN end point for accessing OKTA API data
$StartDate = [System.DateTime]::UtcNow.ToString("yyyy-MM-ddT00:00:00.000Z") # set default fallback start time to 0:00 UTC today

# Define the Log Analytics Workspace ID and Key and Custom Table Name
$customerId = $env:workspaceId
$sharedKey =  $env:workspaceKey
$LogType = "Okta"       #This is the Name for the Azure Sentinel Log Analytics Table
$TimeStampField = "published"

$Telemetry += @{'LATablename' = $LogType}
$Telemetry += @{'LAWorkspace' = $customerId}

# Retrieve Timestamp from last records received from Okta 
# Check if Tabale has already been created and if not create it to maintain state between executions of Function
$storage =  New-AzStorageContext -ConnectionString $AzureWebJobsStorage
$StorageTable = Get-AzStorageTable -Name $Tablename -Context $Storage -ErrorAction Ignore
if($null -eq $StorageTable.Name){  
    $result = New-AzStorageTable -Name $Tablename -Context $storage
    $Table = (Get-AzStorageTable -Name $Tablename -Context $storage.Context).cloudTable
    $uri = "$uri$($StartDate)&limit=1000"
    $result = Add-AzTableRow -table $Table -PartitionKey "part1" -RowKey $ConfigName -property @{"uri"=$uri} -UpdateExisting
}
Else {
    $Table = (Get-AzStorageTable -Name $Tablename -Context $storage.Context).cloudTable
}
# retrieve the row
$row = Get-azTableRow -table $Table -partitionKey "part1" -RowKey $ConfigName -ErrorAction Ignore
if($null -eq $row.uri){
    $uri = "$uri$($StartDate)&limit=1000"
    $result = Add-AzTableRow -table $Table -PartitionKey "part1" -RowKey $ConfigName -property @{"uri"=$uri} -UpdateExisting
    $row = Get-azTableRow -table $Table -partitionKey "part1" -RowKey $ConfigName -ErrorAction Ignore
}
$uri = $row.uri

#Setup uri Headers for requests to OKta
$headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
$headers.Add("Content-Type", "application/json")
$headers.Add("User-Agent", "AzureFunction")
$headers.Add("Authorization", "SSWS $apiToken")
$headers.Add("Accept-Encoding", "gzip, br")

# begin looping through responses from OKTA until we get all available records
$exitDoUntil = $false
$TelemetryUri = @()
do {
    $body = $null
    $uriself = $uri
    if($uri.length -gt 0){
        $response = Invoke-WebRequest -uri $uri  -Method 'GET' -Headers $headers -Body $body
        $TelUri = $uri
    }
    if($response.headers.Keys -contains "link"){
        $uritemp = $response.headers.link.split(",;")
        $uritemp = $uritemp.split(";")
        $uri = $uritemp[2] -replace "<|>", ""
    }
    ELSE{
        $exitDoUntil = $true
    }
    if($uri -ne $uriself){
        $responseObj = (ConvertFrom-Json $response.content)
        $responseCount = $responseObj.count
        $TotalRecordCount= $TotalRecordCount + $responseCount
        
        #ACN_CD_OktaIssue925
        $domain = [regex]::matches($uri, 'https:\/\/([\w\.\-]+)\/').captures.groups[1].value
        #$responseObj = $response | ConvertFrom-Json
        $responseObj | Add-Member -MemberType NoteProperty -Name "domain" -Value $domain
        $json = $responseObj | ConvertTo-Json -Depth 5
                
        Function new-BuildSignature ($customerId, $sharedKey, $date, $contentLength, $method, $contentType, $resource)
        {
            $xHeaders = "x-ms-date:" + $date
            $stringToHash = $method + "`n" + $contentLength + "`n" + $contentType + "`n" + $xHeaders + "`n" + $resource
            $bytesToHash = [Text.Encoding]::UTF8.GetBytes($stringToHash)
            $keyBytes = [Convert]::FromBase64String($sharedKey)
            $sha256 = New-Object System.Security.Cryptography.HMACSHA256
            $sha256.Key = $keyBytes
            $calculatedHash = $sha256.ComputeHash($bytesToHash)
            $encodedHash = [Convert]::ToBase64String($calculatedHash)
            $authorization = 'SharedKey {0}:{1}' -f $customerId,$encodedHash
            return $authorization
        }
        $method="POST"
        $contentType = "application/json"
        $resource = "/api/logs"
        $rfc1123date = [DateTime]::UtcNow.ToString("r")
        
        $body = ([System.Text.Encoding]::UTF8.GetBytes($json))
        $contentLength = $body.Length
        $signature = new-BuildSignature `
            -customerId $customerId `
            -sharedKey $sharedKey `
            -date $rfc1123date `
            -contentLength $contentLength `
            -method $method `
            -contentType $contentType `
            -resource $resource
        $LAuri = "https://" + $customerId + ".ods.opinsights.azure.com" + $resource + "?api-version=2016-04-01"
        $LAheaders = @{
            "Authorization" = $signature;
            "Log-Type" = $logType;
            "x-ms-date" = $rfc1123date;
            "time-generated-field" = $TimeStampField
        }
        $result = Invoke-WebRequest -Uri $LAuri -Method $method -ContentType $contentType -Headers $LAheaders -Body $body -UseBasicParsing

        $TelemetryUri += 'Uri: ' + $TelUri + '; RecordsRetrieved: ' + $responseCount + '; PostToLogAnaResult: ' + $result + '; PostSize: ' + $contentLength
        #update State table for next time we execute function
        #store details in function storage table to retrieve next time function runs 
        $null = Add-AzTableRow -table $Table -PartitionKey "part1" -RowKey $ConfigName -property @{"uri"=$uri} -UpdateExisting
    }
    else{
        $exitDoUntil = $true
    }
    #check on time running, Azure Function default timeout is 5 minutes, if we are getting close exit function cleanly now and get more records next execution
    IF((new-timespan -Start $currentUTCtime -end ((Get-Date).ToUniversalTime())).TotalSeconds -gt 500){$exitDoUntil = $true} 
}until($exitDoUntil) 

if($TotalRecordCount -lt 1){
    if ($TelemetryId) { 
        $Telemetry += @{'TriggerStatus' = "No new Okta logs since $StartDate are available as of $currentUTCtime"}
    }
    Else{
        Write-Output "OKTASSO: No new Okta logs since $StartDate are available as of $currentUTCtime"
    }
}
# Write an information log with the current time.
$finishtime = ((Get-Date).ToUniversalTime())
if ($TelemetryId) { 
    $Telemetry += @{'OktaAPIRequests' = $TelemetryUri}
    $Telemetry += @{'TriggerStatus' = "Azure function completed Records Retrieved"}
    $Telemetry += @{"CompletedTime" = $finishtime}
    $Telemetry += @{'TotalRecordsRetrieved' = $totalrecordCount}
    $null = Invoke-LogAnalyticsData -CustomerId $TelemetryId -SharedKey $TelemetryKey -Body (ConvertTo-Json $Telemetry -Depth 10) -LogTable $TelemetryTable -TimeStampField '' -ResourceId '' 
}
Else{
    Write-Output "OktaSSO: Azure function completed, started: $currentUTCtime, Completed: $finishtime, Processed: $totalrecordcount records"
}

