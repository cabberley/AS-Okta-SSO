﻿<#  
    Title:          Okta Data Connector
    Language:       PowerShell
    Version:        2.0
    Author(s):      Microsoft - Chris Abberley
    Last Modified:  7/22/2020
    Comment:        Fixes for the following issues with Version 1
                    -Potential Data loss due to code not processing linked pages
                    -Potential Data loss due to variations in execution of Triggers
                    -Corrected Timestamp field for Okta logs which use "published"
                    Clean up of code
                    -removed timer interval which is no longer required
                    -standardised code lode logging information messages


    DESCRIPTION
    This Function App calls the Okta System Log API (https://developer.okta.com/docs/reference/api/system-log/) to pull the Okta System logs. The response from the Okta API is recieved in JSON format. This function will build the signature and authorization header 
    needed to post the data to the Log Analytics workspace via the HTTP Data Connector API. The Function App will post the Okta logs to the Okta_CL table in the Log Analytics workspace.
#>

# Input bindings are passed in via param block.
param($Timer)
# Get the current universal time in the default string format
$currentUTCtime = (Get-Date).ToUniversalTime()
# The 'IsPastDue' porperty is 'true' when the current function invocation is later than scheduled.
if ($Timer.IsPastDue) {
    Write-Host "OKTASSO: Azure Function triggered at: $currentUTCtime - timer is running late!"
}
else{
    Write-Host "OKTASSO: Azure Function triggered at: $currentUTCtime - timer is ontime!"

}
#Azure Function State management between Executions
$AzureWebJobsStorage =$env:AzureWebJobsStorage  #Storage Account to use for table to maintain state for log queries between executions
$Tablename = "OKTA"                             #Tablename which will hold datetime record between executions
$TotalRecordCount = 0
$responseDate = $null

# variables needed for the Okta API request
$apiToken = $env:apiToken
$uri = $env:uri
$StartDate = [System.DateTime]::UtcNow.ToString("yyyy-MM-ddT00:00:00.000Z") # set default fallback start time to 0:00 UTC today

# Define the Log Analytics Workspace ID and Key and Custom Table Name
$customerId = $env:workspaceId
$sharedKey =  $env:workspaceKey
$LogType = "Okta"
$TimeStampField = "published"

# Retrieve Timestamp from last records received from Okta 
# Check if Tabale has already been created and if not create it to maintain state between executions of Function
$storage =  New-AzStorageContext -ConnectionString $AzureWebJobsStorage
$StorageTable = Get-AzStorageTable -Name $Tablename -Context $Storage -ErrorAction Ignore
if($null -eq $StorageTable.Name){  
    $result = New-AzStorageTable -Name $Tablename -Context $storage
    $Table = (Get-AzStorageTable -Name $Tablename -Context $storage.Context).cloudTable
    $result = Add-AzTableRow -table $Table -PartitionKey "part1" -RowKey $apiToken -property @{"StartTime"=$StartDate} -UpdateExisting
}
Else {
    $Table = (Get-AzStorageTable -Name $Tablename -Context $storage.Context).cloudTable
}
# retrieve the row
$row = Get-azTableRow -table $Table -partitionKey "part1" -RowKey $apiToken -ErrorAction Ignore
if($null -eq $row.StartTime){
    $result = Add-AzTableRow -table $Table -PartitionKey "part1" -RowKey $apiToken -property @{"StartTime"=$StartDate} -UpdateExisting
    $row = Get-azTableRow -table $Table -partitionKey "part1" -RowKey $apiToken -ErrorAction Ignore
}
$StartDate =  $row.StartTime
if($null -eq $StartDate){$StartDate =  [System.DateTime]::UtcNow.ToString("yyyy-MM-ddT00:00:00.000Z") }



#Setup uri Headers for requests to OKta
$headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
$headers.Add("Content-Type", "application/json")
$headers.Add("User-Agent", "AzureFunction")
$headers.Add("Authorization", "SSWS $apiToken")

#set starting uri for requests from Okta
$uri = "$uri$($startDate)&limit=1000"

# begin looping through responses from OKTA until we get all available records

do {
    $exitDoUntil =0
    $body = $null
    $response = Invoke-WebRequest -uri $uri  -Method 'GET' -Headers $headers -Body $body
    if($response.headers.Keys -contains "link"){
        #got valid Link Header in Response
        $uri = $response.headers.link.split(",|;")[2] -replace "<|>", ""
        $responseCount = (ConvertFrom-Json $response.content).count
        if($responseCount -gt 0){
            $TotalRecordCount= $TotalRecordCount + $responseCount
            $exitDoUntil =1
            $responseDate = ([datetime]::parseexact(($response.headers.date),"ddd, dd MMM yyyy HH:mm:ss Z",$null)).ToString('yyyy-MM-ddThh:mm:ssZ')
            #we have at least 1 record
            # Function to create the authorization signature
            Function Build-Signature ($customerId, $sharedKey, $date, $contentLength, $method, $contentType, $resource)
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

            $contentType = "application/json"
            $resource = "/api/logs"
            $rfc1123date = [DateTime]::UtcNow.ToString("r")
            $body = ([System.Text.Encoding]::UTF8.GetBytes($response))
            $contentLength = $body.Length
            $signature = Build-Signature `
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
                "time-generated-field" = $TimeStampField;
            }
            $result = Invoke-WebRequest -Uri $LAuri -Method "POST" -ContentType $contentType -Headers $LAheaders -Body $body -UseBasicParsing
        }
        else{
        if($TotalRecordCount -lt 1){
            Write-Output "OKTASSO: No new Okta logs are available as of $startDate"
            }
        }
    }
} until($exitDoUntil -eq 0) 
#update State table for next time we execute function
#store details in function storage table to retrieve next time function runs 
if($responseDate.length -gt 0){
    $result = Add-AzTableRow -table $Table -PartitionKey "part1" -RowKey $apiToken -property @{"StartTime"=$responseDate} -UpdateExisting
}
# Write an information log with the current time.
$finishtime = ((Get-Date).ToUniversalTime())
Write-Output "OktaSSO: function ran using, started: $currentUTCtime, Completed: $finishtime, Processed: $totalrecordcount records"
