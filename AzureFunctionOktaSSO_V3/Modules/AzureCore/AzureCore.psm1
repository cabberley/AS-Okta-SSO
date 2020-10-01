###Modules need by functions
Import-Module AzTable

Function confirm-aztable {
    param(
        $AzureWebJobsStorage,
        $TableName
    )
    $Storage = New-AzStorageContext -ConnectionString $AzureWebJobsStorage
    $StorageTable = Get-AzStorageTable -Name $Tablename -Context $Storage -ErrorAction Ignore
    if ($null -eq $StorageTable.Name) {  
        $null = New-AzStorageTable -Name $TableName -Context $Storage
        $Table = (Get-AzStorageTable -Name $TableName -Context $Storage.Context).cloudTable
    }
    Else {
        $Table = (Get-AzStorageTable -Name $Tablename -Context $Storage.Context).cloudTable
    }
    Return $Table
}
Function New-BuildSignature {
    #Builds Signature HASH required by Log Analyitcs to Authenticate for ingestion
    param(
        $customerId, 
        $sharedKey, 
        $date, 
        $contentLength, 
        $method, 
        $contentType, 
        $resource )
    
    $xHeaders = "x-ms-date:" + $date
    $stringToHash = $method + "`n" + $contentLength + "`n" + $contentType + "`n" + $xHeaders + "`n" + $resource
    $bytesToHash = [Text.Encoding]::UTF8.GetBytes($stringToHash)
    $keyBytes = [Convert]::FromBase64String($sharedKey)
    $sha256 = New-Object System.Security.Cryptography.HMACSHA256
    $sha256.Key = $keyBytes
    $calculatedHash = $sha256.ComputeHash($bytesToHash)
    $encodedHash = [Convert]::ToBase64String($calculatedHash)
    $authorization = 'SharedKey {0}:{1}' -f $customerId, $encodedHash
    return $authorization
}
        
# Function to create and post the request
Function Invoke-LogAnalyticsData {
    #Function to send Log Data to the Log Analytics workspace
    Param( 
        $CustomerId, 
        $SharedKey, 
        $Body, 
        $LogTable, 
        $TimeStampField,
        $resourceId)

    $method = "POST"
    $contentType = "application/json"
    $resource = "/api/logs"
    $rfc1123date = [DateTime]::UtcNow.ToString("r")
    $contentLength = $Body.Length
    $signature = New-BuildSignature `
        -customerId $CustomerId `
        -sharedKey $SharedKey `
        -date $rfc1123date `
        -contentLength $contentLength `
        -method $method `
        -contentType $contentType `
        -resource $resource
    #Azure commercial Cloud
    $uri = "https://" + $CustomerId + ".ods.opinsights.azure.com" + $resource + "?api-version=2016-04-01"
    #Azure US Government Cloud
    #$uri = 'https://' + $CustomerId + '.ods.opinsights.azure.us' + $resource + '?api-version=2016-04-01'
    #China .ods.opinsights.azure.cn
    
    $headers1 = @{
        "Authorization"        = $signature;
        "Log-Type"             = $LogTable;
        "x-ms-date"            = $rfc1123date;
        "x-ms-AzureResourceId" = $resourceId;
        "time-generated-field" = $TimeStampField;
    }  
    $null = Invoke-WebRequest -Uri $uri -Method $method -ContentType $contentType -Headers $headers1 -Body $Body 
} 


Function Send-LogAnalyticsData {
    #Function to verify and if required break down into less than 30MB chunks for sending to Log Analytics
    Param( 
        $customerId, 
        $sharedKey, 
        $EventLogs, 
        $CustomLogName, 
        $TimeStampField,
        $resourceId)

    $EventLogs = ConvertFrom-Json $EventLogs
    $tempDataSize = 0
    $count = $eventlogs.count
    $i = 0
    $First = 0
    do {
        #Get cumulative Data size
        $tempDatasize += (ConvertTo-Json $eventlogs[$i]).length
        #Check if we are getting close to max of 30MB for HTTP API and send batch if we are
        if ($tempDataSize -gt 22MB) {
            $Body = (ConvertTo-Json $eventlogs[$first..$i])
            #Send batch to Log Analaytics
            $null = Invoke-LogAnalyticsData -CustomerId $customerId -SharedKey $sharedKey -Body $Body -LogTable $CustomLogName -TimeStampField $TimeStampField -ResourceId $resourceId
            #reset Vars for next chunk
            $First = $i + 1
            $tempdatasize = 0
        }
        $i ++
    }while ($count -gt $i)
    #send the remaining records to Log Analytics 
    $body = (ConvertTo-Json $eventlogs[$first..$i])
    $null = Invoke-LogAnalyticsData -CustomerId $customerId -SharedKey $sharedKey -Body $Body -LogTable $CustomLogName -TimeStampField $TimeStampField -ResourceId $resourceId
}

Export-ModuleMember -Function Invoke-LogAnalyticsData
Export-ModuleMember -Function confirm-aztable
Export-ModuleMember -Function Send-LogAnalyticsData 

