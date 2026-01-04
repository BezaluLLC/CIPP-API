function Invoke-AddIntuneReusableSettingTemplate {
    <#
    .FUNCTIONALITY
        Entrypoint,AnyTenant
    .ROLE
        Endpoint.MEM.ReadWrite
    #>
    [CmdletBinding()]
    param($Request, $TriggerMetadata)

    $APIName = $Request.Params.CIPPEndpoint
    $Headers = $Request.Headers

    $GUID = $Request.Body.GUID ?? (New-Guid).GUID

    function Remove-ReusableSettingMetadata {
        param($InputObject)

        if ($null -eq $InputObject) { return $null }

        if ($InputObject -is [System.Collections.IEnumerable] -and $InputObject -isnot [string]) {
            $CleanArray = @()
            foreach ($item in $InputObject) { $CleanArray += Remove-ReusableSettingMetadata -InputObject $item }
            return $CleanArray
        }

        if ($InputObject -is [psobject]) {
            $Output = [ordered]@{}
            foreach ($prop in $InputObject.PSObject.Properties) {
                if ($null -eq $prop.Value) { continue }
                if ($prop.Name -in @('id','createdDateTime','lastModifiedDateTime','version','@odata.context','@odata.etag','referencingConfigurationPolicyCount','settingInstanceTemplateReference','settingValueTemplateReference','auditRuleInformation')) { continue }
                $Output[$prop.Name] = Remove-ReusableSettingMetadata -InputObject $prop.Value
            }
            return [pscustomobject]$Output
        }

        return $InputObject
    }

    try {
        $displayName = $Request.Body.displayName ?? $Request.Body.DisplayName ?? $Request.Body.displayname
        if (-not $displayName) { throw 'You must enter a displayName' }

        $description = $Request.Body.description ?? $Request.Body.Description
        $rawJsonInput = $Request.Body.rawJSON ?? $Request.Body.RawJSON ?? $Request.Body.json

        if (-not $rawJsonInput) { throw 'You must provide RawJSON for the reusable setting' }

        try {
            $parsed = $rawJsonInput | ConvertFrom-Json -Depth 100 -ErrorAction Stop
        } catch {
            throw "RawJSON is not valid JSON: $($_.Exception.Message)"
        }

        # Deep-clean Graph metadata and nulls so the JSON remains reusable and compact
        $cleanParsed = Remove-ReusableSettingMetadata -InputObject $parsed
        $sanitizedJson = $cleanParsed | ConvertTo-Json -Depth 100 -Compress

        $entity = [pscustomobject]@{
            DisplayName = $displayName
            Description = $description
            RawJSON     = $sanitizedJson
            GUID        = $GUID
        } | ConvertTo-Json -Depth 100 -Compress

        $Table = Get-CippTable -tablename 'templates'
        $Table.Force = $true
        Add-CIPPAzDataTableEntity @Table -Force -Entity @{
            JSON         = "$entity"
            RowKey       = "$GUID"
            PartitionKey = 'IntuneReusableSettingTemplate'
            GUID         = "$GUID"
        }

        Write-LogMessage -headers $Headers -API $APINAME -message "Created Intune reusable setting template named $displayName with GUID $GUID" -Sev 'Debug'
        $body = [pscustomobject]@{ Results = 'Successfully added reusable setting template' }
        $StatusCode = [System.Net.HttpStatusCode]::OK
    } catch {
        $ErrorMessage = Get-CippException -Exception $_
        Write-LogMessage -headers $Headers -API $APINAME -message "Reusable Settings Template creation failed: $($ErrorMessage.NormalizedError)" -Sev 'Error' -LogData $ErrorMessage
        $body = [pscustomobject]@{ Results = "Reusable Settings Template creation failed: $($ErrorMessage.NormalizedError)" }
        $StatusCode = [System.Net.HttpStatusCode]::InternalServerError
    }

    return ([HttpResponseContext]@{
            StatusCode = $StatusCode
            Body       = $body
        })
}
