using namespace System.Net

function Invoke-RemoveReusableSettingTemplate {
    <#
    .FUNCTIONALITY
        Entrypoint
    .ROLE
        Endpoint.MEM.ReadWrite
    #>
    [CmdletBinding()]
    param($Request, $TriggerMetadata)

    $APIName = $Request.Params.CIPPEndpoint
    $Headers = $Request.Headers
    Write-LogMessage -Headers $Headers -API $APIName -message 'Accessed this API' -Sev 'Debug'

    $TemplateId = $Request.Body.ID ?? $Request.Query.ID ?? $Request.Body.GUID ?? $Request.Query.GUID
    if (-not $TemplateId) {
        $Message = 'Template ID is required'
        Write-LogMessage -Headers $Headers -API $APIName -message $Message -Sev 'Error'
        Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
                StatusCode = [HttpStatusCode]::BadRequest
                Body       = @{ Results = $Message }
            })
        return
    }

    try {
        $Table = Get-CippTable -TableName 'templates'
        $Filter = "PartitionKey eq 'IntuneReusableSettingTemplate' and RowKey eq '$TemplateId'"
        $Entity = Get-CIPPAzDataTableEntity @Table -Filter $Filter -Property PartitionKey, RowKey
        if ($Entity) {
            Remove-AzDataTableEntity -Force @Table -Entity $Entity
        }
        Write-LogMessage -Headers $Headers -API $APIName -message "Removed reusable setting template $TemplateId" -Sev 'Info'
        $Result = "Removed reusable setting template $TemplateId"
        $StatusCode = [HttpStatusCode]::OK
    } catch {
        $ErrorMessage = Get-CippException -Exception $_
        Write-LogMessage -Headers $Headers -API $APIName -message "Failed to remove reusable setting template: $($ErrorMessage.NormalizedError)" -Sev 'Error' -LogData $ErrorMessage
        $Result = $ErrorMessage.NormalizedError
        $StatusCode = [HttpStatusCode]::InternalServerError
    }

    Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
            StatusCode = $StatusCode
            Body       = @{ Results = $Result }
        })
}
