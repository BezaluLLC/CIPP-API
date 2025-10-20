using namespace System.Net

function Invoke-AddReusableSettingTemplate {
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

    $DisplayName = $Request.Body.displayName
    $Description = $Request.Body.description
    $DefinitionId = $Request.Body.settingDefinitionId
    $SettingInstancePayload = $Request.Body.settingInstance ?? $Request.Body.settingInstanceJson ?? $Request.Body.RawJson
    $TemplateId = $Request.Body.GUID ?? $Request.Body.id

    if (-not $DisplayName) {
        $Message = 'displayName is required'
        Write-LogMessage -Headers $Headers -API $APIName -message $Message -Sev 'Error'
        Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
                StatusCode = [HttpStatusCode]::BadRequest
                Body       = @{ Results = $Message }
            })
        return
    }

    if (-not $DefinitionId) {
        $Message = 'settingDefinitionId is required'
        Write-LogMessage -Headers $Headers -API $APIName -message $Message -Sev 'Error'
        Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
                StatusCode = [HttpStatusCode]::BadRequest
                Body       = @{ Results = $Message }
            })
        return
    }

    if (-not $SettingInstancePayload) {
        $Message = 'settingInstance payload is required'
        Write-LogMessage -Headers $Headers -API $APIName -message $Message -Sev 'Error'
        Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
                StatusCode = [HttpStatusCode]::BadRequest
                Body       = @{ Results = $Message }
            })
        return
    }

    try {
        if ($SettingInstancePayload -is [string]) {
            $SettingInstance = $SettingInstancePayload | ConvertFrom-Json -Depth 100 -ErrorAction Stop
        } else {
            $SettingInstance = $SettingInstancePayload
        }
    } catch {
        $Message = 'settingInstance must be valid JSON'
        Write-LogMessage -Headers $Headers -API $APIName -message $Message -Sev 'Error'
        Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
                StatusCode = [HttpStatusCode]::BadRequest
                Body       = @{ Results = $Message }
            })
        return
    }

    if (-not $TemplateId) {
        $TemplateId = (New-Guid).Guid
    }

    $TemplateObject = [PSCustomObject]@{
        DisplayName        = $DisplayName
        Description        = $Description
        SettingDefinitionId = $DefinitionId
        SettingInstance    = $SettingInstance
        GUID               = $TemplateId
        LastUpdated        = (Get-Date).ToUniversalTime().ToString('o')
    }

    $Table = Get-CippTable -TableName 'templates'

    try {
        Add-CIPPAzDataTableEntity @Table -Entity @{
            JSON         = ($TemplateObject | ConvertTo-Json -Depth 100)
            RowKey       = $TemplateId
            PartitionKey = 'IntuneReusableSettingTemplate'
        } -Force
        Write-LogMessage -Headers $Headers -API $APIName -message "Stored reusable setting template $DisplayName" -Sev 'Info'
        $Result = "Stored reusable setting template $DisplayName"
        $StatusCode = [HttpStatusCode]::OK
    } catch {
        $ErrorMessage = Get-CippException -Exception $_
        Write-LogMessage -Headers $Headers -API $APIName -message "Failed to store reusable setting template: $($ErrorMessage.NormalizedError)" -Sev 'Error' -LogData $ErrorMessage
        $Result = $ErrorMessage.NormalizedError
        $StatusCode = [HttpStatusCode]::InternalServerError
    }

    Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
            StatusCode = $StatusCode
            Body       = @{ Results = $Result }
        })
}
