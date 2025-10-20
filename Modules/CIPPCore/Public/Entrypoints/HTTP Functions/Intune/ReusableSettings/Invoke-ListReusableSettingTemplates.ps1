using namespace System.Net

function Invoke-ListReusableSettingTemplates {
    <#
    .FUNCTIONALITY
        Entrypoint
    .ROLE
        Endpoint.MEM.Read
    #>
    [CmdletBinding()]
    param($Request, $TriggerMetadata)

    $APIName = $Request.Params.CIPPEndpoint
    $Headers = $Request.Headers
    Write-LogMessage -Headers $Headers -API $APIName -message 'Accessed this API' -Sev 'Debug'

    $TemplateId = $Request.Query.id ?? $Request.Query.GUID
    $View = $Request.Query.View

    $Table = Get-CippTable -TableName 'templates'

    try {
        $Filter = "PartitionKey eq 'IntuneReusableSettingTemplate'"
        if ($TemplateId) {
            $Filter = "$Filter and RowKey eq '$TemplateId'"
        }

        $Rows = Get-CIPPAzDataTableEntity @Table -Filter $Filter

        if (-not $Rows) {
            $Result = @()
        } else {
            $Result = if ($View) {
                $Rows | ForEach-Object {
                    try {
                        $Json = $_.JSON | ConvertFrom-Json -Depth 100
                        $Json
                    } catch {
                        $null
                    }
                } | Where-Object { $_ }
            } else {
                $Rows.JSON | ForEach-Object { try { ConvertFrom-Json -InputObject $_ -Depth 100 } catch { $null } }
            }
        }

        $StatusCode = [HttpStatusCode]::OK
    } catch {
        $ErrorMessage = Get-CippException -Exception $_
        Write-LogMessage -Headers $Headers -API $APIName -message "Failed to list reusable setting templates: $($ErrorMessage.NormalizedError)" -Sev 'Error' -LogData $ErrorMessage
        $Result = @{ Results = $ErrorMessage.NormalizedError }
        $StatusCode = [HttpStatusCode]::InternalServerError
    }

    Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
            StatusCode = $StatusCode
            Body       = $Result
        })
}
