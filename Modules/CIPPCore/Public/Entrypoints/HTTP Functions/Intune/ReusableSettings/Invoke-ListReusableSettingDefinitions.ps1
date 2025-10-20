using namespace System.Net

function Invoke-ListReusableSettingDefinitions {
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

    $TenantFilter = $Request.Query.tenantFilter ?? $Request.Body.tenantFilter
    if (-not $TenantFilter) {
        $Message = 'tenantFilter is required'
        Write-LogMessage -Headers $Headers -API $APIName -message $Message -Sev 'Error'
        Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
                StatusCode = [HttpStatusCode]::BadRequest
                Body       = @{ Results = $Message }
            })
        return
    }

    $StatusCode = [HttpStatusCode]::OK

    try {
        $Parameters = @{
            '$top' = $Request.Query.top ?? 999
        }
        if ($Request.Query.'$filter') { $Parameters['$filter'] = $Request.Query.'$filter' }
        if ($Request.Query.search) { $Parameters['$search'] = $Request.Query.search }

        $Result = Get-GraphRequestList -TenantFilter $TenantFilter -Endpoint 'deviceManagement/reusableSettings' -Parameters $Parameters -Caller 'Invoke-ListReusableSettingDefinitions'
    } catch {
        $ErrorMessage = Get-CippException -Exception $_
        Write-LogMessage -Headers $Headers -API $APIName -tenant $TenantFilter -message "Failed to list reusable setting definitions: $($ErrorMessage.NormalizedError)" -Sev 'Error' -LogData $ErrorMessage
        $Result = @{ Results = $ErrorMessage.NormalizedError }
        $StatusCode = [HttpStatusCode]::Forbidden
    }

    Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
            StatusCode = $StatusCode
            Body       = $Result
        })
}
