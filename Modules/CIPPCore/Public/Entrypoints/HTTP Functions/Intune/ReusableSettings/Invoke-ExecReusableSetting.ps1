using namespace System.Net

function Invoke-ExecReusableSetting {
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

    $TenantFilter = $Request.Body.tenantFilter ?? $Request.Query.tenantFilter
    $Action = $Request.Body.Action ?? $Request.Query.Action
    $SettingId = $Request.Body.ID ?? $Request.Query.ID

    if (-not $TenantFilter -or -not $SettingId) {
        $Message = 'tenantFilter and ID are required'
        Write-LogMessage -Headers $Headers -API $APIName -message $Message -Sev 'Error'
        Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
                StatusCode = [HttpStatusCode]::BadRequest
                Body       = @{ Results = $Message }
            })
        return
    }

    if (-not $Action) {
        $Action = 'Delete'
    }

    try {
        switch ($Action.ToLowerInvariant()) {
            'delete' {
                $Uri = "https://graph.microsoft.com/beta/deviceManagement/reusablePolicySettings('$SettingId')"
                $null = New-GraphPOSTRequest -Uri $Uri -tenantid $TenantFilter -Type 'DELETE' -Body '{}'
                Write-LogMessage -Headers $Headers -API $APIName -tenant $TenantFilter -message "Deleted reusable setting $SettingId" -Sev 'Info'
                $Result = "Deleted reusable setting $SettingId"
                $StatusCode = [HttpStatusCode]::OK
            }
            default {
                throw "Unsupported action: $Action"
            }
        }
    } catch {
        $ErrorMessage = Get-CippException -Exception $_
        Write-LogMessage -Headers $Headers -API $APIName -tenant $TenantFilter -message "Reusable setting action failed: $($ErrorMessage.NormalizedError)" -Sev 'Error' -LogData $ErrorMessage
        $Result = $ErrorMessage.NormalizedError
        $StatusCode = [HttpStatusCode]::Forbidden
    }

    Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
            StatusCode = $StatusCode
            Body       = @{ Results = $Result }
        })
}
