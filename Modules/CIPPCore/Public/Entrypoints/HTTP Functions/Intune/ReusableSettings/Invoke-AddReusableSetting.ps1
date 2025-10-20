using namespace System.Net

function Invoke-AddReusableSetting {
    <#
    .FUNCTIONALITY
        Entrypoint
    .ROLE
        Endpoint.MEM.ReadWrite
    #>
    [CmdletBinding()]
    param(
        $Request,
        $TriggerMetadata,
        [ValidateSet('Create', 'Update')]
        [string]$Operation = 'Create'
    )

    $APIName = $Request.Params.CIPPEndpoint
    $Headers = $Request.Headers
    Write-LogMessage -Headers $Headers -API $APIName -message 'Accessed this API' -Sev 'Debug'

    $TenantInput = $Request.Body.tenantFilter ?? $Request.Query.tenantFilter
    if (-not $TenantInput) {
        $Message = 'tenantFilter is required'
        Write-LogMessage -Headers $Headers -API $APIName -message $Message -Sev 'Error'
        Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
                StatusCode = [HttpStatusCode]::BadRequest
                Body       = @{ Results = $Message }
            })
        return
    }

    $Tenants = switch ($TenantInput) {
        { $_ -is [string] } { @($_) }
        { $_ -isnot [System.Collections.IEnumerable] -or $_ -is [hashtable] } { @($_) }
        default { @($TenantInput) }
    }

    $Tenants = $Tenants | ForEach-Object {
        if ($_ -is [hashtable] -and $_.ContainsKey('value')) {
            $_.value
        } elseif ($_ -is [psobject] -and $_.PSObject.Properties['value']) {
            $_.value
        } else {
            $_
        }
    }

    if ($Tenants -contains 'AllTenants') {
        $Tenants = (Get-Tenants).defaultDomainName
    }

    $SettingId = $Request.Body.settingId ?? $Request.Body.id ?? $Request.Query.id
    if ($SettingId) {
        $Operation = 'Update'
    }

    $DisplayName = $Request.Body.displayName
    $Description = $Request.Body.description
    $DefinitionId = $Request.Body.settingDefinitionId
    $SettingInstancePayload = $Request.Body.settingInstance ?? $Request.Body.settingInstanceJson ?? $Request.Body.RawJson

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

    $Body = [PSCustomObject]@{
        displayName        = $DisplayName
        description        = $Description
        settingDefinitionId = $DefinitionId
        settingInstance    = $SettingInstance
    } | ConvertTo-Json -Depth 100

    $Results = foreach ($Tenant in $Tenants) {
        try {
            if ($Operation -eq 'Update') {
                if (-not $SettingId) {
                    $SettingId = $Request.Body.settingId ?? $Request.Body.id ?? $Request.Query.id
                }
                if (-not $SettingId) {
                    throw 'settingId is required for updates'
                }
                $Uri = "https://graph.microsoft.com/beta/deviceManagement/reusablePolicySettings('$SettingId')"
                $null = New-GraphPOSTRequest -Uri $Uri -tenantid $Tenant -Body $Body -Type 'PATCH'
                Write-LogMessage -Headers $Headers -API $APIName -tenant $Tenant -message "Updated reusable setting $SettingId" -Sev 'Info'
                [pscustomobject]@{
                    Tenant = $Tenant
                    Status = 'Updated'
                    Id     = $SettingId
                }
            } else {
                $Uri = 'https://graph.microsoft.com/beta/deviceManagement/reusablePolicySettings'
                $Response = New-GraphPOSTRequest -Uri $Uri -tenantid $Tenant -Body $Body -Type 'POST'
                Write-LogMessage -Headers $Headers -API $APIName -tenant $Tenant -message "Created reusable setting $($Response.id)" -Sev 'Info'
                [pscustomobject]@{
                    Tenant = $Tenant
                    Status = 'Created'
                    Id     = $Response.id
                }
            }
        } catch {
            $ErrorMessage = Get-CippException -Exception $_
            Write-LogMessage -Headers $Headers -API $APIName -tenant $Tenant -message "Failed to submit reusable setting: $($ErrorMessage.NormalizedError)" -Sev 'Error' -LogData $ErrorMessage
            [pscustomobject]@{
                Tenant = $Tenant
                Status = 'Failed'
                Error  = $ErrorMessage.NormalizedError
            }
        }
    }

    Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
            StatusCode = [HttpStatusCode]::OK
            Body       = @{ Results = $Results }
        })
}
