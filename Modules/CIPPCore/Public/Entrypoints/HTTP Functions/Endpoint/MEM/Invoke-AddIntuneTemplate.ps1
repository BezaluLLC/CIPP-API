function Invoke-AddIntuneTemplate {
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

    function Get-ReusableSettingReferences {
        param(
            [Parameter(Mandatory = $true)]
            $PolicyObject
        )

        $ids = [System.Collections.Generic.List[string]]::new()

        function Scan-Object {
            param(
                $Value,
                [string]$ParentName = ''
            )

            if ($null -eq $Value) { return }

            if ($Value -is [System.Collections.IEnumerable] -and $Value -isnot [string]) {
                foreach ($item in $Value) { Scan-Object -Value $item -ParentName $ParentName }
                return
            }

            if ($Value -is [psobject]) {
                # Capture reference-setting objects that carry GUIDs in their value field
                if ($Value.'@odata.type' -like '*ReferenceSettingValue' -and $Value.value -match '^[0-9a-fA-F-]{36}$') {
                    $ids.Add($Value.value)
                }

                # Fallback: some reference objects lack @odata.type but still sit under simpleSettingCollectionValue
                if ($ParentName -eq 'simpleSettingCollectionValue' -and $Value.value -is [string] -and $Value.value -match '^[0-9a-fA-F-]{36}$') {
                    $ids.Add($Value.value)
                }

                foreach ($prop in $Value.PSObject.Properties) {
                    $name = $prop.Name
                    $propValue = $prop.Value

                    if ($name -match 'reusableSetting') {
                        if ($propValue -is [string] -and $propValue -match '^[0-9a-fA-F-]{36}$') { $ids.Add($propValue) }
                        elseif ($propValue -is [psobject] -and $propValue.id -match '^[0-9a-fA-F-]{36}$') { $ids.Add($propValue.id) }
                        elseif ($propValue -is [System.Collections.IEnumerable]) {
                            foreach ($entry in $propValue) {
                                if ($entry -is [string] -and $entry -match '^[0-9a-fA-F-]{36}$') { $ids.Add($entry) }
                                elseif ($entry -is [psobject] -and $entry.id -match '^[0-9a-fA-F-]{36}$') { $ids.Add($entry.id) }
                            }
                        }
                    }

                    Scan-Object -Value $propValue -ParentName $name
                }
                return
            }
        }

        Scan-Object -Value $PolicyObject
        return $ids | Select-Object -Unique
    }

    $GUID = (New-Guid).GUID
    try {
        if ($Request.Body.RawJSON) {
            if (!$Request.Body.displayName) { throw 'You must enter a displayName' }
            if ($null -eq ($Request.Body.RawJSON | ConvertFrom-Json)) { throw 'the JSON is invalid' }

            $reusableTemplateRefs = @()
            $object = [PSCustomObject]@{
                Displayname       = $Request.Body.displayName
                Description       = $Request.Body.description
                RAWJson           = $Request.Body.RawJSON
                Type              = $Request.Body.TemplateType
                GUID              = $GUID
                ReusableSettings  = $reusableTemplateRefs
            } | ConvertTo-Json -Depth 100
            $Table = Get-CippTable -tablename 'templates'
            $Table.Force = $true
            Add-CIPPAzDataTableEntity @Table -Entity @{
                JSON              = "$object"
                ReusableSettingsCount = $reusableTemplateRefs.Count
                RowKey            = "$GUID"
                PartitionKey      = 'IntuneTemplate'
                GUID              = "$GUID"
            }
            Write-LogMessage -headers $Headers -API $APIName -message "Created intune policy template named $($Request.Body.displayName) with GUID $GUID" -Sev 'Debug'

            $Result = 'Successfully added template'
            $StatusCode = [HttpStatusCode]::OK
        } else {
            $TenantFilter = $Request.Body.tenantFilter ?? $Request.Query.tenantFilter
            $URLName = $Request.Body.URLName ?? $Request.Query.URLName
            $ID = $Request.Body.ID ?? $Request.Query.ID
            $ODataType = $Request.Body.ODataType ?? $Request.Query.ODataType
            $Template = New-CIPPIntuneTemplate -TenantFilter $TenantFilter -URLName $URLName -ID $ID -ODataType $ODataType
            Write-Host "Template: $Template"
            $reusableTemplateRefs = @()
            try {
                $policyObject = $Template.TemplateJson | ConvertFrom-Json -Depth 300 -ErrorAction Stop
                $referencedReusableIds = if ($policyObject) { Get-ReusableSettingReferences -PolicyObject $policyObject } else { @() }
                Write-Information "ReusableSettings discovery: found $($referencedReusableIds.Count) ids -> $($referencedReusableIds -join ',')"

                if ($referencedReusableIds) {
                    $templatesTable = Get-CippTable -tablename 'templates'
                    $templatesTable.Force = $true
                    $existingReusableTemplates = Get-CIPPAzDataTableEntity @templatesTable -Filter "PartitionKey eq 'IntuneReusableSettingTemplate'"

                    foreach ($settingId in $referencedReusableIds) {
                        try {
                            $setting = New-GraphGETRequest -Uri "https://graph.microsoft.com/beta/deviceManagement/reusablePolicySettings/$settingId" -tenantid $TenantFilter
                            if (-not $setting) {
                                Write-LogMessage -headers $Headers -API $APIName -message "Reusable setting $settingId not returned from Graph" -Sev 'Warn'
                                continue
                            }
                            $settingDisplayName = $setting.displayName
                            if (-not $settingDisplayName) {
                                Write-LogMessage -headers $Headers -API $APIName -message "Reusable setting $settingId missing displayName" -Sev 'Warn'
                                continue
                            }

                            Write-LogMessage -headers $Headers -API $APIName -message "Reusable setting $settingId displayName '$settingDisplayName' discovered" -Sev 'Info'

                            $matchedTemplate = $existingReusableTemplates |
                                Where-Object { $_.DisplayName -eq $settingDisplayName } |
                                Select-Object -First 1

                            if (-not $matchedTemplate) {
                                $matchedTemplate = $existingReusableTemplates |
                                    Where-Object { ($_.JSON | ConvertFrom-Json -ErrorAction SilentlyContinue).DisplayName -eq $settingDisplayName } |
                                    Select-Object -First 1
                            }

                            $templateGuid = $matchedTemplate.RowKey

                            if (-not $templateGuid) {
                                $cleanSetting = Remove-ReusableSettingMetadata -InputObject $setting
                                $sanitizedJson = $cleanSetting | ConvertTo-Json -Depth 100 -Compress
                                $templateGuid = (New-Guid).Guid
                                $reusableEntity = [pscustomobject]@{
                                    DisplayName = $settingDisplayName
                                    Description = $setting.description
                                    RawJSON     = $sanitizedJson
                                    GUID        = $templateGuid
                                } | ConvertTo-Json -Depth 100 -Compress

                                Add-CIPPAzDataTableEntity @templatesTable -Force -Entity @{
                                    JSON         = "$reusableEntity"
                                    RowKey       = "$templateGuid"
                                    PartitionKey = 'IntuneReusableSettingTemplate'
                                    GUID         = "$templateGuid"
                                    DisplayName  = $settingDisplayName
                                }

                                $existingReusableTemplates += [pscustomobject]@{
                                    RowKey      = $templateGuid
                                    DisplayName = $settingDisplayName
                                    JSON        = $reusableEntity
                                }

                                Write-LogMessage -headers $Headers -API $APIName -message "Created reusable setting template $templateGuid for '$settingDisplayName'" -Sev 'Info'
                            } else {
                                Write-LogMessage -headers $Headers -API $APIName -message "Reusing existing reusable setting template $templateGuid for '$settingDisplayName'" -Sev 'Info'
                            }

                            $reusableTemplateRefs += [pscustomobject]@{
                                displayName = $settingDisplayName
                                templateId  = $templateGuid
                                sourceId    = $settingId
                            }
                        } catch {
                            Write-LogMessage -headers $Headers -API $APIName -message "Failed to link reusable setting $settingId for template creation: $($_.Exception.Message)" -Sev 'Warn'
                        }
                    }

                    Write-LogMessage -headers $Headers -API $APIName -message "Reusable settings mapped: $($reusableTemplateRefs.Count) -> $($reusableTemplateRefs.displayName -join ', ')" -Sev 'Info'
                }
            } catch {
                Write-LogMessage -headers $Headers -API $APIName -message "Reusable settings discovery failed: $($_.Exception.Message)" -Sev 'Warn'
            }

            $objectData = [PSCustomObject]@{
                Displayname      = $Template.DisplayName
                Description      = $Template.Description
                RAWJson          = $Template.TemplateJson
                Type             = $Template.Type
                GUID             = $GUID
                ReusableSettings = $reusableTemplateRefs
            }

            $object = $objectData | ConvertTo-Json -Depth 100
            $Table = Get-CippTable -tablename 'templates'
            $Table.Force = $true
            Add-CIPPAzDataTableEntity @Table -Entity @{
                JSON              = "$object"
                ReusableSettingsCount = $reusableTemplateRefs.Count
                RowKey            = "$GUID"
                PartitionKey      = 'IntuneTemplate'
                GUID              = "$GUID"
            }
            Write-LogMessage -headers $Headers -API $APIName -message "Created intune policy template $($Template.DisplayName) with GUID $GUID using an original policy from a tenant" -Sev 'Debug'

            $Result = 'Successfully added template'
            $StatusCode = [HttpStatusCode]::OK
        }
    } catch {
        $StatusCode = [HttpStatusCode]::InternalServerError
        $ErrorMessage = Get-CippException -Exception $_
        $Result = "Intune Template Deployment failed: $($ErrorMessage.NormalizedError)"
        Write-LogMessage -headers $Headers -API $APIName -message $Result -Sev 'Error' -LogData $ErrorMessage
    }


    return ([HttpResponseContext]@{
            StatusCode = $StatusCode
            Body       = @{'Results' = $Result }
        })
}
