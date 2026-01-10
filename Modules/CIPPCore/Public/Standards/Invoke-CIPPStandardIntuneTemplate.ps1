function Invoke-CIPPStandardIntuneTemplate {
    <#
    .FUNCTIONALITY
        Internal
    .COMPONENT
        (APIName) IntuneTemplate
    .SYNOPSIS
        (Label) Intune Template
    .DESCRIPTION
        (Helptext) Deploy and manage Intune templates across devices.
        (DocsDescription) Deploy and manage Intune templates across devices.
    .NOTES
        CAT
            Templates
        MULTIPLE
            True
        DISABLEDFEATURES
            {"report":false,"warn":false,"remediate":false}
        IMPACT
            High Impact
        ADDEDDATE
            2023-12-30
        EXECUTIVETEXT
            Deploys standardized device management configurations across all corporate devices, ensuring consistent security policies, application settings, and compliance requirements. This template-based approach streamlines device management while maintaining uniform security standards across the organization.
        ADDEDCOMPONENT
            {"type":"autoComplete","multiple":false,"creatable":false,"required":false,"name":"TemplateList","label":"Select Intune Template","api":{"queryKey":"ListIntuneTemplates-autcomplete","url":"/api/ListIntuneTemplates","labelField":"Displayname","valueField":"GUID","showRefresh":true,"templateView":{"title":"Intune Template","property":"RAWJson","type":"intune"}}}
            {"type":"autoComplete","multiple":false,"required":false,"creatable":false,"name":"TemplateList-Tags","label":"Or select a package of Intune Templates","api":{"queryKey":"ListIntuneTemplates-tag-autcomplete","url":"/api/ListIntuneTemplates?mode=Tag","labelField":"label","valueField":"value","addedField":{"templates":"templates"}}}
            {"name":"AssignTo","label":"Who should this template be assigned to?","type":"radio","options":[{"label":"Do not assign","value":"On"},{"label":"Assign to all users","value":"allLicensedUsers"},{"label":"Assign to all devices","value":"AllDevices"},{"label":"Assign to all users and devices","value":"AllDevicesAndUsers"},{"label":"Assign to Custom Group","value":"customGroup"}]}
            {"type":"textField","required":false,"name":"customGroup","label":"Enter the custom group name if you selected 'Assign to Custom Group'. Wildcards are allowed."}
            {"name":"excludeGroup","label":"Exclude Groups","type":"textField","required":false,"helpText":"Enter the group name(s) to exclude from the assignment. Wildcards are allowed. Multiple group names are comma-seperated."}
            {"type":"textField","required":false,"name":"assignmentFilter","label":"Assignment Filter Name (Optional)","helpText":"Enter the assignment filter name to apply to this policy assignment. Wildcards are allowed."}
            {"name":"assignmentFilterType","label":"Assignment Filter Mode (Optional)","type":"radio","required":false,"helpText":"Choose whether to include or exclude devices matching the filter. Only applies if you specified a filter name above. Defaults to Include if not specified.","options":[{"label":"Include - Assign to devices matching the filter","value":"include"},{"label":"Exclude - Assign to devices NOT matching the filter","value":"exclude"}]}
        UPDATECOMMENTBLOCK
            Run the Tools\Update-StandardsComments.ps1 script to update this comment block
    .LINK
        https://docs.cipp.app/user-documentation/tenant/standards/list-standards
    #>
    param($Tenant, $Settings)

    function Remove-CIPPReusableSettingNoise {
        param($InputObject)

        if ($null -eq $InputObject) { return $null }

        if ($InputObject -is [System.Collections.IEnumerable] -and $InputObject -isnot [string]) {
            $CleanArray = @()
            foreach ($item in $InputObject) { $CleanArray += Remove-CIPPReusableSettingNoise -InputObject $item }
            return $CleanArray
        }

        if ($InputObject -is [psobject]) {
            $Output = [ordered]@{}
            foreach ($prop in $InputObject.PSObject.Properties) {
                if ($prop.Name -in @('id','createdDateTime','lastModifiedDateTime','version','@odata.context','@odata.etag')) { continue }
                if ($null -ne $prop.Value) { $Output[$prop.Name] = Remove-CIPPReusableSettingNoise -InputObject $prop.Value }
            }
            return [pscustomobject]$Output
        }

        return $InputObject
    }

    function Sync-CIPPReusableSettingsForTemplate {
        param(
            [psobject]$TemplateInfo,
            [string]$Tenant
        )

        $result = [pscustomobject]@{
            RawJSON = $TemplateInfo.RawJSON
            Map     = @{}
        }

        $reusableRefs = @($TemplateInfo.ReusableSettings)
        if (-not $reusableRefs) { return $result }

        $existingReusableSettings = New-GraphGETRequest -Uri 'https://graph.microsoft.com/beta/deviceManagement/reusablePolicySettings?$top=999' -tenantid $Tenant
        $table = Get-CippTable -tablename 'templates'
        $templateEntities = Get-CIPPAzDataTableEntity @table -Filter "PartitionKey eq 'IntuneReusableSettingTemplate'"

        foreach ($ref in $reusableRefs) {
            $templateId = $ref.templateId ?? $ref.templateID ?? $ref.GUID ?? $ref.RowKey
            $sourceId = $ref.sourceId ?? $ref.sourceReusableSettingId ?? $ref.sourceGuid ?? $ref.id
            $displayName = $ref.displayName ?? $ref.DisplayName

            if (-not $templateId -or -not $displayName) { continue }

            $templateEntity = $templateEntities | Where-Object { $_.RowKey -eq $templateId } | Select-Object -First 1
            if (-not $templateEntity) { continue }

            $templateData = $templateEntity.JSON | ConvertFrom-Json -Depth 200 -ErrorAction SilentlyContinue
            $templateRaw = $templateData.RawJSON
            $templateBody = $templateRaw | ConvertFrom-Json -Depth 200 -ErrorAction SilentlyContinue
            if (-not $templateRaw -or -not $templateBody) { continue }

            $existingMatch = $existingReusableSettings | Where-Object -Property displayName -EQ $displayName | Select-Object -First 1
            $targetId = $existingMatch.id
            $needsUpdate = $false

            if ($existingMatch) {
                try {
                    $existingClean = Remove-CIPPReusableSettingNoise -InputObject ($existingMatch | Select-Object -Property * -ExcludeProperty id, createdDateTime, lastModifiedDateTime, version, '@odata.context')
                    $templateClean = Remove-CIPPReusableSettingNoise -InputObject $templateBody
                    $compare = Compare-CIPPIntuneObject -ReferenceObject $templateClean -DifferenceObject $existingClean -compareType 'ReusablePolicySetting' -ErrorAction SilentlyContinue
                    if ($compare) { $needsUpdate = $true }
                } catch {
                    $needsUpdate = $true
                }
            } else {
                $needsUpdate = $true
            }

            if ($needsUpdate) {
                try {
                    if ($targetId) {
                        $updated = New-GraphPOSTRequest -uri "https://graph.microsoft.com/beta/deviceManagement/reusablePolicySettings/$targetId" -tenantid $Tenant -type PUT -body $templateRaw
                        $targetId = $updated.id ?? $targetId
                    } else {
                        $created = New-GraphPOSTRequest -uri 'https://graph.microsoft.com/beta/deviceManagement/reusablePolicySettings' -tenantid $Tenant -type POST -body $templateRaw
                        $targetId = $created.id ?? $targetId
                    }
                } catch {
                    Write-LogMessage -API 'Standards' -tenant $Tenant -message "Failed to deploy reusable setting $($displayName): $($_.Exception.Message)" -sev 'Error'
                }
            }

            if ($sourceId -and $targetId) { $result.Map[$sourceId] = $targetId }
        }

        $updatedJson = $result.RawJSON
        foreach ($pair in $result.Map.GetEnumerator()) {
            $updatedJson = $updatedJson -replace [regex]::Escape($pair.Key), $pair.Value
        }
        $result.RawJSON = $updatedJson

        return $result
    }
    $TestResult = Test-CIPPStandardLicense -StandardName 'IntuneTemplate_general' -TenantFilter $Tenant -RequiredCapabilities @('INTUNE_A', 'MDM_Services', 'EMS', 'SCCM', 'MICROSOFTINTUNEPLAN1')
    ##$Rerun -Type Standard -Tenant $Tenant -Settings $Settings 'intuneTemplate'

    if ($TestResult -eq $false) {
        #writing to each item that the license is not present.
        $settings.TemplateList | ForEach-Object {
            Set-CIPPStandardsCompareField -FieldName "standards.IntuneTemplate.$($_.value)" -FieldValue 'This tenant does not have the required license for this standard.' -Tenant $Tenant
        }
        Write-Host "We're exiting as the correct license is not present for this standard."
        return $true
    } #we're done.
    $Table = Get-CippTable -tablename 'templates'
    $Filter = "PartitionKey eq 'IntuneTemplate'"
    $Request = @{body = $null }
    Write-Host "IntuneTemplate: Starting process. Settings are: $($Settings | ConvertTo-Json -Compress)"
    $CompareList = foreach ($Template in $Settings) {
        Write-Host "IntuneTemplate: $($Template.TemplateList.value) - Trying to find template"
        $Request.body = (Get-CIPPAzDataTableEntity @Table -Filter $Filter | Where-Object -Property RowKey -Like "$($Template.TemplateList.value)*").JSON | ConvertFrom-Json -ErrorAction SilentlyContinue
        if ($null -eq $Request.body) {
            Write-LogMessage -API 'Standards' -tenant $tenant -message "Failed to find template $($Template.TemplateList.value). Has this Intune Template been deleted?" -sev 'Error'
            continue
        }
        $reusableSync = Sync-CIPPReusableSettingsForTemplate -TemplateInfo $Request.body -Tenant $Tenant
        if ($reusableSync.RawJSON) { $Request.body.RawJSON = $reusableSync.RawJSON }
        Write-Host "IntuneTemplate: $($Template.TemplateList.value) - Got template."

        $displayname = $request.body.Displayname
        $description = $request.body.Description
        $RawJSON = $Request.body.RawJSON
        try {
            Write-Host "IntuneTemplate: $($Template.TemplateList.value) - Grabbing existing Policy"
            $ExistingPolicy = Get-CIPPIntunePolicy -tenantFilter $Tenant -DisplayName $displayname -TemplateType $Request.body.Type
        } catch {
            Write-Host "IntuneTemplate: $($Template.TemplateList.value) - Failed to get existing."
        }
        if ($ExistingPolicy) {
            try {
                Write-Host "IntuneTemplate: $($Template.TemplateList.value) - Found existing policy."
                $RawJSON = Get-CIPPTextReplacement -Text $RawJSON -TenantFilter $Tenant
                Write-Host "IntuneTemplate: $($Template.TemplateList.value) - Grabbing JSON existing."
                $JSONExistingPolicy = $ExistingPolicy.cippconfiguration | ConvertFrom-Json
                Write-Host "IntuneTemplate: $($Template.TemplateList.value) - Got existing JSON. Converting RawJSON to Template"
                $JSONTemplate = $RawJSON | ConvertFrom-Json
                Write-Host "IntuneTemplate: $($Template.TemplateList.value) - Converted RawJSON to Template."
                Write-Host "IntuneTemplate: $($Template.TemplateList.value) - Comparing JSON."
                $Compare = Compare-CIPPIntuneObject -ReferenceObject $JSONTemplate -DifferenceObject $JSONExistingPolicy -compareType $Request.body.Type -ErrorAction SilentlyContinue
            } catch {
                Write-Host "The compare failed. The error was: $($_.Exception.Message)"
            }
            Write-Host "IntuneTemplate: $($Template.TemplateList.value) - Compared JSON: $($Compare | ConvertTo-Json -Compress)"
        } else {
            Write-Host "IntuneTemplate: $($Template.TemplateList.value) - No existing policy found."
            $compare = [pscustomobject]@{
                MatchFailed = $true
                Difference  = 'This policy does not exist in Intune.'
            }
        }
        if ($Compare) {
            Write-Host "IntuneTemplate: $($Template.TemplateList.value) - Compare found differences."
            [PSCustomObject]@{
                MatchFailed            = $true
                displayname            = $displayname
                description            = $description
                compare                = $Compare
                rawJSON                = $RawJSON
                body                   = $Request.body
                assignTo               = $Template.AssignTo
                excludeGroup           = $Template.excludeGroup
                remediate              = $Template.remediate
                alert                  = $Template.alert
                report                 = $Template.report
                existingPolicyId       = $ExistingPolicy.id
                templateId             = $Template.TemplateList.value
                customGroup            = $Template.customGroup
                assignmentFilter       = $Template.assignmentFilter
                assignmentFilterType   = $Template.assignmentFilterType
            }
        } else {
            Write-Host "IntuneTemplate: $($Template.TemplateList.value) - No differences found."
            [PSCustomObject]@{
                MatchFailed            = $false
                displayname            = $displayname
                description            = $description
                compare                = $false
                rawJSON                = $RawJSON
                body                   = $Request.body
                assignTo               = $Template.AssignTo
                excludeGroup           = $Template.excludeGroup
                remediate              = $Template.remediate
                alert                  = $Template.alert
                report                 = $Template.report
                existingPolicyId       = $ExistingPolicy.id
                templateId             = $Template.TemplateList.value
                customGroup            = $Template.customGroup
                assignmentFilter       = $Template.assignmentFilter
                assignmentFilterType   = $Template.assignmentFilterType
            }
        }
    }

    if ($true -in $Settings.remediate) {
        Write-Host 'starting template deploy'
        foreach ($TemplateFile in $CompareList | Where-Object -Property remediate -EQ $true) {
            Write-Host "working on template deploy: $($TemplateFile.displayname)"
            try {
                $TemplateFile.customGroup ? ($TemplateFile.AssignTo = $TemplateFile.customGroup) : $null

                $PolicyParams = @{
                    TemplateType  = $TemplateFile.body.Type
                    Description   = $TemplateFile.description
                    DisplayName   = $TemplateFile.displayname
                    RawJSON       = $templateFile.rawJSON
                    AssignTo      = $TemplateFile.AssignTo
                    ExcludeGroup  = $TemplateFile.excludeGroup
                    tenantFilter  = $Tenant
                }

                # Add assignment filter if specified
                if ($TemplateFile.assignmentFilter) {
                    $PolicyParams.AssignmentFilterName = $TemplateFile.assignmentFilter
                    $PolicyParams.AssignmentFilterType = $TemplateFile.assignmentFilterType ?? 'include'
                }

                Set-CIPPIntunePolicy @PolicyParams
            } catch {
                $ErrorMessage = Get-NormalizedError -Message $_.Exception.Message
                Write-LogMessage -API 'Standards' -tenant $tenant -message "Failed to create or update Intune Template $($TemplateFile.displayname), Error: $ErrorMessage" -sev 'Error'
            }
        }

    }

    if ($true -in $Settings.alert) {
        foreach ($Template in $CompareList | Where-Object -Property alert -EQ $true) {
            Write-Host "working on template alert: $($Template.displayname)"
            $AlertObj = $Template | Select-Object -Property displayname, description, compare, assignTo, excludeGroup, existingPolicyId
            if ($Template.compare) {
                Write-StandardsAlert -message "Template $($Template.displayname) does not match the expected configuration." -object $AlertObj -tenant $Tenant -standardName 'IntuneTemplate' -standardId $Settings.templateId
                Write-LogMessage -API 'Standards' -tenant $Tenant -message "Template $($Template.displayname) does not match the expected configuration. We've generated an alert" -sev info
            } else {
                if ($Template.ExistingPolicyId) {
                    Write-LogMessage -API 'Standards' -tenant $Tenant -message "Template $($Template.displayname) has the correct configuration." -sev Info
                } else {
                    Write-StandardsAlert -message "Template $($Template.displayname) is missing." -object $AlertObj -tenant $Tenant -standardName 'IntuneTemplate' -standardId $Settings.templateId
                    Write-LogMessage -API 'Standards' -tenant $Tenant -message "Template $($Template.displayname) is missing." -sev info
                }
            }
        }
    }

    if ($true -in $Settings.report) {
        foreach ($Template in $CompareList | Where-Object { $_.report -eq $true -or $_.remediate -eq $true }) {
            Write-Host "working on template report: $($Template.displayname)"
            $id = $Template.templateId
            $CompareObj = $Template.compare
            $state = $CompareObj ? $CompareObj : $true
            Set-CIPPStandardsCompareField -FieldName "standards.IntuneTemplate.$id" -FieldValue $state -TenantFilter $Tenant
        }
        #Add-CIPPBPAField -FieldName "policy-$id" -FieldValue $Compare -StoreAs bool -Tenant $tenant
    }
}
