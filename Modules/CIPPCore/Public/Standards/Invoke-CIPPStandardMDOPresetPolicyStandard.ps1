function Invoke-CIPPStandardMDOPresetPolicyStandard {
    <#
    .FUNCTIONALITY
    Internal
    #>

    param($Tenant, $Settings)
    $ProtectionLevel = 'Standard'
    $PolicyName = "$ProtectionLevel Preset Security Policy"

    $errorMessagePattern = "The operation couldn't be performed because object '$PolicyName' couldn't be found*"
    try {
        $EOPCurrentState = New-ExoRequest -tenantid $Tenant -cmdlet 'Get-EOPProtectionPolicyRule' -select 'Name,State' | Where-Object -Property Name -EQ $PolicyName
    } catch {
        if ($_.Exception.Message -like $errorMessagePattern) {
            Write-Host "The EOP '$PolicyName' needs to be created."
            Write-LogMessage -API 'Standards' -tenant $Tenant -message "EOP '$PolicyName' is not present." -sev Info
            $EOPCurrentState = $null
        } else {
            Write-Host "The current state of '$PolicyName' could not be acquired."
            Write-LogMessage -API 'Standards' -tenant $Tenant -message "The current state of EOP '$PolicyName' could not be acquired. $_.Exception.Message" -sev Warn
        }
    }
    $EOPStateIsCorrect = ($CurrentState.Name -eq $PolicyName) -and
                         ($CurrentState.State -eq "Enabled")


    try {
        $ATPCurrentState = New-ExoRequest -tenantid $Tenant -cmdlet 'Get-ATPProtectionPolicyRule' -select 'Name,State' | Where-Object -Property Name -EQ $PolicyName
    } catch {
        if ($_.Exception.Message -like $errorMessagePattern) {
            Write-Host "The ATP '$PolicyName' needs to be created."
            Write-LogMessage -API 'Standards' -tenant $Tenant -message "The ATP '$PolicyName' needs to be created." -sev Info
            $ATPCurrentState = $null
        } else {
            Write-Host "The current state of '$PolicyName' could not be acquired."
            Write-LogMessage -API 'Standards' -tenant $Tenant -message "The current state of ATP '$PolicyName' could not be acquired. $_.Exception.Message" -sev Warn
        }
    }
    

    if ($Settings.remediate -eq $true) {
        if ($ATPCurrentState -and $EOPCurrentState) {
            Write-LogMessage -API 'Standards' -tenant $Tenant -message 'Standard Preset Security Policy already correctly configured' -sev Info
        } else {
            $cmdparams = @{
                Enabled      = $true
            }
            try {
                $AntiPhishPolicy =     ( Get-AntiPhishPolicy | Where-Object -Property RecommendedPolicyType -eq -Value $ProtectionLevel )
                $HostedContentPolicy = ( Get-HostedContentFilterPolicy | Where-Object -Property RecommendedPolicyType -eq -Value $ProtectionLevel )
                $MalwarePolicy =       ( Get-MalwareFilterPolicy | Where-Object -Property RecommendedPolicyType -eq -Value $ProtectionLevel )
                $SafelinksPolicy =     ( Get-SafeLinksPolicy | Where-Object -Property RecommendedPolicyType -eq -Value $ProtectionLevel )
                $AttachmentPolicy =    ( Get-SafeAttachmentPolicy | Where-Object -Property RecommendedPolicyType -eq -Value $ProtectionLevel )
            } catch {
                Write-Host "Failed to gather dependent policies to create $PolicyName"
                Write-LogMessage -API 'Standards' -tenant $Tenant -message "Failed to gather dependent policies to create $PolicyName. $_.Exception.Message" -sev Error
            }
            
            if ($EOPCurrentState -eq $null) {
                try {
                    New-EOPProtectionPolicyRule -Name $PolicyName -AntiPhishPolicy $AntiPhishPolicy.Name -HostedContentFilterPolicy $HostedContentPolicy.Name -MalwareFilterPolicy $MalwarePolicy.Name -Priority 1 -ErrorAction Continue
                } catch {
                    Write-Host "Could not create EOP $PolicyName"
                    Write-LogMessage -API 'Standards' -tenant $Tenant -message "Could not create EOP $PolicyName. $_.Exception.Message" -sev Error
                }
            } else {
                Write-Host "EOP $PolicyName already exists"
                Write-LogMessage -API 'Standards' -tenant $Tenant -message "EOP $PolicyName already exists" -sev Info
            }
            
            if ($ATPCurrentState -eq $null) {
                try {
                    New-ATPProtectionPolicyRule -Name $PolicyName -SafeAttachmentPolicy $AttachmentPolicy.Name -SafeLinksPolicy $SafelinksPolicy.Name -Priority 1 -ErrorAction Continue
                } catch {
                    Write-Host "Could not create ATP $PolicyName"
                    Write-LogMessage -API 'Standards' -tenant $Tenant -message "Could not create ATP $PolicyName. $_.Exception.Message" -sev Error
                }
            } else {
                Write-Host "ATP $PolicyName already exists"
                Write-LogMessage -API 'Standards' -tenant $Tenant -message "ATP $PolicyName already exists" -sev Info
            }
        }
    }


    if ($Settings.alert -eq $true) {

        if ($ATPCurrentState -and $EOPCurrentState) {
            Write-LogMessage -API 'Standards' -tenant $Tenant -message 'Standard Preset Security Policy is enabled' -sev Info
        } else {
            Write-LogMessage -API 'Standards' -tenant $Tenant -message 'Standard Preset Security Policy is not enabled' -sev Alert
        }
    }

    if ($Settings.report -eq $true) {
        Add-CIPPBPAField -FieldName 'MDOPresetPolicyStandard' -FieldValue ($ATPCurrentState -and $EOPCurrentState) -StoreAs bool -Tenant $tenant
    }

}