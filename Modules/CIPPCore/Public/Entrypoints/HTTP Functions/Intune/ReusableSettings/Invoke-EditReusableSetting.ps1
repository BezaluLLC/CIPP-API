using namespace System.Net

function Invoke-EditReusableSetting {
    <#
    .FUNCTIONALITY
        Entrypoint
    .ROLE
        Endpoint.MEM.ReadWrite
    #>
    [CmdletBinding()]
    param($Request, $TriggerMetadata)

    $Request.Body ??= [pscustomobject]@{}
    if (-not $Request.Body.settingId) {
        $Request.Body | Add-Member -NotePropertyName 'settingId' -NotePropertyValue ($Request.Body.id ?? $Request.Query.id) -Force
    }

    Invoke-AddReusableSetting -Request $Request -TriggerMetadata $TriggerMetadata -Operation 'Update'
}
