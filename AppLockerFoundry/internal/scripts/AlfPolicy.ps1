enum AlfEnsure
{
    Present
    Absent
}

class AlfReason
{
    [DscProperty()] [string] $Code
    [DscProperty()] [string] $Phrase
}

[DscResource()]
class AlfPolicy
{
    # LDAP path to the AppLocker policy object or 'local' for the local policy
    [DscProperty(Key)] [string] $ResourceIdentifier

    # The AppLocker policy XML
    [DscProperty(Mandatory)] [string] $PolicyXml

    [DscProperty()] [AlfEnsure] $Ensure

    # Reasons why the resource was not in the desired state
    [DscProperty(NotConfigurable)] [AlfReason[]] $Reasons

    [AlfPolicy] Get()
    {
        $currentStatus = @{
            Reasons = [System.Collections.Generic.List[AlfReason]]::new()
        }
        $alfParam = @{ 
            ErrorAction = 'Stop'
        }

        if ($this.ResourceIdentifier -eq 'local')
        {
            $alfParam['Local'] = $true
        }
        else
        {
            $alfParam['Ldap'] = $this.ResourceIdentifier
            $alfParam['Domain'] = $true
        }

        $currentAlf = Get-AppLockerPolicy @alfParam

        if ($this.Ensure -eq 'Present' -and -not $currentAlf)
        {
            $currentStatus.Reasons.Add(@{
                    Code   = 'AppLocker policy not found but ensure was set to present'
                    Phrase = 'AlfPolicy:AlfPolicy:NotFound'
                })
        }

        if ($this.Ensure -eq 'Absent' -and $currentAlf)
        {
            $currentStatus.Reasons.Add(@{
                    Code   = 'AppLocker policy found but ensure was set to absent'
                    Phrase = 'AlfPolicy:AlfPolicy:Found'
                })
        }        

        return $currentStatus
    }

    [void] Set()
    {
        $alfParam = @{ 
            ErrorAction = 'Stop'
        }

        if ($this.ResourceIdentifier -eq 'local')
        {
            $alfParam['Local'] = $true
        }
        else
        {
            $alfParam['Ldap'] = $this.ResourceIdentifier
            $alfParam['Domain'] = $true
        }

        $xmlPolicy = if ($this.Ensure -eq 'Absent')
        {
            '<AppLockerPolicy Version="1" />'
        }
        else
        {
            $this.PolicyXml
        }

        $alfParam['PolicyXml'] = $xmlPolicy

        Set-AppLockerPolicy @alfParam
    }

    [bool] Test()
    {
        $currentStatus = $this.Get()

        return $currentStatus.Reasons.Count -eq 0
    }
}
