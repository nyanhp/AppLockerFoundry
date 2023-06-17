<#
.SYNOPSIS
    Exports an AppLocker Foundry object to an AppLocker XML file.
.DESCRIPTION
    Exports an AppLocker Foundry object to an AppLocker XML file.
.PARAMETER Rsop
    The AppLocker Foundry object to export.
.PARAMETER Path
    The directory path to export the AppLocker XML file to.
.EXAMPLE
    Export-AlfXml -Rsop $Rsop -Path C:\AppLocker.xml

    Exports the AppLocker Foundry object $Rsop to C:\AppLocker
.EXAMPLE
    Get-DatumRsop $datum (Get-DatumNodesRecursive -AllDatumNodes $Datum.AllNodes) | Export-AlfXml -Path C:\AppLocker

    Calculate policy objects from Datum and export them to C:\AppLocker
#>
function Export-AlfXml
{
    [OutputType([System.IO.FileInfo])]
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [System.Collections.Specialized.OrderedDictionary]
        $Rsop,

        [Parameter(Mandatory = $true)]
        [string]
        $Path
    )

    process
    {
        $xmlDoc = [System.Xml.XmlDocument]::new()
        $null = $xmlDoc.AppendChild($xmlDoc.CreateXmlDeclaration('1.0', 'UTF-8', $null))
        $policyNode = $xmlDoc.CreateElement('AppLockerPolicy')
        $versionAttr = $xmlDoc.CreateAttribute('Version')
        $versionAttr.InnerText = '1'
        $null = $policyNode.Attributes.Append($versionAttr)
        Write-PSFMessage -Level Debug -Message ($Rsop | ConvertTo-Yaml)
        $domainPath = Join-Path -Path $Path -ChildPath $Rsop['Domain']
        if (-not (Test-Path -Path $domainPath))
        {
            Write-PSFMessage -Level Verbose -Message "Creating directory $domainPath"
            $null = New-Item -Path $domainPath -ItemType Directory
        }

        $policyPath = Join-Path -Path $domainPath -ChildPath ('{0}.xml' -f $Rsop['PolicyName'])
        Write-PSFMessage -Level Verbose -Message "Will export $($Rsop['PolicyName']) to $policyPath"

        foreach ($ruleCollection in $Rsop['RuleCollections'].GetEnumerator())
        {
            $ruleCollectionNode = $xmlDoc.CreateElement('RuleCollection')
            $typeAttr = $xmlDoc.CreateAttribute('Type')
            $typeAttr.InnerText = $ruleCollection.Key
            $enforcementAttr = $xmlDoc.CreateAttribute('EnforcementMode')
            $enforcementAttr.InnerText = $ruleCollection.Value.EnforcementMode
            $null = $ruleCollectionNode.Attributes.Append($typeAttr)
            $null = $ruleCollectionNode.Attributes.Append($enforcementAttr)

            foreach ($rule in $ruleCollection.Value.Rules)
            {
                Write-PSFMessage -Level Verbose -Message "Adding rule $($rule.Name)"
                $guidAttr = $xmlDoc.CreateAttribute('Id')
                $guidAttr.InnerText = [System.Guid]::NewGuid().ToString()
                $nameAttr = $xmlDoc.CreateAttribute('Name')
                $nameAttr.InnerText = $rule.Name
                $descriptionAttr = $xmlDoc.CreateAttribute('Description')
                $descriptionAttr.InnerText = $rule.Description
                $userOrGroupAttr = $xmlDoc.CreateAttribute('UserOrGroupSid')
                $userOrGroupAttr.InnerText = $rule.UserOrGroupSid
                $actionAttr = $xmlDoc.CreateAttribute('Action')
                $actionAttr.InnerText = $rule.Action

                if ($rule.Contains('Path'))
                {
                    # Path Rule
                    $ruleNode = $xmlDoc.CreateElement('FilePathRule')
                    $conditionNode = $xmlDoc.CreateElement('Conditions')
                    foreach ($rulePath in $rule.Path)
                    {
                        $pathConditionNode = $xmlDoc.CreateElement('FilePathCondition')
                        $pathAttr = $xmlDoc.CreateAttribute('Path')
                        $pathAttr.InnerText = $rulePath
                        $null = $pathConditionNode.Attributes.Append($pathAttr)
                        $null = $conditionNode.AppendChild($pathConditionNode)
                    }
                    $null = $ruleNode.AppendChild($conditionNode)

                    $exceptionsNode = $xmlDoc.CreateElement('Exceptions')
                    foreach ($exception in $rule.Exceptions)
                    {
                        $exceptionConditionNode = $xmlDoc.CreateElement('FilePathCondition')
                        $pathAttr = $xmlDoc.CreateAttribute('Path')
                        $pathAttr.InnerText = $exception
                        $null = $exceptionConditionNode.Attributes.Append($pathAttr)
                        $null = $exceptionsNode.AppendChild($exceptionConditionNode)
                    }
                    $null = $ruleNode.AppendChild($exceptionsNode)
                }

                if ($rule.Contains('Data'))
                {
                    # FileHash Rule
                    $ruleNode = $xmlDoc.CreateElement('FileHashRule')
                    $conditionNode = $xmlDoc.CreateElement('Conditions')
                    $hashConditionNode = $xmlDoc.CreateElement('FileHashCondition')
                    $hashNode = $xmlDoc.CreateElement('FileHash')
                    $dataAttr = $xmlDoc.CreateAttribute('Data')
                    $dataAttr.InnerText = $rule.Data
                    $null = $hashNode.Attributes.Append($dataAttr)
                    $hashTypeAttr = $xmlDoc.CreateAttribute('Type')
                    $hashTypeAttr.InnerText = $rule.Type
                    $null = $hashNode.Attributes.Append($hashTypeAttr)
                    $sourceFileNameAttr = $xmlDoc.CreateAttribute('SourceFileName')
                    $sourceFileNameAttr.InnerText = $rule.SourceFileName
                    $null = $hashNode.Attributes.Append($sourceFileNameAttr)
                    $sourceFileLengthAttr = $xmlDoc.CreateAttribute('SourceFileLength')
                    $sourceFileLengthAttr.InnerText = $rule.SourceFileLength
                    $null = $hashNode.Attributes.Append($sourceFileLengthAttr)
                    $null = $hashConditionNode.AppendChild($hashNode)
                    $null = $conditionNode.AppendChild($hashConditionNode)
                    $null = $ruleNode.AppendChild($conditionNode)
                }

                if ($rule.Contains('PublisherName'))
                {
                    # Publisher Rule
                    $ruleNode = $xmlDoc.CreateElement('FilePublisherRule')
                    $conditionNode = $xmlDoc.CreateElement('Conditions')
                    $publisherConditionNode = $xmlDoc.CreateElement('FilePublisherCondition')
                    $publisherNameAttr = $xmlDoc.CreateAttribute('PublisherName')
                    $publisherNameAttr.InnerText = $rule.PublisherName
                    $null = $publisherConditionNode.Attributes.Append($publisherNameAttr)
                    $productNameAttr = $xmlDoc.CreateAttribute('ProductName')
                    $productNameAttr.InnerText = $rule.ProductName
                    $null = $publisherConditionNode.Attributes.Append($productNameAttr)
                    $binaryNameAttr = $xmlDoc.CreateAttribute('BinaryName')
                    $binaryNameAttr.InnerText = $rule.BinaryName
                    $null = $publisherConditionNode.Attributes.Append($binaryNameAttr)
                    $binaryVersionRangeNode = $xmlDoc.CreateElement('BinaryVersionRange')
                    $binaryLowSectionAttr = $xmlDoc.CreateAttribute('LowSection')
                    $binaryLowSectionAttr.InnerText = $rule.BinaryVersionRange.LowSection
                    $null = $binaryVersionRangeNode.Attributes.Append($binaryLowSectionAttr)
                    $binaryHighSectionAttr = $xmlDoc.CreateAttribute('HighSection')
                    $binaryHighSectionAttr.InnerText = $rule.BinaryVersionRange.HighSection
                    $null = $binaryVersionRangeNode.Attributes.Append($binaryHighSectionAttr)
                    $null = $publisherConditionNode.AppendChild($binaryVersionRangeNode)
                    $null = $conditionNode.AppendChild($publisherConditionNode)
                    $null = $ruleNode.AppendChild($conditionNode)
                }
                
                $null = $ruleNode.Attributes.Append($guidAttr)
                $null = $ruleNode.Attributes.Append($nameAttr)
                $null = $ruleNode.Attributes.Append($descriptionAttr)
                $null = $ruleNode.Attributes.Append($userOrGroupAttr)
                $null = $ruleNode.Attributes.Append($actionAttr)
                $null = $ruleCollectionNode.AppendChild($ruleNode)
                $null = $policyNode.AppendChild($ruleCollectionNode)
            }
        }
        
        Write-PSFMessage -Level Verbose -Message "Exporting $($Rsop['PolicyName']) to $policyPath"
        Write-PSFMessage -Level Debug -Message $xmlDoc.ToString()
        $null = $xmlDoc.AppendChild($policyNode)
        $parent = Split-Path -Parent -Path $policyPath
        if (-not (Test-Path -Path $parent))
        {
            Write-PSFMessage -Level Verbose -Message "Creating directory $parent"
            $null = New-Item -Path $parent -ItemType Directory
        }

        $xmlDoc.Save($policyPath)
        Get-Item -Path $policyPath
    }
}
