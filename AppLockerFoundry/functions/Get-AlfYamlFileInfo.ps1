﻿<#
.SYNOPSIS
    Get AppLocker file information and convert it to YAML
.DESCRIPTIOn
    Get AppLocker file information and convert it to YAML
.PARAMETER Path
    The path to the file or directory to get AppLocker file information for.
.PARAMETER OutPath
    The path to the YAML file to write the AppLocker file information to.
.EXAMPLE
    Get-ChildItem -Path "C:\Program Files\git" -Recurse -Filter *.exe | Get-AlfYamlFileInfo -OutPath configurationData\Apps\git.yml

    Get AppLocker file information for all files in "C:\Program Files\git" and convert it to YAML
#>
function Get-AlfYamlFileInfo
{
    param
    (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [Alias('FullName')]
        [string[]]
        $Path,

        [Parameter(Mandatory = $true)]
        [string]
        $OutPath
    )

    begin
    {
        $yamlObject = @{
            RuleCollections = @{}
        }
    }

    process
    {
        $fileInfos = Get-AppLockerFileInformation -Path $Path

        :files foreach ($fileInfo in $fileInfos)
        {
            <#
            Exe: .exe and .com
            Msi: .msi, .msp, and .mst
            Script: .ps1, .bat, .cmd, .vbs, and .js
            StoreApps: .appx
            DLL: .dll and .ocx
            #>
            $ruleType = switch ([IO.Path]::GetExtension($fileInfo.Path.Path))
            {
                { $_ -in '.exe', '.com' } { 'Exe' }
                { $_ -in '.msi', '.msp', '.mst' } { 'Msi' }
                { $_ -in '.ps1', '.bat', '.cmd', '.vbs', '.js' } { 'Script' }
                { $_ -in '.appx' } { 'StoreApps' }
                { $_ -in '.dll', '.ocx' } { 'Dll' }
                default
                {
                    Write-Verbose -Message "Invalid file extension for AppLocker: $_"
                    continue files
                }
            }

            if (-not $yamlObject['RuleCollections'].Contains($ruleType))
            {
                $yamlObject['RuleCollections'][$ruleType] = @{
                    EnforcementMode = 'AuditOnly'
                    Rules           = [System.Collections.ArrayList]::new()
                }
            }

            $null = $yamlObject['RuleCollections'][$ruleType].Rules.Add(
                @{
                    Name           = $fileInfo.Path.Path
                    Description    = $fileInfo.Path.Path
                    Path           = $fileInfo.Path.Path
                    UserOrGroupSid = 'S-1-1-0'
                    Action         = 'Allow'
                }
            )

            if ($fileInfo.Publisher)
            {
                # Ensure all those unnecessary custom types are converted
                $obj = @{
                    Name               = '{0} - {1}' -f $fileInfo.Publisher.PublisherName, $fileInfo.Publisher.ProductName
                    Description        = '{0} - {1}' -f $fileInfo.Publisher.PublisherName, $fileInfo.Publisher.ProductName
                    PublisherName      = $fileInfo.Publisher.PublisherName
                    ProductName        = $fileInfo.Publisher.ProductName
                    BinaryName         = $fileInfo.Publisher.BinaryName
                    BinaryVersionRange = @{
                        LowSection  = $fileInfo.Publisher.BinaryVersion.ToString()
                        HighSection = $fileInfo.Publisher.BinaryVersion.ToString()
                    }
                    UserOrGroupSid     = 'S-1-1-0'
                    Action             = 'Allow'
                }
                $null = $yamlObject['RuleCollections'][$ruleType].Rules.Add($obj)
            }

            if ($fileInfo.Hash)
            {
                $obj = @{
                    Name             = '{0} - {1}' -f $fileInfo.Hash.SourceFileName, $fileInfo.Hash.HashType.ToString()
                    Description      = '{0} - {1}' -f $fileInfo.Hash.SourceFileName, $fileInfo.Hash.HashType.ToString()
                    HashType         = $fileInfo.Hash.HashType.ToString()
                    HashDataString   = $fileInfo.Hash.HashDataString
                    SourceFileName   = $fileInfo.Hash.SourceFileName
                    SourceFileLength = $fileInfo.Hash.SourceFileLength
                    UserOrGroupSid   = 'S-1-1-0'
                    Action           = 'Allow'
                }
                $null = $yamlObject['RuleCollections'][$ruleType].Rules.Add($obj)
            }
        }
    }

    end
    {
        if (-not (Test-Path -Path (Split-Path -Path $OutPath -Parent)))
        {
            New-Item -Path (Split-Path -Path $OutPath -Parent) -ItemType Directory -Force | Out-Null
        }

        $yamlObject | ConvertTo-Yaml -OutFile $OutPath -Force
    }
}
