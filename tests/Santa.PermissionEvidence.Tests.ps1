#Requires -Version 7.6
Describe 'Current permission evidence inventory' {
    BeforeAll {
        $root = Split-Path $PSScriptRoot -Parent
        $manifest = Get-Content (Join-Path $root 'azd-permissions.json') -Raw | ConvertFrom-Json
    }

    It 'binds every evidence record to current repository file bytes' {
        $evidence = @($manifest.requirements.evidence)
        $evidence.Count | Should -BeGreaterThan 0
        foreach ($entry in $evidence) {
            $path = Join-Path $root $entry.path
            Test-Path -LiteralPath $path -PathType Leaf | Should -BeTrue -Because $entry.path
            (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant() |
                Should -BeExactly $entry.sha256 -Because "the hash describes current source '$($entry.path)', not documentationUrl content"
        }
    }

    It 'preserves partial coverage and distinguishes historical provenance from current hashes' {
        $manifest.coverage | Should -BeExactly 'partial'
        $manifest.gaps.Count | Should -BeGreaterThan 0
        ($manifest.gaps -join "`n") | Should -Match 'sha256 fields bind current repository file bytes'
        ($manifest.gaps -join "`n") | Should -Match 'historical documentationUrl'
        foreach ($entry in $manifest.requirements) { $entry.defaultEnabled | Should -BeFalse }
        foreach ($entry in @($manifest.requirements.evidence | Where-Object documentationUrl)) {
            $entry.documentationUrl | Should -Match '^https://github\.com/nathanmcnulty/azd-santa/blob/[a-f0-9]{40}/'
        }
    }

    It 'inventories the exact current declared Graph scope set for <feature>' -ForEach @(
        @{ feature = 'intune-package-publication'; path = 'scripts/Invoke-SantaIntunePackage.ps1' }
        @{ feature = 'intune-profile-publication'; path = 'scripts/Invoke-SantaIntuneProfiles.ps1' }
        @{ feature = 'intune-profile-status'; path = 'scripts/Get-SantaIntuneProfileStatus.ps1' }
    ) {
        # Parse declarations without loading the script or invoking authentication.
        $tokens = $null
        $errors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $root $path), [ref]$tokens, [ref]$errors)
        $errors | Should -BeNullOrEmpty
        $connect = @($ast.FindAll({ param($node)
            $node -is [System.Management.Automation.Language.CommandAst] -and $node.GetCommandName() -eq 'Connect-MgGraph'
        }, $true))
        $connect.Count | Should -Be 1
        $elements = $connect[0].CommandElements
        $scopeParameters = @($elements | Where-Object { $_ -is [System.Management.Automation.Language.CommandParameterAst] -and $_.ParameterName -eq 'Scopes' })
        $scopeParameters.Count | Should -Be 1
        $index = $elements.IndexOf($scopeParameters[0])
        $value = $elements[$index + 1]
        if ($value -is [System.Management.Automation.Language.VariableExpressionAst]) {
            $scopeName = $value.VariablePath.UserPath
            $assignment = @($ast.FindAll({ param($node)
                $node -is [System.Management.Automation.Language.AssignmentStatementAst] -and
                $node.Left -is [System.Management.Automation.Language.VariableExpressionAst] -and
                $node.Left.VariablePath.UserPath -eq $scopeName
            }, $true))
            $assignment.Count | Should -Be 1
            $value = $assignment[0].Right.Expression
        }
        $requested = @($value.SafeGetValue() | Sort-Object -Unique)
        $requested.Count | Should -BeGreaterThan 0
        $inventoried = @($manifest.requirements | Where-Object { $_.feature -eq $feature -and $_.resource -eq 'Microsoft Graph' -and $_.kind -eq 'delegated' })
        (($inventoried.permission | Sort-Object -Unique) -join '|') | Should -BeExactly ($requested -join '|')
        foreach ($entry in $inventoried) { $entry.evidence.path | Should -Contain $path }
    }
}
