#Requires -Version 7.6
BeforeAll {
    $script:root = Split-Path -Parent $PSScriptRoot
}

Describe 'Supported management and development baseline' {
    It 'runs on PowerShell 7.6 or later with actual Pester 6.2 or later' {
        ($PSVersionTable.PSVersion -ge [version]'7.6') | Should -BeTrue
        $pester = @(Get-Module Pester)
        $pester.Count | Should -Be 1
        ($pester[0].Version -ge [version]'6.2.0') | Should -BeTrue
    }

    It 'parses and guards every maintained management script, module and test at PowerShell 7.6' {
        $files = @(
            Get-ChildItem (Join-Path $script:root 'scripts') -File | Where-Object Extension -in '.ps1', '.psm1'
            Get-ChildItem $PSScriptRoot -File -Filter '*.ps1'
        )
        $files.Count | Should -BeGreaterThan 0
        foreach ($file in $files) {
            $tokens = $null
            $errors = $null
            $ast = [Management.Automation.Language.Parser]::ParseFile($file.FullName, [ref]$tokens, [ref]$errors)
            $errors | Should -BeNullOrEmpty -Because $file.Name
            $ast.ScriptRequirements.RequiredPSVersion | Should -Be ([version]'7.6') -Because $file.Name
        }
    }

    It 'installs and imports the same exact Pester runner before the full CI suite' {
        $workflow = Get-Content -LiteralPath (Join-Path $script:root '.github/workflows/validate.yml') -Raw
        $workflow | Should -Match 'Install-Module Pester -RequiredVersion 6\.2\.0 -Force -Scope CurrentUser'
        $workflow | Should -Match 'Import-Module Pester -RequiredVersion 6\.2\.0 -Force'
        $workflow | Should -Match '(?s)Import-Module Pester.+Get-Module Pester.+Invoke-Pester ./tests -CI'
        $workflow | Should -Match '\$PSVersionTable\.PSVersion -ne \[version\]''7\.6\.6'''
    }

    It 'locks only the consumed validation component at its reviewed immutable baseline' {
        $lock = Get-Content -LiteralPath (Join-Path $script:root 'azd-components.lock.json') -Raw | ConvertFrom-Json
        @($lock.components).Count | Should -Be 1
        $component = $lock.components[0]
        $component.id | Should -BeExactly 'deployment-validation'
        $component.version | Should -BeExactly '2.0.0'
        $component.sourceRevision | Should -BeExactly 'fbb521e468ed129f951e7e13ecf0134986fdbd75'
        @($component.files).Count | Should -Be 3
        foreach ($file in $component.files) {
            (Get-FileHash -LiteralPath (Join-Path $script:root $file.target) -Algorithm SHA256).Hash.ToLowerInvariant() | Should -BeExactly $file.sha256
        }
        $manifest = Import-PowerShellDataFile (Join-Path $script:root 'scripts/vendor/Azd.DeploymentValidation/Azd.DeploymentValidation.psd1')
        $manifest.ModuleVersion | Should -BeExactly '2.0.0'
        $manifest.PowerShellVersion | Should -BeExactly '7.6'
    }
}
