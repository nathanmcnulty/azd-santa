BeforeAll {
    $script:root = Split-Path -Parent $PSScriptRoot
    Import-Module (Join-Path $script:root 'scripts/Santa.Template.psm1') -Force
    $script:generated = Join-Path $TestDrive 'profiles'
    New-SantaProfileSet -Organization 'Test Organization' -OutputPath $script:generated | Out-Null
}

Describe 'Release lock and profiles' {
    It 'pins the selected immutable release and identity' {
        $lock = Get-SantaLock
        $lock.release.tag | Should -Be '2026.8'
        $lock.release.sourceCommit | Should -Match '^[0-9a-f]{40}$'
        $lock.identity.teamId | Should -Be 'ZMCG7MLDV9'
        $lock.verification.packageSignature.status | Should -Be 'required-not-yet-proven'
    }

    It 'generates valid profiles in prerequisite order without the network extension' {
        $result = Test-SantaProfileSet -ProfilePath $script:generated
        $result.valid | Should -BeTrue
        $result.profiles | Should -Be @('10-system-extension.mobileconfig','20-tcc.mobileconfig','30-service-management.mobileconfig','40-configuration.mobileconfig','50-notifications.mobileconfig')
        (Get-Content -Raw (Join-Path $script:generated '10-system-extension.mobileconfig')) | Should -Not -Match 'santa\.netd'
    }

    It 'detects package tampering before Apple verification' {
        $fake = Join-Path $TestDrive 'santa.pkg'
        Set-Content -LiteralPath $fake -Value 'tampered'
        { Test-SantaPackageHash -Path $fake } | Should -Throw '*mismatch*'
    }
}

Describe 'Readiness and rule safety' {
    It 'parses deployment-only and synchronized santactl status separately' {
        $monitor = ConvertFrom-SantactlStatus -Text (Get-Content -Raw (Join-Path $script:root 'tests/fixtures/santactl/status-monitor.txt'))
        $synced = ConvertFrom-SantactlStatus -Text (Get-Content -Raw (Join-Path $script:root 'tests/fixtures/santactl/status-synced.txt'))
        $monitor.mode | Should -Be 'MONITOR'
        $monitor.syncConfigured | Should -BeFalse
        $synced.syncConfigured | Should -BeTrue
        $synced.lastSuccessfulFullSync | Should -Not -BeNullOrEmpty
    }

    It 'accepts complete fresh endpoint evidence' {
        $state = Get-Content -Raw (Join-Path $script:root 'tests/fixtures/endpoint/healthy.json') | ConvertFrom-Json
        (Test-EndpointState -State $state).ready | Should -BeTrue
    }

    It 'rejects partial installs and inactive extensions' {
        $state = Get-Content -Raw (Join-Path $script:root 'tests/fixtures/endpoint/partial-install.json') | ConvertFrom-Json
        $result = Test-EndpointState -State $state
        $result.ready | Should -BeFalse
        $result.failures | Should -Contain 'profile:tcc'
        $result.failures | Should -Contain 'system-extension:active'
    }

    It 'rejects stale endpoint evidence' {
        $state = Get-Content -Raw (Join-Path $script:root 'tests/fixtures/endpoint/healthy.json') | ConvertFrom-Json
        $state.lastCheckAgeMinutes = 1441
        (Test-EndpointState -State $state).failures | Should -Contain 'evidence:stale'
    }

    It 'implements the documented first-match precedence' {
        Get-RulePrecedence CDHASH | Should -BeLessThan (Get-RulePrecedence BINARY)
        Get-RulePrecedence BINARY | Should -BeLessThan (Get-RulePrecedence SIGNINGID)
        Get-RulePrecedence SIGNINGID | Should -BeLessThan (Get-RulePrecedence CERTIFICATE)
        Get-RulePrecedence CERTIFICATE | Should -BeLessThan (Get-RulePrecedence TEAMID)
        { Get-RulePrecedence PATH } | Should -Throw '*Unsupported*'
    }
}

Describe 'Fixture sync adapter' {
    It 'deduplicates events and completes a paged clean sync' {
        $result = Invoke-SyncFixture -Path (Join-Path $script:root 'tests/fixtures/sync/clean-sync.json')
        $result.cleanSync | Should -BeTrue
        $result.uploadedEventCount | Should -Be 2
        $result.duplicateEventCount | Should -Be 1
        $result.appliedRuleCount | Should -Be 2
        $result.postflight | Should -Be 'succeeded'
    }

    It 'fails closed for an incompatible server protocol' {
        { Invoke-SyncFixture -Path (Join-Path $script:root 'tests/fixtures/sync/incompatible.json') } | Should -Throw '*Unsupported sync protocol*'
    }
}

Describe 'Mutation boundary' {
    It 'keeps the generated plan as what-if only' {
        & (Join-Path $script:root 'scripts/New-DeploymentPlan.ps1') -Organization 'Contoso' -OutputPath (Join-Path $TestDrive 'plan.json')
        $plan = Get-Content -Raw (Join-Path $TestDrive 'plan.json') | ConvertFrom-Json
        $plan.mode | Should -Be 'what-if'
        $plan.performsMutation | Should -BeFalse
        $plan.authorizationRequiredForApply | Should -BeTrue
        (@($plan.operations | Where-Object action -eq 'create-upload-commit-required-pkg'))[0].order | Should -BeGreaterThan 60
        $plan.rollback.available | Should -BeFalse
        @($plan.cleanup.order) | Should -Be @(10,20,30,40,50)
    }

    It 'keeps the Intune apply script guarded and free of device-code fallback' {
        $scriptText = Get-Content -Raw (Join-Path $script:root 'scripts/Invoke-SantaIntuneProfiles.ps1')
        $scriptText | Should -Match 'if \(-not \$Apply\)'
        $scriptText | Should -Match 'ShouldProcess'
        $scriptText | Should -Not -Match 'UseDevice(Code|Authentication)'
        $scriptText | Should -Match 'exactly one member'
        $scriptText | Should -Match 'assignment outside the authorized pilot group'
    }
}

Describe 'Provider-neutral evidence contracts' {
    It 'validates the same event, candidate, and rule artifacts for every Git provider' {
        foreach ($name in 'event','candidate','rule') {
            $fixture = Get-Content -Raw (Join-Path $script:root "tests/fixtures/contracts/$name.json")
            $fixture | Test-Json -SchemaFile (Join-Path $script:root "schemas/$name.schema.json") -ErrorAction Stop | Should -BeTrue
        }
    }

    It 'rejects an unrecorded or malformed approval' {
        $rule = Get-Content -Raw (Join-Path $script:root 'tests/fixtures/contracts/rule.json') | ConvertFrom-Json
        $rule.approval.reviewedCommit = 'not-a-commit'
        ($rule | ConvertTo-Json -Depth 20) | Test-Json -SchemaFile (Join-Path $script:root 'schemas/rule.schema.json') -ErrorAction SilentlyContinue | Should -BeFalse
    }
}
