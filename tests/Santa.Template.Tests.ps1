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
        foreach ($profileName in $result.profiles) {
            $profileText = Get-Content -Raw (Join-Path $script:generated $profileName)
            ([regex]::Matches($profileText, '<key>PayloadUUID</key>')).Count | Should -Be 2 -Because "the top-level and inner payloads in '$profileName' both require stable UUIDs"
        }
    }

    It 'detects package tampering before Apple verification' {
        $fake = Join-Path $TestDrive 'santa.pkg'
        Set-Content -LiteralPath $fake -Value 'tampered'
        { Test-SantaPackageHash -Path $fake } | Should -Throw '*mismatch*'
    }

    It 'accepts a macOS verification receipt bound to the release lock' {
        Test-SantaPackageVerificationReceipt -Path (Join-Path $script:root 'tests/fixtures/package/verified.json') | Should -BeTrue
    }

    It 'rejects signing identity and package metadata drift' {
        $receipt = Get-Content -Raw (Join-Path $script:root 'tests/fixtures/package/verified.json') | ConvertFrom-Json
        foreach ($mutation in @(
                @{ Path = 'teamId'; Value = 'AAAAAAAAAA'; Error = '*teamId*' },
                @{ Path = 'certificate'; Value = 'Developer ID Installer: Unexpected'; Error = '*installerCertificateCommonName*' },
                @{ Path = 'version'; Value = '2026.8.999'; Error = '*version*' }
            )) {
            $copy = $receipt | ConvertTo-Json -Depth 20 | ConvertFrom-Json
            if ($mutation.Path -eq 'teamId') { $copy.identity.teamId = $mutation.Value }
            elseif ($mutation.Path -eq 'certificate') { $copy.identity.installerCertificateCommonName = $mutation.Value }
            else { $copy.package.version = $mutation.Value }
            $path = Join-Path $TestDrive "$($mutation.Path)-receipt.json"
            $copy | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $path
            { Test-SantaPackageVerificationReceipt -Path $path } | Should -Throw $mutation.Error
        }
    }

    It 'preserves the pinned Santa license and dependency notices with verified artifacts' {
        $projectLicense = Get-Content -Raw (Join-Path $script:root 'LICENSE')
        $notice = Get-Content -Raw (Join-Path $script:root 'THIRD_PARTY_NOTICES.md')
        $workflow = Get-Content -Raw (Join-Path $script:root '.github/workflows/verify-santa-package.yml')
        $license = Get-Content -Raw (Join-Path $script:root 'third_party/santa-2026.8/LICENSE.txt')
        $dependencyNotices = Get-Content -Raw (Join-Path $script:root 'third_party/santa-2026.8/ThirdPartyLicenses.txt')

        $projectLicense | Should -Match 'free and unencumbered software released into the public domain'
        $projectLicense | Should -Match 'THE SOFTWARE IS PROVIDED "AS IS"'
        $notice | Should -Match 'released under the \[Unlicense\]\(LICENSE\)'
        $notice | Should -Match 'santa/blob/2026\.8/LICENSE'
        $notice | Should -Match 'not modified, repackaged, committed'
        $workflow | Should -Match 'third_party/santa-2026\.8/LICENSE\.txt'
        $workflow | Should -Match 'third_party/santa-2026\.8/ThirdPartyLicenses\.txt'
        $license | Should -Match 'Apache License\s+Version 2\.0, January 2004'
        $dependencyNotices | Should -Match 'Third Party Licenses'
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
        $plan.packageVerification.state | Should -Be 'missing'
        $plan.packageVerification.uploadBlocked | Should -BeTrue
        (@($plan.operations | Where-Object action -eq 'create-upload-commit-required-pkg'))[0].order | Should -BeGreaterThan 60
        (@($plan.operations | Where-Object action -eq 'create-upload-commit-required-pkg'))[0].blocked | Should -BeTrue
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

    It 'builds cleanup only from exact receipt object IDs in reverse profile order' {
        $receiptPath = Join-Path $script:root 'tests/fixtures/intune/profile-receipt.json'
        $plan = Get-SantaProfileCleanupPlan -ReceiptPath $receiptPath
        $plan.performsMutation | Should -BeFalse
        @($plan.operations.profileId) | Should -Be @('notifications','configuration','service-management','tcc','system-extension')
        @($plan.operations.objectId | Sort-Object -Unique).Count | Should -Be 5
        @($plan.operations.assignmentGroupId | Sort-Object -Unique) | Should -Be @('22222222-2222-4222-8222-222222222222')
    }

    It 'rejects cleanup scope drift and package-present teardown' {
        $receipt = Get-Content -Raw (Join-Path $script:root 'tests/fixtures/intune/profile-receipt.json') | ConvertFrom-Json
        $receipt.profiles[0].assignmentGroupId = '44444444-4444-4444-8444-444444444444'
        $scopePath = Join-Path $TestDrive 'scope-drift-receipt.json'
        $receipt | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $scopePath
        { Get-SantaProfileCleanupPlan -ReceiptPath $scopePath } | Should -Throw '*outside the recorded pilot group*'

        $receipt = Get-Content -Raw (Join-Path $script:root 'tests/fixtures/intune/profile-receipt.json') | ConvertFrom-Json
        $receipt.package.status = 'installed'
        $packagePath = Join-Path $TestDrive 'package-present-receipt.json'
        $receipt | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $packagePath
        { Get-SantaProfileCleanupPlan -ReceiptPath $packagePath } | Should -Throw '*Package cleanup and endpoint removal evidence*'
    }

    It 'separates exact assignment proof from missing pilot-device configuration states' {
        $state = Get-Content -Raw (Join-Path $script:root 'tests/fixtures/intune/profile-status-zero.json') | ConvertFrom-Json
        $result = Test-SantaIntuneProfileReport -State $state
        $result.assignmentProven | Should -BeTrue
        $result.pilotDeviceBound | Should -BeTrue
        $result.pilotDeviceConfigurationStateCount | Should -Be 0
        $result.profileStatusRowCount | Should -Be 0
        $result.requiredProfilesDelivered | Should -BeFalse
        $result.deliveryReadiness | Should -BeFalse
    }

    It 'accepts a successful exact-device state for every required profile' {
        $state = Get-Content -Raw (Join-Path $script:root 'tests/fixtures/intune/profile-status-success.json') | ConvertFrom-Json
        $result = Test-SantaIntuneProfileReport -State $state
        $result.assignmentProven | Should -BeTrue
        $result.pilotDeviceBound | Should -BeTrue
        $result.pilotDeviceConfigurationStateCount | Should -Be 4
        $result.profileStatusRowCount | Should -Be 4
        $result.requiredProfilesDelivered | Should -BeTrue
        $result.deliveryReadiness | Should -BeTrue
    }

    It 'rejects foreign assignment, failed exact-device state, and missing exact-device state' {
        $state = Get-Content -Raw (Join-Path $script:root 'tests/fixtures/intune/profile-status-success.json') | ConvertFrom-Json
        $state.profiles[0].assignment.groupIds += '44444444-4444-4444-8444-444444444444'
        $state.profiles[0].assignment.exactPilotOnly = $false
        $state.pilotDevice.configurationStates[1].state = 'failed'
        $state.pilotDevice.configurationStates = @($state.pilotDevice.configurationStates | Where-Object id -ne '33333333-3333-4333-8333-333333333333')
        $result = Test-SantaIntuneProfileReport -State $state
        $result.assignmentProven | Should -BeFalse
        $result.requiredProfilesDelivered | Should -BeFalse
        $result.deliveryReadiness | Should -BeFalse
        $result.failures | Should -Contain 'profile:system-extension:assignment'
        $result.failures | Should -Contain 'profile:tcc:failed'
        $result.failures | Should -Contain 'profile:service-management:pilot-device-state'
    }

    It 'rejects a report whose pilot group and managed-device chain do not bind' {
        $state = Get-Content -Raw (Join-Path $script:root 'tests/fixtures/intune/profile-status-success.json') | ConvertFrom-Json
        $state.pilotDevice.entraObjectId = '88888888-8888-4888-8888-888888888888'
        $result = Test-SantaIntuneProfileReport -State $state
        $result.pilotDeviceBound | Should -BeFalse
        $result.deliveryReadiness | Should -BeFalse
        $result.failures | Should -Contain 'pilot-device:binding'
    }

    It 'keeps the status collector read-only and free of device-code fallback' {
        $scriptText = Get-Content -Raw (Join-Path $script:root 'scripts/Get-SantaIntuneProfileStatus.ps1')
        $scriptText | Should -Match "DeviceManagementConfiguration.Read.All"
        $scriptText | Should -Match "DeviceManagementManagedDevices.Read.All"
        $scriptText | Should -Not -Match "(?i)-Method\s+(POST|PATCH|DELETE)|syncDevice|UseDevice(Code|Authentication)"
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

    It 'validates Intune profile status fixtures against the report schema' {
        foreach ($name in 'profile-status-zero','profile-status-success') {
            $fixture = Get-Content -Raw (Join-Path $script:root "tests/fixtures/intune/$name.json")
            $fixture | Test-Json -SchemaFile (Join-Path $script:root 'schemas/intune-profile-status.schema.json') -ErrorAction Stop | Should -BeTrue
        }
    }
}

Describe 'Guarded Intune package apply' {
    It 'has an explicit apply boundary and no device-code authentication fallback' {
        $scriptText = Get-Content -Raw (Join-Path $script:root 'scripts/Invoke-SantaIntunePackage.ps1')
        $scriptText | Should -Match '\[switch\]\s+\$Apply'
        $scriptText | Should -Match 'SupportsShouldProcess'
        $scriptText | Should -Not -Match '(?i)UseDevice(Code|Authentication)|DeviceCodeCredential'
    }

    It 'requires verified bytes, exact-device readiness, publication, and assignment read-back' {
        $scriptText = Get-Content -Raw (Join-Path $script:root 'scripts/Invoke-SantaIntunePackage.ps1')
        $scriptText | Should -Match 'Test-SantaPackageVerificationReceipt'
        $scriptText | Should -Match 'summary\.deliveryReadiness'
        $scriptText | Should -Match "publishingState -ne 'published'"
        $scriptText | Should -Match 'Assignment read-back did not match the exact required pilot target'
    }
}
