#Requires -Version 7.6
BeforeDiscovery {
    Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent) 'experiments/vm/PrivateVmInstall.psm1') -Force
}
Describe 'Optional private VM azd installation' {
    It 'allows initialization before key generation while retaining the actual host key gate' {
        $root = Split-Path $PSScriptRoot -Parent
        $outer = Get-Content (Join-Path $root 'experiments/vm/infra/main.bicep') -Raw
        $hostSource = Get-Content (Join-Path $root 'experiments/vm/infra/host.bicep') -Raw
        $hooks = Get-Content (Join-Path $root 'experiments/vm/azure.yaml') -Raw
        $outer | Should -Match "param sshPublicKey string = ''"
        $outer | Should -Not -Match '@minLength\(40\)'
        $hostSource | Should -Match '@minLength\(40\)\s+param sshPublicKey string\s'
        $hostSource | Should -Not -Match 'param sshPublicKey string\s*='
        $hooks | Should -Match '(?s)preprovision:.*?run: ./Install-PrivateBackend.ps1 -Phase preprovision'
        $hooks | Should -Not -Match '(?m)^  preup:'
        # Both lifecycle entry points use the same tested public-only/override
        # implementation. This structural check is not a real azd execution.
    }
    InModuleScope PrivateVmInstall {
        BeforeAll { $priorEnvironment = $env:AZURE_ENV_NAME; $env:AZURE_ENV_NAME = 'synthetic' }
        AfterAll { $env:AZURE_ENV_NAME = $priorEnvironment }
        BeforeEach {
            $script:values = @{ AZURE_ENV_NAME = 'synthetic'; SANTA_PRIVATE_BACKEND_INSTALL = 'true'
                AZURE_SUBSCRIPTION_ID = '11111111-1111-4111-8111-111111111111'; AZURE_RESOURCE_GROUP = 'rg-azd-santa-vm-synthetic'
                SANTA_VM_NAME = 'vm-santa-lab'; SANTA_VM_RESOURCE_ID = '/selected/vm'; SANTA_VM_INSTANCE_ID = '33333333-3333-4333-8333-333333333333'
                SANTA_VM_DEPLOYMENT_ID = '/subscriptions/11111111-1111-4111-8111-111111111111/providers/Microsoft.Resources/deployments/private-test' }
            $script:target = @{ TenantId = '22222222-2222-4222-8222-222222222222'; SubscriptionId = $script:values.AZURE_SUBSCRIPTION_ID
                EnvironmentName = 'synthetic'; ResourceGroup = $script:values.AZURE_RESOURCE_GROUP; VmName = 'vm-santa-lab'
                VmId = $script:values.SANTA_VM_RESOURCE_ID; VmInstanceId = $script:values.SANTA_VM_INSTANCE_ID }
            $script:privateDirectory = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
            [IO.Directory]::CreateDirectory($script:privateDirectory) | Out-Null
            Mock Get-PrivateEnvironmentDirectory { $script:privateDirectory }
            Mock Invoke-PrivateAzd { param($Arguments, $Json) if ($Json) { $script:values } }
            Mock Invoke-PrivateAzure { throw 'Unexpected Azure mutation.' }
            Mock Get-SantaPrivateVmDeploymentTarget { $script:target }
            Mock Complete-SantaBackendInstallation { [pscustomobject]@{ Path = 'synthetic-binding' } }
            Mock Start-Sleep {}
        }
        It 'generates only a valid 3072-bit SSH public provisioning key' {
            $public = New-ProvisioningPublicKey
            $public | Should -Match '^ssh-rsa [A-Za-z0-9+/=]+ azd-private-provisioning-only$'
            $raw = [Convert]::FromBase64String($public.Split(' ')[1])
            $stream = [IO.MemoryStream]::new($raw)
            try {
                $parts = @()
                for ($i=0; $i -lt 3; $i++) {
                    $lengthBytes = [byte[]]::new(4); $stream.ReadExactly($lengthBytes)
                    [Array]::Reverse($lengthBytes); $length = [BitConverter]::ToUInt32($lengthBytes)
                    $value = [byte[]]::new($length); $stream.ReadExactly($value); $parts += ,$value
                }
                [Text.Encoding]::ASCII.GetString($parts[0]) | Should -Be 'ssh-rsa'
                $parts[2].Length | Should -Be 385 # Leading positive mpint byte + 384-byte RSA modulus.
                $stream.Position | Should -Be $stream.Length
            } finally { $stream.Dispose() }
            $public | Should -Not -Match 'PRIVATE KEY'
        }
        It 'preserves a user override and otherwise saves only stable public input automatically' {
            $script:values.SANTA_VM_SSH_PUBLIC_KEY = 'user-supplied-public-key'
            Invoke-PrivateVmAzdHook preprovision
            Should -Invoke Invoke-PrivateAzd -Times 0 -ParameterFilter { $Arguments[1] -eq 'set' }
            $script:values.Remove('SANTA_VM_SSH_PUBLIC_KEY')
            Invoke-PrivateVmAzdHook preprovision
            $path = Join-Path $script:privateDirectory 'provisioning-only.pub'
            $first = [IO.File]::ReadAllText($path)
            Invoke-PrivateVmAzdHook preprovision
            [IO.File]::ReadAllText($path) | Should -BeExactly $first
            @(Get-ChildItem $script:privateDirectory).Count | Should -Be 1
            Should -Invoke Invoke-PrivateAzure -Times 0
        }
        It 'sets the exact host shutdown guard without installing the opt-in backend' {
            Mock Send-PrivateInstallCommand { throw 'Unexpected installer action.' }
            $script:shutdownCalls = @()
            Mock Invoke-PrivateAzure {
                $script:shutdownCalls += ,@($Arguments)
                @{ status = 'Enabled' }
            }
            $script:values.Remove('SANTA_PRIVATE_BACKEND_INSTALL')
            Invoke-PrivateVmAzdHook postprovision
            $script:values.SANTA_PRIVATE_BACKEND_INSTALL = 'false'
            Invoke-PrivateVmAzdHook postprovision
            $script:shutdownCalls.Count | Should -Be 2
            foreach ($call in $script:shutdownCalls) {
                $call[0] | Should -Be 'vm'
                $call[1] | Should -Be 'auto-shutdown'
                $call[3] | Should -Be $script:target.SubscriptionId
                $call[5] | Should -Be $script:target.ResourceGroup
                $call[7] | Should -Be $script:target.VmName
                $call[9] | Should -Match '^\d{4}$'
            }
            Should -Invoke Get-SantaPrivateVmDeploymentTarget -Times 2
            Should -Invoke Invoke-PrivateAzure -Times 2 -ParameterFilter { $Arguments[1] -eq 'auto-shutdown' }
            Should -Invoke Send-PrivateInstallCommand -Times 0
            Should -Invoke Complete-SantaBackendInstallation -Times 0
        }
        It 'builds deterministic source bundles with bounded chunks and verifies every source hash' {
            $one = New-PrivateSourceBundle; $two = New-PrivateSourceBundle
            $one.Sha256 | Should -BeExactly $two.Sha256
            foreach ($chunk in $one.Chunks) { $chunk.Length | Should -BeLessOrEqual 24576 }
            $compressed = [Convert]::FromBase64String(($one.Chunks -join ''))
            [Convert]::ToHexStringLower([Security.Cryptography.SHA256]::HashData($compressed)) | Should -Be $one.ArchiveSha256
            $memory = [IO.MemoryStream]::new($compressed); $zip = [IO.Compression.GZipStream]::new($memory, [IO.Compression.CompressionMode]::Decompress)
            $raw = [IO.MemoryStream]::new()
            try { $zip.CopyTo($raw); $bytes = $raw.ToArray() } finally { $zip.Dispose(); $memory.Dispose(); $raw.Dispose() }
            [Convert]::ToHexStringLower([Security.Cryptography.SHA256]::HashData($bytes)) | Should -Be $one.Sha256
            $package = [Text.Encoding]::UTF8.GetString($bytes) | ConvertFrom-Json -AsHashtable
            $package.files.Count | Should -Be $files.Count
            foreach ($entry in $package.files.Values) {
                [Convert]::ToHexStringLower([Security.Cryptography.SHA256]::HashData([Convert]::FromBase64String($entry.base64))) | Should -Be $entry.sha256
            }
        }
        It 'observes an unknown submit instead of repeating initialization and finalizes machine outputs' {
            Mock Invoke-PrivateAzure { @{} }
            Mock New-PrivateSourceBundle { [pscustomobject]@{ Sha256 = 'a' * 64; ArchiveSha256 = 'b' * 64; Chunks = @('AAAA', 'BBBB') } }
            $script:observations = 0
            Mock Send-PrivateInstallCommand { param($Target, $Command)
                switch ($Command.mode) {
                    chunk { return @{ scope = 'private-azd-install-chunk'; index = $Command.index; count = $Command.count } }
                    submit { throw 'Synthetic submission timeout.' }
                    observe {
                        $script:observations++
                        if ($script:observations -eq 1) { return @{ scope = 'private-azd-install-observation'; state = 'not-installed'; completion = $null } }
                        return @{ scope = 'private-azd-install-observation'; unit = 'azd-santa-install-aaaaaaaaaaaaaaaa.service'; state = 'active'; completion = @{
                            scope = 'private-azd-install-complete'; bundle_sha256 = 'a' * 64
                            outputs = @{ } + $script:target + @{ ImageId = 'sha256:' + ('c' * 64); ComposePath = '/bound/compose.json'; ComposeSha256 = 'd' * 64; Origin = 'https://localhost:8000' } } }
                    }
                }
            }
            Invoke-PrivateVmAzdHook postprovision
            Should -Invoke Send-PrivateInstallCommand -Times 1 -Exactly -ParameterFilter { $Command.mode -eq 'submit' }
            Should -Invoke Send-PrivateInstallCommand -Times 2 -Exactly -ParameterFilter { $Command.mode -eq 'observe' }
            Should -Invoke Complete-SantaBackendInstallation -Times 1
            Should -Invoke Invoke-PrivateAzd -Times 1 -ParameterFilter { $Arguments[1] -eq 'set' -and $Arguments[2] -eq 'SANTA_OPERATOR_BINDING_PATH' }
        }
        It 'binds only authoritative selected HTTPS facts into fresh submission and completion' {
            $script:values.SANTA_PRIVATE_HTTPS_ORIGIN = 'true'
            $script:origin = 'https://santa-1111111111114111-synthetic-vm.westus2.cloudapp.azure.com'
            Mock Get-SantaHttpsEndpointFacts { @{ Fqdn = $script:origin.Substring(8) } }
            Mock Invoke-PrivateAzure { @{} }
            Mock New-PrivateSourceBundle { [pscustomobject]@{ Sha256 = 'a'*64; ArchiveSha256 = 'b'*64; Chunks = @('AAAA') } }
            Mock Send-PrivateInstallCommand { param($Target,$Command)
                if ($Command.mode -eq 'observe') { return @{ scope='private-azd-install-observation'; state='not-installed'; completion=$null } }
                if ($Command.mode -eq 'chunk') { return @{ scope='private-azd-install-chunk'; index=0; count=1 } }
                $Command.https_origin | Should -BeExactly $script:origin
                @{ scope='private-azd-install-observation'; unit='azd-santa-install-aaaaaaaaaaaaaaaa.service'; completion=@{
                    scope='private-azd-install-complete'; bundle_sha256='a'*64; outputs=@{}+$script:target+@{Origin=$script:origin} } }
            }
            Invoke-PrivateVmAzdHook postprovision
            Should -Invoke Get-SantaHttpsEndpointFacts -Times 1 -Exactly -ParameterFilter {
                $TenantId -eq $script:target.TenantId -and $SubscriptionId -eq $script:target.SubscriptionId -and
                $VmInstanceId -eq $script:target.VmInstanceId -and $EnvironmentName -eq 'synthetic'
            }
            Should -Invoke Complete-SantaBackendInstallation -Times 1 -Exactly -ParameterFilter { $InstallationOutputs.Origin -ceq $script:origin }
        }
        It 'rejects ambiguous origin opt-in before shutdown or installation' -ForEach @(@{value='https://evil.invalid'},@{value=$true}) {
            $script:values.SANTA_PRIVATE_HTTPS_ORIGIN = $value
            { Invoke-PrivateVmAzdHook postprovision } | Should -Throw '*must be true or false*'
            Should -Invoke Invoke-PrivateAzure -Times 0 -Exactly
            Should -Invoke Complete-SantaBackendInstallation -Times 0 -Exactly
        }
        It 'keeps maximum chunk commands below the packet bound and requires their exact receipt' {
            Mock Invoke-PrivateAzure { param($Arguments)
                $script = [IO.File]::ReadAllText($Arguments[-1].Substring(1))
                [Text.Encoding]::UTF8.GetByteCount($script) | Should -BeLessOrEqual 65536
                $requestMatch = [regex]::Match($script, "(?m)^export AZD_PRIVATE_INSTALL_COMMAND='(?<data>[A-Za-z0-9+/=]+)'$")
                $command = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($requestMatch.Groups['data'].Value)) | ConvertFrom-Json
                $command.data.Length | Should -Be 24576
                $nonce = [regex]::Match($script, "SANTA_PRIVATE_TRANSPORT_DONE:(?<nonce>[a-f0-9]{32})").Groups['nonce'].Value
                $payload = @{ scope = 'private-azd-install-chunk'; bundle_sha256 = $command.bundle_sha256; index = 0; count = 1 } | ConvertTo-Json -Compress
                @{ value = @(@{ code = 'ProvisioningState/succeeded'; level = 'Info'; message = "SANTA_PRIVATE_INSTALL_JSON:$payload`nSANTA_PRIVATE_TRANSPORT_DONE:$nonce" }) }
            }
            $result = Send-PrivateInstallCommand $script:target @{ mode = 'chunk'; bundle_sha256 = 'a' * 64; archive_sha256 = 'b' * 64; index = 0; count = 1; data = 'A' * 24576 }
            $result.index | Should -Be 0
            Mock Invoke-PrivateAzure { @{ value = @(@{ code = 'ProvisioningState/succeeded'; message = 'No receipt was staged.' }) } }
            { Send-PrivateInstallCommand $script:target @{ mode = 'observe'; bundle_sha256 = 'a' * 64 } } | Should -Throw '*receipt absent*'
        }
        It 'reads an existing completed install without uploading or submitting another initialization' {
            Mock Invoke-PrivateAzure { @{} }
            Mock New-PrivateSourceBundle { [pscustomobject]@{ Sha256 = 'a' * 64; ArchiveSha256 = 'b' * 64; Chunks = @('AAAA') } }
            Mock Send-PrivateInstallCommand {
                @{ scope = 'private-azd-install-observation'; unit = 'azd-santa-install-aaaaaaaaaaaaaaaa.service'; state = 'active'; completion = @{
                    scope = 'private-azd-install-complete'; bundle_sha256 = 'a' * 64
                    outputs = @{ } + $script:target + @{ ImageId = 'sha256:' + ('c' * 64); ComposePath = '/bound/compose.json'; ComposeSha256 = 'd' * 64; Origin = 'https://localhost:8000' } } }
            }
            Invoke-PrivateVmAzdHook postprovision
            Should -Invoke Send-PrivateInstallCommand -Times 0 -ParameterFilter { $Command.mode -in @('chunk', 'submit') }
            Should -Invoke Complete-SantaBackendInstallation -Times 1
        }
        It 'rejects a missing, malformed or differently scoped deployment before any write' -ForEach @(
            @{ Id = '' }, @{ Id = '/selected/deployment' },
            @{ Id = '/subscriptions/99999999-9999-4999-8999-999999999999/providers/Microsoft.Resources/deployments/private-test' },
            @{ Id = '/subscriptions/11111111-1111-4111-8111-111111111111/resourceGroups/other/providers/Microsoft.Resources/deployments/private-test' }
        ) {
            $script:values.SANTA_VM_DEPLOYMENT_ID = $Id
            Mock Send-PrivateInstallCommand { throw 'Unexpected delivery.' }
            { Invoke-PrivateVmAzdHook postprovision } | Should -Throw '*canonical deployment*'
            Should -Invoke Invoke-PrivateAzure -Times 0
            Should -Invoke Send-PrivateInstallCommand -Times 0
            Should -Invoke Complete-SantaBackendInstallation -Times 0
            Should -Invoke Invoke-PrivateAzd -Times 0 -ParameterFilter { $Arguments[0] -eq 'env' -and $Arguments[1] -eq 'set' }
        }
        It 'fails actionable on a failed retained job without resetting data or operators' {
            Mock Invoke-PrivateAzure { @{} }
            Mock New-PrivateSourceBundle { [pscustomobject]@{ Sha256 = 'a' * 64; ArchiveSha256 = 'b' * 64; Chunks = @('AAAA') } }
            Mock Send-PrivateInstallCommand { @{ scope = 'private-azd-install-observation'; state = 'failed'; completion = $null } }
            { Invoke-PrivateVmAzdHook postprovision } | Should -Throw '*same unit/data retained*'
            Should -Invoke Send-PrivateInstallCommand -Times 0 -ParameterFilter { $Command.mode -in @('chunk', 'submit') }
            Should -Invoke Complete-SantaBackendInstallation -Times 0
        }
        It 'runs relay and fresh-only guard tests without external operations' {
            $root = Split-Path (Split-Path (Get-Module PrivateVmInstall).Path -Parent) -Parent
            $root = Split-Path $root -Parent
            $result = & python -m unittest discover -s (Join-Path $root 'tests') -p test_private_install.py 2>&1
            $LASTEXITCODE | Should -Be 0 -Because ($result -join "`n")
        }
        It 'reports only the allowlisted failure for the bound failed job' -ForEach @(
            @{ Code = 'source-verification'; Bundle = 'a' * 64; Message = '*SantaInstall.source-verification*' },
            @{ Code = 'private-canary'; Bundle = 'a' * 64; Message = '*same unit/data retained*' },
            @{ Code = 'source-verification'; Bundle = 'b' * 64; Message = '*same unit/data retained*' }
        ) {
            $script:failure = @{ scope = 'private-azd-install-observation'; bundle_sha256 = $Bundle
                unit = 'azd-santa-install-aaaaaaaaaaaaaaaa.service'; state = 'failed'; completion = $null; failure_code = $Code }
            Mock Invoke-PrivateAzure { @{} }
            Mock New-PrivateSourceBundle { [pscustomobject]@{ Sha256 = 'a' * 64; ArchiveSha256 = 'b' * 64; Chunks = @('AAAA') } }
            Mock Send-PrivateInstallCommand { $script:failure }
            $output = & {
                try { Invoke-PrivateVmAzdHook postprovision } catch { $_.Exception.Message }
            } *>&1 | Out-String
            $output | Should -BeLike $Message
            $output | Should -Not -Match 'private-canary'
            Should -Invoke Send-PrivateInstallCommand -Times 1 -Exactly -ParameterFilter { $Command.mode -eq 'observe' }
            Should -Invoke Send-PrivateInstallCommand -Times 0 -Exactly -ParameterFilter { $Command.mode -in @('chunk','submit') }
            Should -Invoke Complete-SantaBackendInstallation -Times 0 -Exactly
        }
    }
}
