[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $PSScriptRoot 'Santa.Template.psm1') -Force
$lockRaw = Get-Content -LiteralPath (Join-Path $root 'package/santa.lock.json') -Raw
if (-not ($lockRaw | Test-Json -SchemaFile (Join-Path $root 'schemas/santa-lock.schema.json') -ErrorAction Stop)) { throw 'Santa lock schema validation failed.' }
$profileResult = Test-SantaProfileSet
& python (Join-Path $PSScriptRoot 'test_mobileconfig.py') (Join-Path $root 'profiles/generated')
if ($LASTEXITCODE -ne 0) { throw 'Semantic mobileconfig validation failed.' }
$plan = Get-Content -LiteralPath (Join-Path $root 'out/deployment-plan.json') -Raw | ConvertFrom-Json
if ($plan.mode -ne 'what-if' -or $plan.performsMutation) { throw 'Deployment plan is not mutation-free.' }
if ($plan.packageVerification.state -ne 'verified' -or $plan.packageVerification.uploadBlocked) { throw 'Vendored package and macOS verification receipt do not match the lock.' }
if (@($plan.operations | Where-Object { $_.order -lt 60 -and $_.action -ne 'create-or-update-custom-profile' }).Count -ne 0) { throw 'Package or assignment appears before the readiness gate.' }
if ($plan.rollback.available) { throw 'Rollback must fail closed until a prior verified package lock exists.' }
$cleanupOrders = @($plan.cleanup.order)
if (($cleanupOrders -join ',') -ne '10,20,30,40,50') { throw 'Cleanup ordering is invalid.' }
Test-SantaPackageVerificationReceipt -Path (Join-Path $root 'tests/fixtures/package/verified.json') | Out-Null
$cleanupPlan = Get-SantaProfileCleanupPlan -ReceiptPath (Join-Path $root 'tests/fixtures/intune/profile-receipt.json')
if ($cleanupPlan.performsMutation -or @($cleanupPlan.operations).Count -ne 5) { throw 'Receipt-bound cleanup plan is invalid.' }
$fixtureResult = Invoke-SyncFixture -Path (Join-Path $root 'tests/fixtures/sync/clean-sync.json')
[pscustomobject]@{ lock = 'valid'; profiles = $profileResult.profiles.Count; plan = 'what-if'; packageUpload = 'verification-ready; device gate still required'; cleanup = 'what-if'; syncFixture = $fixtureResult.postflight } | Format-List
