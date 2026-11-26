#Requires -Version 7.6
Describe 'Santa restore authority planning' {
    It 'plans bounded dispositions for restored identities and credentials' {
        $result = & python -m unittest discover -s $PSScriptRoot -p test_restore_authority_plan.py 2>&1
        $LASTEXITCODE | Should -Be 0 -Because ($result -join "`n")
    }
    It 'builds a signed request only for the reviewed recovery step' {
        $result = & python -m unittest discover -s $PSScriptRoot -p test_restore_operator_approval.py 2>&1
        $LASTEXITCODE | Should -Be 0 -Because ($result -join "`n")
    }
    It 'delivers the signed worker request once through the selected VM transport' {
        $result = & python -m unittest discover -s $PSScriptRoot -p test_restore_worker_transport.py 2>&1
        $LASTEXITCODE | Should -Be 0 -Because ($result -join "`n")
    }
    It 'guards the fresh administrator reissue with the completed quarantine and exact approval' -Skip:$IsWindows {
        $result = & python -m unittest discover -s $PSScriptRoot -p test_restore_admin_reissue.py 2>&1
        $LASTEXITCODE | Should -Be 0 -Because ($result -join "`n")
    }
    It 'verifies the exact signed administrator approval once and rejects expiry and tampering' {
        $result = & python -m unittest discover -s $PSScriptRoot -p test_restore_admin_approval.py 2>&1
        $LASTEXITCODE | Should -Be 0 -Because ($result -join "`n")
    }
}
