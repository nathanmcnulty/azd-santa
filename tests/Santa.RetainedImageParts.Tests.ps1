#Requires -Version 7.6
Describe 'Santa retained image transfer parts' {
    It 'rejects incomplete or changed parts and verifies the assembled ciphertext' {
        $result = & python -m unittest discover -s $PSScriptRoot -p test_retained_image_parts.py 2>&1
        $LASTEXITCODE | Should -Be 0 -Because ($result -join "`n")
    }
}
