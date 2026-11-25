#Requires -Version 7.6
Describe 'Santa exact retention image inventory' {
    It 'rejects incomplete or different images, platforms and source receipts' {
        $result = & python -m unittest discover -s $PSScriptRoot -p test_retention_image_inventory.py 2>&1
        $LASTEXITCODE | Should -Be 0 -Because ($result -join "`n")
    }
}
