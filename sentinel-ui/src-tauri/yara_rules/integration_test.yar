rule Sentinel_YARA_Integration_Test {
    meta:
        severity = "Test"
        description = "Harmless rule for testing YARA integration"

    strings:
        $marker = "SENTINEL_YARA_INTEGRATION_TEST_6F31"

    condition:
        $marker
}