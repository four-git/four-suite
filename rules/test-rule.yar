/* Harmless validation rule; NOT real malware coverage. */
rule four_security_benign_test
{
    meta:
        description = "Match a deliberately harmless four-security test string"
        author = "four-security"
    strings:
        $marker = "FOUR_SECURITY_YARA_TEST_SAMPLE" ascii
    condition:
        $marker
}
