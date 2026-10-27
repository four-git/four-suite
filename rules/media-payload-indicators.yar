/* Narrow, local triage rules. A match is an indicator for review, not proof
 * of malware. No filesize guard: deliberately checks large files too.
 * Rule provenance and limits: docs/RULE-COVERAGE.md.
 */
rule four_embedded_windows_executable_in_media
{
    meta:
        author = "four-security"
        description = "Valid PE header found in an MKV or MP4 container; investigate embedded executable data"
        severity = "review"
    strings:
        $mz = { 4D 5A }
    condition:
        (uint32be(0) == 0x1a45dfa3 or uint32be(4) == 0x66747970) and
        for any i in (1..#mz) : (
            @mz[i] + 64 < filesize and
            uint32(@mz[i] + 60) >= 64 and
            uint32(@mz[i] + 60) < 1048576 and
            @mz[i] + uint32(@mz[i] + 60) + 4 <= filesize and
            uint32(@mz[i] + uint32(@mz[i] + 60)) == 0x00004550
        )
}

rule four_script_payload_indicators_in_media
{
    meta:
        author = "four-security"
        description = "Multiple script execution and encoded-payload indicators in MKV/MP4; review for false positives"
        severity = "review"
    strings:
        $ps1 = "powershell.exe" ascii wide nocase
        $ps2 = "-EncodedCommand" ascii wide nocase
        $ps3 = "FromBase64String" ascii wide
        $ps4 = "DownloadString(" ascii wide
        $js1 = "WScript.Shell" ascii wide
        $js2 = "ADODB.Stream" ascii wide
        $js3 = "MSXML2.XMLHTTP" ascii wide
    condition:
        (uint32be(0) == 0x1a45dfa3 or uint32be(4) == 0x66747970) and
        (3 of ($ps*) or all of ($js*))
}
