import "pe"

rule RedLine_Stealer_Kenneth_Triage {
    meta:
        author = "kenneth"
        email = "kenmbogu@gmail.com"
        hash = "f7856dc0d9a74e8bccfc47b55b24fe170f568b87feb7a8cb9c54fd81eee0f68d"
        description = "Detects RedLine Stealer - SOC Triage Lab"
        date = "2026-10-27"

    strings:
        $telegram = "TelegramSessionParser" ascii wide
        $discord = "Discord" ascii wide nocase
        $http_req = "HttpWebRequest" ascii wide
        $guid = "F935DC21" ascii wide
        $b64_marker = "QAAA" ascii wide

    condition:
        uint16(0) == 0x5A4D and pe.is_pe and 3 of them
}
