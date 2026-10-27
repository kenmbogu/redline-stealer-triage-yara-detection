# RedLine Stealer - SOC Triage Lab
Analyst: kenneth | kenmbogu@gmail.com | Kali Lab

Sample: f7856dc0d9a74e8bccfc47b55b24fe170f568b87feb7a8cb9c54fd81eee0f68d
Size: 322KB | PE32+ x64 | .NET Mono | Packed (2 sections, asInvoker)

## Findings
- Obfuscated .NET, 2 sections = packed
- Strings: TelegramSessionParser, Discord, HttpWebRequest
- IoCs: F935DC21 GUID, Base64 C2 blobs
- Behavior: Steals browsers, Discord tokens, Telegram sessions, crypto wallets. Exfils via HTTP.

## Detection
YARA rule verified working against sample.
Splunk: Hunt for Discord/Telegram + HttpWebRequest from temp folders.

## Tools
Kali, strings, floss, file, YARA, PE-Bear

## Safety
Offline VM only. No binaries in repo, only IoCs.

SOC Skills: Static Triage, YARA, Splunk, IoC Extraction
