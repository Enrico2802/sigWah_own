# sigWah
A Sigma to Wazuh / OSSEC converter

## Description
sigWah is a tool for converting [Sigma](https://github.com/Neo23x0/sigma/tree/master/rules/windows/sysmon) rules to Wazuh rules, it is **not** fully automatic and still in a very early stage.
Manual review is recommended and some cases required (it's indicated).

This repository does also contain rules generated with sigWah, these rules are manually reviewed.

### Supported rules
sigWah does not (yet) support all rule conditions, it does support:

* OR statements like: `one of $` `$ or $ or ..`
* AND NOT statements like: `$ and not $`
* AND statements like: `all of them` `$ and $ and ..`
  *  The AND statement fails too many times due wrong syntax in Sigma, so there will 
  be still a `Manual check needed!` note
  
It does not support more complex conditions, all these rules will be processed as `OR` rules and 
gets a `Manual check needed!` note, some examples:
* `selection1 and not 1 of filter*`
* `(selection1 AND NOT filter) OR (selection2 AND NOT filter)`
* `selection_1 and ( selection_2 and selection_3 ) or selection_1 and ( selection_4 and selection_5 )`

A rule may also get a `Manual check needed!` note if:
* the field name is unknown
* it does not have a `title`, `id`, `description`, `level`, `logsource` / `EventID` or `detection` key
* somethings unexpected fails in the rule parse

### Regex converter
All detection rules will be converted to the Wazuh Regex syntax, this includes:
* Convert the Sigma wildcard `.` to the Wazuh wildcard `\.*`
* Characters escaping, according to the [documentation](https://documentation.wazuh.com/current/user-manual/ruleset/ruleset-xml-syntax/regex.html#regex-os-regex-syntax)
  * All `\ ` in Windows Events will be processed by Wazuh as `\\`,  so  `\ ` in a Sigma rule will be `\\\\` in a 
  Wazuh rule. (Double backslashes and backslash escaping)
* Convert the Sigma Modifiers to the Wazuh syntax (`contains|all`, `endswith` and `startswith`)

In order to avoid a lot of false negatives, some extra adjustments are made:
* All spaces are replaced with `\s+`, except at start and end of string:  
It often happens that 2 spaces are behind each other, this solves the problem. For example: `WMIC.exe⋅⋅shadowcopy⋅delete`
* The following variables are replaced:
  * `C:\\` with `\.:\\`
  * `%AppData%` with `\.AppData\.`
  * `%System%` with `\.system32\.`
  * `%WinDir%` with `\.Windows\.`
  
### Rule information
The aim was to include as much information as possible for the researcher who gets the alert. The following
information from the Sigma rule is parsed to the Wazuh rule:
* The Wazuh title (`description`) field consist of:
  * The first part: `ATT&CK {}` with the Mitre technique from `tags`
  * Followed by the title of the rule
* The Wazuh `info` field consist of:
  * The rule `description`
  * All `references` if presented
  * All `falsepositives` if presented
  * The Sigma UUID

The level conversion:
- critical: 15
- high: 14
- medium: 10
- low: 8

## Regeluebersicht und Wazuh-Integration

Dieses Repository enthaelt neben dem Konverter auch bereits generierte und manuell gepruefte Wazuh/OSSEC-Regeln. Fuer den schnellen Einsatz ist `ossec-rules/local_rules.xml` die wichtigste Datei: Sie buendelt alle aktiven Regeln in einem Wazuh-kompatiblen `<group>`-Block. Die Unterordner enthalten dieselben Regelarten als einzelne Dateien und sind hilfreich, wenn du nur bestimmte Detektionsbereiche uebernehmen oder einzelne Regeln tunen willst.

### Welche Regeln kann ich nutzen?

| Datei / Ordner | Aktive Regeln | Rule-IDs | Datenquelle | Nutzen |
| --- | ---: | --- | --- | --- |
| `ossec-rules/local_rules.xml` | 696 | `250000-300970` | Alle enthaltenen Quellen | Empfohlener Startpunkt. Importiert die komplette Regelbasis inklusive Sysmon-, Windows-, PowerShell-, Malware- und Whitelist-Regeln. |
| `ossec-rules/windows/sysmon/` | 143 | `250000-251011` | Sysmon Eventchannel | Gute Endpoint-Sicht auf Prozessstarts, Netzwerkverbindungen, Image/DLL-Loads, Remote Threads, Registry- und Dateiaktivitaeten. Nuetzlich gegen Credential Dumping, UAC-Bypass, WMI-Persistenz, Webshells und LOLBin-Missbrauch. |
| `ossec-rules/windows/process_creation/` | 383 | `260000-265983` | Sysmon Event ID 1 / Process Creation | Groesster Block fuer Command-Line-Hunting. Erkennt auffaellige PowerShell/cmd-Aufrufe, Recon, Lateral Movement, verdaechtige LOLBins, Exploit-/CVE-Muster und typische Malware-/Ransomware-Aktivitaeten. |
| `ossec-rules/windows/powershell/` | 26 | `270000-270220` | PowerShell Operational Log | Erkennt verdraechtige PowerShell-Nutzung wie Download-Cradles, Obfuscation, Encoded Commands, Downgrade-Angriffe, fremde Hosts und bekannte offensive Framework-Artefakte. |
| `ossec-rules/windows/builtin/` | 133 | `300000-300970` | Windows Security/System/Application und weitere Windows-Kanaele | Besonders wertvoll fuer Domain Controller und Windows-Server. Deckt AD-Aenderungen, DCSync, Pass-the-Hash, RDP, Service-Installationen, Eventlog-Clearing, User-/Group-Aenderungen und Defender-/Security-relevante Events ab. |
| `ossec-rules/windows/malware/` | 6 | `290040-290072` | Windows/Sysmon je nach Regel | Kleine, spezifische IOC-/Verhaltensregeln fuer Malware-Familien wie Ryuk, Ursnif, AZORult und Blue Mockingbird. |
| `ossec-rules/windows/other/` | 5 | `280000-280030` | Windows/Sysmon je nach Regel | Ergaenzende Regeln fuer Defender-Bypass, PsExec und WMI-Persistenz. |
| `ossec-rules/windows/ai_tools/` | 6 | `310000-310021` | Wazuh Syscollector Software Inventory | Optionales Zusatz-Regelset, um installierte KI-Tools wie ChatGPT, Claude, Cursor, Windsurf, Ollama, LM Studio, GPT4All, Stable Diffusion und aehnliche Tools auf Clients zu erkennen. |

### Empfehlung nach Einsatzszenario

| Szenario | Empfohlene Regeln | Warum |
| --- | --- | --- |
| Schnell starten / Lab | `ossec-rules/local_rules.xml` | Eine Datei, alle Regeln, geringster Integrationsaufwand. |
| Windows-Endpoints mit Sysmon | `local_rules.xml` plus `sysmonconfig.xml` auf den Agents | Die meisten Regeln brauchen Sysmon-Felder wie `win.eventdata.Image`, `CommandLine`, `TargetObject`, `ImageLoaded` oder `DestinationIp`. |
| Domain Controller / Active Directory | `windows/builtin/` oder komplette `local_rules.xml` | Fokus auf AD-Replikation, DCSync, Delegation, privilegierte Gruppen, RDP und Security-Eventlog-Aktivitaeten. |
| PowerShell-lastige Umgebung | `windows/powershell/`, `windows/process_creation/`, `windows/sysmon/` | Kombiniert PowerShell Event Logs mit Prozess- und Netzwerk-Kontext. |
| Malware- und Ransomware-Hunting | `windows/process_creation/`, `windows/sysmon/`, `windows/malware/` | Deckt Verhalten wie LSASS-Dumps, Schattenkopie-Loeschung, verdraechtige Downloader, Named Pipes und bekannte Malware-Muster ab. |
| Produktiver Betrieb mit wenig False Positives | Erst `local_rules.xml` testen, dann Level-0-Regeln und lokale Ausnahmen pruefen | Die Regeln enthalten Whitelist-Regeln (`level="0"`). Diese sollten zur eigenen Umgebung passen, bevor breit alarmiert wird. |

### In Wazuh einfuegen

1. Auf dem Wazuh Manager ein Backup der lokalen Regeln erstellen:

```bash
sudo cp /var/ossec/etc/rules/local_rules.xml /var/ossec/etc/rules/local_rules.xml.bak
```

2. Die gebuendelte Regeldatei aus diesem Repository nach Wazuh kopieren:

```bash
sudo cp ossec-rules/local_rules.xml /var/ossec/etc/rules/local_rules.xml
sudo chown root:wazuh /var/ossec/etc/rules/local_rules.xml
sudo chmod 640 /var/ossec/etc/rules/local_rules.xml
```

Wenn du eigene Regeln bereits in `/var/ossec/etc/rules/local_rules.xml` hast, ersetze die Datei nicht blind. Fuege dann den Inhalt aus `ossec-rules/local_rules.xml` in deine bestehende lokale Regeldatei ein oder lege eine neue Datei unter `/var/ossec/etc/rules/` an, zum Beispiel `sigwah_rules.xml`.

3. Syntax und Matching testen:

```bash
sudo /var/ossec/bin/wazuh-logtest
```

4. Wazuh Manager neu starten:

```bash
sudo systemctl restart wazuh-manager
```

5. Windows-Agenten so konfigurieren, dass die benoetigten Eventchannels geliefert werden. Sysmon ist fuer die meisten Regeln wichtig. Installiere oder aktualisiere Sysmon auf dem Endpoint mit der mitgelieferten Konfiguration:

```powershell
Sysmon64.exe -accepteula -i sysmonconfig.xml
```

Bei bereits installiertem Sysmon:

```powershell
Sysmon64.exe -c sysmonconfig.xml
```

6. Im Wazuh Agent unter `C:\Program Files (x86)\ossec-agent\ossec.conf` die zusaetzlichen Channels aktivieren:

```xml
<localfile>
  <location>Microsoft-Windows-Sysmon/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>

<localfile>
  <location>Microsoft-Windows-PowerShell/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
```

Danach den Windows-Agent neu starten:

```powershell
Restart-Service -Name wazuh
```

Windows `System`, `Application` und `Security` werden von Wazuh-Agenten normalerweise bereits gesammelt. Fuer die `builtin`-Regeln muss aber auch die Windows-Audit-Policy passende Security-Events erzeugen, zum Beispiel fuer Logons, Account Management, Directory Service Changes und Object Access.

### Einzelne Regeln statt Gesamtdatei nutzen

Die XML-Dateien in den Unterordnern sind praktisch zum Selektieren, aber viele davon enthalten nur `<rule>`-Elemente ohne aeusseren `<group>`-Wrapper. Wenn du einzelne Dateien uebernehmen willst, lege sie in einer eigenen Datei unter `/var/ossec/etc/rules/` in einen Gruppenblock, zum Beispiel:

```xml
<group name="mitre,sigwah,windows,">
  <!-- ausgewaehlte <rule>...</rule> Bloecke hier einfuegen -->
</group>
```

Pruefe danach immer mit `wazuh-logtest` und starte den Manager neu. Bei produktivem Einsatz zuerst auf einer kleinen Agent-Gruppe testen und False Positives anhand der `info`- und `Falsepositives`-Felder der Regeln bewerten.

Weitere offizielle Hinweise stehen in der Wazuh-Dokumentation zu [Custom rules](https://documentation.wazuh.com/current/user-manual/ruleset/rules/custom.html) und zur [Windows event channel collection](https://documentation.wazuh.com/current/user-manual/capabilities/log-data-collection/configuration.html#windows-event-channel).

### KI-Tools auf Clients erkennen

Das optionale Regelset `ossec-rules/windows/ai_tools/win_ai_tools_inventory.xml` erkennt bekannte KI-Tools ueber Wazuh Syscollector. Es nutzt den eingebauten Syscollector-Parent `221` und matcht auf `program.name` bei Software-Inventory-Events vom Typ `dbsync_packages`.

Erkannte Kategorien:

| Kategorie | Beispiele |
| --- | --- |
| AI Chat Assistants | ChatGPT, Claude, Perplexity, Poe, Msty, Microsoft Copilot, Google Gemini |
| AI Coding Tools | Cursor, Windsurf, Trae, GitHub Copilot, Tabnine, Codeium, Qodo, Amazon Q, JetBrains AI Assistant, Sourcegraph Cody |
| Lokale LLM-Runtimes | Ollama, LM Studio, GPT4All, Jan, AnythingLLM, Open WebUI, Pinokio, KoboldCPP, llama.cpp |
| AI Image/Media Tools | Stable Diffusion, Stability Matrix, ComfyUI, AUTOMATIC1111, InvokeAI, Fooocus, Krita AI Diffusion, NVIDIA ChatRTX |

Installation auf dem Wazuh Manager:

```bash
sudo cp ossec-rules/windows/ai_tools/win_ai_tools_inventory.xml /var/ossec/etc/rules/
sudo chown root:wazuh /var/ossec/etc/rules/win_ai_tools_inventory.xml
sudo chmod 640 /var/ossec/etc/rules/win_ai_tools_inventory.xml
sudo /var/ossec/bin/wazuh-logtest
sudo systemctl restart wazuh-manager
```

Syscollector muss auf den Clients aktiv sein und Software-Pakete scannen. Das ist in Wazuh normalerweise standardmaessig aktiv. Falls du es zentral setzen willst, fuege in der Agent-Gruppe zum Beispiel Folgendes ein:

```xml
<wodle name="syscollector">
  <disabled>no</disabled>
  <interval>1h</interval>
  <scan_on_start>yes</scan_on_start>
  <packages>yes</packages>
</wodle>
```

Wichtig: Der erste Syscollector-Scan erzeugt in Wazuh noch keine Alerts, weil er die Baseline bildet. Die Regeln schlagen an, wenn danach ein KI-Tool installiert, geaendert oder entfernt wird. Fuer bereits vorhandene Installationen kannst du im Dashboard oder per API direkt in der Inventory suchen, zum Beispiel:

```text
GET /syscollector/<AGENT_ID>/packages?pretty=true&name=ChatGPT
GET /syscollector/<AGENT_ID>/packages?pretty=true&name=Ollama
GET /syscollector/<AGENT_ID>/packages?pretty=true&name=Cursor
```

Im Wazuh Dashboard kannst du die Alerts mit `rule.groups:ai_tools` filtern. Fuer eine reine Inventar-Suche nutze die Software-Inventory-Ansicht oder filtere die Inventory-Indizes nach `data.program.name`.

## Wazuh improvement
sigWah is created to improve the detection capabilities of Wazuh. It was part of a research project carried out during an internship. The aim of the research
was to compare the detecting capabilities of a NIDS and a HIDS to advise small and medium-sized enterprises if network detection (NIDS) sufficient is to detect malware infection.

The first batch we tested (12 malware samples) with a bare Wazuh instance, Wazuh did not detect one of it. After the improvement of the Sigma rules generated by sigWah it detected 6 samples.

In the research a total of 31 malware samples were tested against Wazuh with the Sigma improvement, the result was a detection ratio of 52% (16/32)*.

The details of the research results can be found [here](https://github.com/SanWieb/PROJ201-Research-Results), this also contains the raw exports of the alerts generated at each malware sample test.

\*The Sigma community gets bigger and bigger, new rules are added every week, so the detection ratio will also improve.

## Usage

```
usage: sigWah.py [-h] [-r int] [-t YYYY-MM-DD/HH:MM:SS] input_path output_path

Sigma rules converter for OSSEC and Wazuh

positional arguments:
  input_path            Path to scan for Sigma files
  output_path           Path to output the Wazuh files

optional arguments:
  -h, --help            show this help message and exit
  -r int                Rule number to start with (adds up by 10, default 250000)
  -t YYYY-MM-DD/HH:MM:SS
                        The start modified date incl. time which files need to be processed, used to only process the files which changed
```
The conversion of /windows/process_creation rules, with start rule number `260000`:

```
python sigWah.py -r 260000 sigma/rules/windows/process_creation ossec-rules/windows/process_creation
```
After the rules have been generated hit CTRL-F and search for `Manual check needed!` note, assess and adjust if necessary.

### The whitelist override problem
If you're not careful with writing level zero Wazuh rules you can make some rules unreachable. We will explain why.

All rules with the `AND NOT` condition will by default consist of 2 parts: first the detection rule, second the whitelist rule.
Lets take for example [this](https://github.com/Neo23x0/sigma/blob/master/rules/windows/process_creation/win_control_panel_item.yml)
Sigma rule, sigWah will convert it like this:

```xml
<rule id="260300" level="15">
	<if_group>sysmon_event1</if_group>
	<field name="win.eventdata.CommandLine">.cpl</field>
	<description>ATT&CK T1196: Control Panel Items</description>
	<info type="text">Detects the use of a control panel item (.cpl) outside of the System32 folder </info>
	<info type="text">Falsepositives: Unknown. </info>
	<info type="text">Sigma UUID: 0ba863e6-def5-4e50-9cea-4dd8c7dc46a4 </info>
	<group>attack.execution,attack.t1196,attack.defense_evasion,MITRE</group>
</rule>

<rule id="260301" level="0">
	<if_sid>260300</if_sid>
	<field name="win.eventdata.CommandLine">\\\\System32\\\\|system32</field>
	<description>Whitelist Interaction: Control Panel Items</description>
	<group>attack.execution,attack.t1196,attack.defense_evasion,MITRE</group>
</rule>
```
This rule will be fine, unless there is another rule which does match on `<field name="win.eventdata.CommandLine">xx .cpl</field>`
with a level of 14. Wazuh will never reach the second rule because it did already match on `260300`. There is no other rule which 
matches on `.cpl` so here it is not a problem, but we will take another one. 

For example the rule [renamed Powershell](https://github.com/Neo23x0/sigma/blob/master/rules/windows/process_creation/win_renamed_powershell.yml),
sigWah will convert it to this:

```xml
<rule id="262390" level="15">
	<if_group>sysmon_event1</if_group>
	<field name="win.eventdata.Description">Windows PowerShell</field>
	<field name="win.eventdata.Company">Microsoft Corporation</field>
	<description>ATT&CK: Renamed PowerShell</description>
	<info type="text">Detects the execution of a renamed PowerShell often used by attackers or malware </info>
	<info type="text">Falsepositives: Unknown. </info>
	<info type="text">Sigma UUID: d178a2d7-129a-4ba4-8ee6-d6e1fecd5d20 </info>
	<info type="link">https://twitter.com/christophetd/status/1164506034720952320 </info>
	<group>car.2013-05-009,MITRE</group>
</rule>

<rule id="262391" level="0">
	<if_sid>262390</if_sid>
	<field name="win.eventdata.Image">\\\\powershell.exe|\\\\powershell_ise.exe</field>
	<description>Whitelist Interaction: Renamed PowerShell</description>
	<group>car.2013-05-009,MITRE</group>
</rule>
```
In this particular case there is a problem. Each generated `event_1` with the Powershell description and company will match
`262390`, but if the image contains `\\powershell.exe` or `\\powershell_ise.exe` the level will be set to zero and no
alert will be generated. Any other rules that might have matched will not be checked anymore.

The solution is to use the `<match>` option and negate the expression:
```xml
<rule id="262390" level="15">
	<if_group>sysmon_event1</if_group>
	<field name="win.eventdata.Description">Windows PowerShell</field>
	<field name="win.eventdata.Company">Microsoft Corporation</field>
	<match>!\\powershell.exe|\\powershell_ise.exe</match>
	<description>ATT&CK: Renamed PowerShell</description>
	<info type="text">Detects the execution of a renamed PowerShell often used by attackers or malware </info>
	<info type="text">Falsepositives: Unknown. </info>
	<info type="text">Sigma UUID: d178a2d7-129a-4ba4-8ee6-d6e1fecd5d20 </info>
	<info type="link">https://twitter.com/christophetd/status/1164506034720952320 </info>
	<group>car.2013-05-009,MITRE</group>
</rule>
```

However, this solution would not work for the rule `260300`, the `<match>` option will match on any field (like the image path),
not only the commandline in this particular case. So, it is recommended to double check all rules with a level zero and check
if it can be converted to the negated `<match>` option to prevent the whitelist overriding.

All rules in this repository are double checked for this problem.

