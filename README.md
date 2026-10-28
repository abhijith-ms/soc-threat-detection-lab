# Windows Threat Detection and Alert Triage Lab

A Wazuh detection for encoded PowerShell process creation, with synthetic Sysmon event replay and Windows collection configuration.

**Status:** rule `100100` is implemented and validated against eight synthetic replay cases. Live Windows endpoint collection, indexing and dashboard validation are pending.

## Detection

The rule matches Sysmon process-creation events for `powershell.exe` or `pwsh.exe` with a complete `-enc` or `-EncodedCommand` token followed by an argument. It uses Wazuh's native Windows-event decoder and the built-in process-creation rule hierarchy, producing a level 7 alert mapped to MITRE ATT&CK `T1059.001`.

An encoded command can be legitimate. The rule is a triage signal; it does not establish malicious intent. Coverage is limited to the two switch forms and executable names above. Renamed binaries, other aliases and encodings are outside the current rule's scope; quoted argument text can require additional context.

## Run validation

Requirements: Docker with access to the official Wazuh 4.14.9 AMD64 manager image. The runner pins the image by digest.

```bash
bash tests/run.sh
```

The tests replay raw synthetic Windows event envelopes through the manager's native input socket. All eight cases passed: three expected matches and five expected non-matches. Each case checks decoding and command-line preservation; positive cases also check the generated manager alert.

The disposable container uses 768 MiB RAM and one CPU, mounts the repository read-only and has no network or published ports. Test commands are treated as event data and are not executed. See the [validation record](evidence/first-rule-validation.md) for the case matrix, tool version and measured results.

## Repository contents

| Path | Purpose |
| --- | --- |
| [rules/soc_powershell.xml](rules/soc_powershell.xml) | Native Wazuh detection rule |
| [tests](tests/) | Synthetic events and manager replay tests |
| [windows/sysmon-config.xml](windows/sysmon-config.xml) | Sysmon configuration for the Windows test endpoint |
| [windows/agent-channels.xml](windows/agent-channels.xml) | Wazuh event-channel configuration blocks |
| [windows/generate-test-event.ps1](windows/generate-test-event.ps1) | Harmless encoded-PowerShell event generator |
| [evidence/first-rule-validation.md](evidence/first-rule-validation.md) | Validation results and remaining gaps |

## Windows integration

The prepared Windows configuration and event generator have not been executed on a Windows VM. The intended deployment path is:

```text
Windows process -> Sysmon event 1 -> Wazuh agent
    -> Manager decoding and rule evaluation
    -> Indexer -> Dashboard and alert triage
```

Current replay results validate manager decoding and detection behavior. Sysmon installation, agent transport, indexing and dashboard visibility require separate live validation.

## References

- [Wazuh](https://github.com/wazuh/wazuh)
- [Microsoft Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
