# First detection validation

Validated 28 October 2026 with the official Wazuh 4.14.9 AMD64 manager image.

Image digest: `sha256:3561b33f8d1edf3d3b05e1819fa9a47fd28d6536787793d1840bfdf1172359ff`.

## Result

All eight synthetic replay cases passed. Wazuh's `wazuh-analysisd -t` accepted the configuration and custom rule. The suite verified the native `windows_eventchannel` decoder and preserved command line for every case, then checked whether custom rule `100100` matched. Positive cases also produced a manager alert with rule ID `100100` and level 7.

| Synthetic case | Expected result for rule 100100 | Observed result |
| --- | --- | --- |
| Windows PowerShell with `-EncodedCommand` and harmless encoded output | Match | Matched |
| Windows PowerShell with mixed-case `-EnC` | Match | Matched |
| PowerShell 7 executable with `-enc` | Match | Matched |
| Unencoded PowerShell output command | No match | Did not match |
| `cmd.exe` containing the same argument text | No match | Did not match |
| Sysmon event 11 instead of process-creation event 1 | No match | Did not match |
| `-ExecutionPolicy` without an encoded-command switch | No match | Did not match |
| Encoded-command switch without an argument | No match | Did not match |

Final run: one unittest method containing eight subcases, all passed in 7.733 seconds. This is elapsed test-suite time, not a detection-latency measurement.

## Reproduce

```bash
bash tests/run.sh
```

The runner starts the manager analysis service in a fresh disposable container, waits for readiness and feeds synthetic raw Windows event envelopes into its native input socket. It enables archiving only inside that test container so each negative case can be confirmed as processed. It does not alter the upstream base rules. It publishes no ports, has no network access and mounts the source read-only. Limits are 768 MiB RAM, one CPU and 384 processes/threads.

The final console output included:

```text
Ran 1 test in 7.733s
OK
PASS: full switch: custom rule matched
PASS: short mixed-case switch: custom rule matched
PASS: PowerShell 7: custom rule matched
PASS: plain command: custom rule did not match
PASS: different process: custom rule did not match
PASS: different Sysmon event: custom rule did not match
PASS: unrelated switch: custom rule did not match
PASS: missing encoded argument: custom rule did not match
```

Shell/Python syntax and the fixture JSON and XML configuration syntax were also checked. Windows configuration was parsed as XML, not executed on Windows.

## What remains unverified

No Windows process was executed by these tests. They do not verify actual Sysmon installation, Windows audit settings, agent enrollment or transport, Filebeat, indexing, dashboard visibility or a full incident investigation. No general accuracy percentage or performance claim follows from eight chosen cases. The rule's known coverage limits are recorded in its source comment and the [detection description](../README.md#detection).

The command-line `wazuh-logtest` preprocessing path did not select the Windows-event decoder for normalized JSON samples. The replay harness therefore uses the native Windows-event message type and raw event envelope instead. Upstream implementation references: [manager input processing](https://github.com/wazuh/wazuh/blob/v4.14.9/src/analysisd/analysisd.c), [message types](https://github.com/wazuh/wazuh/blob/v4.14.9/src/headers/mq_op.h), [Windows agent serialization](https://github.com/wazuh/wazuh/blob/v4.14.9/src/logcollector/read_win_event_channel.c) and [Windows decoder](https://github.com/wazuh/wazuh/blob/v4.14.9/src/analysisd/decoders/winevtchannel.c).
