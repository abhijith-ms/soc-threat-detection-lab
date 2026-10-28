"""Replay synthetic Windows events through the manager; never execute their commands."""

import base64
import copy
import json
from pathlib import Path
import re
import socket
import time
import unittest
import xml.etree.ElementTree as ET


ROOT = Path(__file__).resolve().parent
BASE = json.loads((ROOT / "base-event.json").read_text())
PAYLOAD = base64.b64encode("Write-Output 'SOC-LAB-P1'".encode("utf-16le")).decode()


def windows_message(event):
    """Use the agent's raw Event XML envelope, before manager normalization."""
    source = event["win"]
    root = ET.Element("Event")
    system = ET.SubElement(root, "System")
    ET.SubElement(system, "Provider", Name=source["system"]["providerName"])
    for name, value in (("EventID", source["system"]["eventID"]), ("Level", "4"),
                        ("Channel", source["system"]["channel"]), ("Computer", source["system"]["computer"])):
        ET.SubElement(system, name).text = value
    ET.SubElement(system, "TimeCreated", SystemTime=source["system"]["systemTime"])
    ET.SubElement(system, "Keywords").text = "0x8000000000000000"
    data = ET.SubElement(root, "EventData")
    for name, value in source["eventdata"].items():
        ET.SubElement(data, "Data", Name=name[0].upper() + name[1:]).text = value
    # Windows renders XML attributes with single quotes before the agent JSON envelope.
    xml = re.sub(r'="([^"]*)"', r"='\1'", ET.tostring(root, encoding="unicode"))
    return json.dumps({"Event": xml, "Message": "Synthetic SOC lab event"})


def wait_for_record(path, location):
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        if path.exists():
            for line in path.read_text().splitlines():
                record = json.loads(line)
                if record.get("location") == location:
                    return record
        time.sleep(0.1)
    raise TimeoutError(f"No processed event for {location} in {path}")


class PowerShellRuleTests(unittest.TestCase):
    def test_native_rule_cases(self):
        cases = [
            ("full switch", {"commandLine": f"powershell.exe -NoProfile -EncodedCommand {PAYLOAD}"}, "1", True),
            ("short mixed-case switch", {"commandLine": f"powershell.exe -EnC {PAYLOAD}"}, "1", True),
            ("PowerShell 7", {"image": r"C:\Program Files\PowerShell\7\pwsh.exe", "commandLine": f"pwsh.exe -enc {PAYLOAD}"}, "1", True),
            ("plain command", {}, "1", False),
            ("different process", {"image": r"C:\Windows\System32\cmd.exe", "commandLine": f"cmd.exe /c echo -enc {PAYLOAD}"}, "1", False),
            ("different Sysmon event", {"commandLine": f"powershell.exe -enc {PAYLOAD}"}, "11", False),
            ("unrelated switch", {"commandLine": "powershell.exe -ExecutionPolicy RemoteSigned -Command Get-Date"}, "1", False),
            ("missing encoded argument", {"commandLine": "powershell.exe -EncodedCommand"}, "1", False),
        ]
        for index, (label, fields, event_id, expected) in enumerate(cases):
            with self.subTest(case=label):
                event = copy.deepcopy(BASE)
                event["win"]["eventdata"].update(fields)
                event["win"]["system"]["eventID"] = event_id
                location = f"SOC-LAB-CASE-{index}"
                with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as sender:
                    sender.sendto(f"f:{location}:{windows_message(event)}".encode(), "/var/ossec/queue/sockets/queue")
                record = wait_for_record(Path("/var/ossec/logs/archives/archives.json"), location)
                self.assertEqual(record.get("decoder", {}).get("name"), "windows_eventchannel", record)
                self.assertIn("eventdata", record["data"]["win"], record)
                self.assertEqual(record["data"]["win"]["eventdata"]["commandLine"], event["win"]["eventdata"]["commandLine"])
                self.assertEqual(record.get("rule", {}).get("id") == "100100", expected, record)
                if expected:
                    self.assertEqual(record["rule"]["level"], 7)
                    alert = wait_for_record(Path("/var/ossec/logs/alerts/alerts.json"), location)
                    self.assertEqual(alert["rule"]["id"], "100100", alert)
                    self.assertEqual(alert["rule"]["level"], 7, alert)
                print(f"PASS: {label}: custom rule {'matched' if expected else 'did not match'}")


if __name__ == "__main__":
    unittest.main(verbosity=2, failfast=True)
