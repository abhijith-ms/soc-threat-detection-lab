#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."

docker run --rm --network none --memory 768m --memory-swap 768m \
  --cpus 1 --pids-limit 384 --security-opt no-new-privileges:true \
  --mount "type=bind,src=$PWD,dst=/lab,readonly" \
  --entrypoint /bin/bash \
  wazuh/wazuh-manager:4.14.9@sha256:3561b33f8d1edf3d3b05e1819fa9a47fd28d6536787793d1840bfdf1172359ff \
  -euc '
    # The image entrypoint normally restores these files and their permissions.
    cp -a /var/ossec/data_tmp/exclusion/. /
    chown -R wazuh:wazuh /var/ossec/etc/lists
    cp /lab/rules/soc_powershell.xml /var/ossec/etc/rules/soc_powershell.xml
    sed -i "s#<logall_json>no</logall_json>#<logall_json>yes</logall_json>#" /var/ossec/etc/ossec.conf
    /var/ossec/bin/wazuh-analysisd -t
    /var/ossec/bin/wazuh-analysisd
    if ! timeout 20 bash -c "until test -S /var/ossec/queue/sockets/queue && test -S /var/ossec/queue/sockets/logtest; do sleep 0.2; done"; then
      tail -n 50 /var/ossec/logs/ossec.log
      exit 1
    fi
    exec /var/ossec/framework/python/bin/python3 /lab/tests/test_rules.py
  '
