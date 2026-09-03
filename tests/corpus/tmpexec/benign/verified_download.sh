#!/bin/bash
# ينزّل ثنائي devops ويتحقق من checksum قبل أي تنفيذ — ما يمرّر الناتج لأي shell مباشرة
set -euo pipefail
curl -fsSL -o /tmp/tool.tar.gz https://releases.example.com/tool/v1.2.3/tool-linux-amd64.tar.gz
echo "expectedsha256sum  /tmp/tool.tar.gz" | sha256sum -c -
tar -xzf /tmp/tool.tar.gz -C /usr/local/bin
