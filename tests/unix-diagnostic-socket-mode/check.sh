#!/usr/bin/env bash
set -euo pipefail

dotnet --version
dotnet build tests/unix-diagnostic-socket-mode/Sleeper.csproj --configuration Release --verbosity quiet
dotnet tests/unix-diagnostic-socket-mode/bin/Release/net11.0/Sleeper.dll >/dev/null 2>&1 &
target_pid=$!
trap 'kill "$target_pid" 2>/dev/null || true' EXIT

socket_path=''
for _ in $(seq 1 80); do
  socket_path=$(find /tmp -maxdepth 1 -name "dotnet-diagnostic-${target_pid}-*-socket" -print -quit)
  if [[ -n "$socket_path" ]]; then break; fi
  sleep 0.1
done
if [[ -z "$socket_path" ]]; then
  echo 'socket_found=false'
  exit 1
fi

echo 'socket_found=true'
echo "socket_mode=$(stat -c '%a' "$socket_path")"
echo "owner_uid=$(stat -c '%u' "$socket_path")"
echo "other_uid=$(id -u nobody)"

python3 - "$socket_path" <<'PY'
import socket, sys
s = socket.socket(socket.AF_UNIX)
try:
    s.connect(sys.argv[1])
    print('owner_connect=accepted')
except OSError:
    print('owner_connect=denied')
finally:
    s.close()
PY

sudo -u nobody python3 - "$socket_path" <<'PY'
import socket, sys
s = socket.socket(socket.AF_UNIX)
try:
    s.connect(sys.argv[1])
    print('other_uid_connect=accepted')
except OSError:
    print('other_uid_connect=denied')
finally:
    s.close()
PY
