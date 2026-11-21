#!/usr/bin/env bash
# Walks the backbone volume of a stopped Compose project up the releases in
# deploy/redpanda-upgrade-path. A release refuses data more than one logical
# version behind it and names the version the data is at, so the newest is asked
# first; a release older than the data is never started, because v25.1 and v25.2
# run on newer data instead of refusing it.
set -euo pipefail
cd "$(dirname "$0")/.."
volume="$(docker compose -f deploy/compose.yaml config | sed -n 's/^name: //p')_redpanda"
if ! docker volume inspect "$volume" > /dev/null 2>&1; then
  echo "there is no $volume to upgrade"
  exit 0
fi
if [ -n "$(docker ps -q --filter volume="$volume")" ]; then
  echo "$volume is in use: stop the stack first" >&2
  exit 1
fi

broker="seagull-backbone-upgrade-$$"
trap 'docker rm -f "$broker" > /dev/null 2>&1 || true' EXIT

reaches() {
  docker rm -f "$broker" > /dev/null 2>&1 || true
  docker run -d --name "$broker" --network none -v "$volume:/var/lib/redpanda/data" "$1" \
    redpanda start --node-id=0 --smp=1 --memory=1G --reserve-memory=0M --overprovisioned --check=false \
    --kafka-addr=internal://0.0.0.0:9092,external://0.0.0.0:19092 \
    --advertise-kafka-addr=internal://redpanda:9092,external://127.0.0.1:19092 > /dev/null
  for _ in $(seq 1 90); do
    if docker exec "$broker" curl -fsS http://localhost:9644/v1/features 2> /dev/null | grep -q "\"cluster_version\": $2,"; then
      docker stop -t 60 "$broker" > /dev/null
      return 0
    fi
    if [ "$(docker inspect -f '{{.State.Running}}' "$broker")" != true ]; then
      return 1
    fi
    sleep 2
  done
  return 1
}

mapfile -t ladder < <(grep -v '^#' deploy/redpanda-upgrade-path)
read -r newest current <<< "${ladder[-1]}"
if reaches "$newest" "$current"; then
  echo "$volume is at logical version $current, the one ${newest%@*} runs"
  exit 0
fi
held="$(docker logs "$broker" 2>&1 | sed -n 's/.*upgrade from incompatible logical version \([0-9]*\) to.*/\1/p' | head -1)"
if [ -z "$held" ]; then
  docker logs --tail 20 "$broker" >&2
  echo "${newest%@*} did not start on $volume, and not because its data is older than it can read" >&2
  exit 1
fi

echo "$volume is at logical version $held"
for line in "${ladder[@]}"; do
  read -r image version <<< "$line"
  if [ "$version" -le "$held" ]; then
    continue
  fi
  if ! reaches "$image" "$version"; then
    docker logs --tail 20 "$broker" >&2
    echo "the backbone did not reach logical version $version under ${image%@*}" >&2
    exit 1
  fi
  echo "${image%@*}: the data is at logical version $version"
done
echo "$volume is at logical version $current; start the stack again with make up"
