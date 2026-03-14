#!/bin/sh
set -eu

SCENARIO="${1:-baseline}"
TIMESTAMP="$(date +%Y%m%d-%H%M%S)"
LOG_FILE="logs/${SCENARIO}-${TIMESTAMP}.log"

mkdir -p logs

{
  echo "[$(date '+%F %T')] Scenario: ${SCENARIO}"
  echo "1. Start the containers: docker compose up -d controller mininet"
  echo "2. Start the topology: ./scripts/run_topology.sh"
  echo "3. Start packet captures: ./scripts/start_captures.sh ${SCENARIO}"

  case "${SCENARIO}" in
    baseline)
      echo "4. Run traffic/benign_traffic.sh from h1 and h4"
      ;;
    port-scan)
      echo "4. Run traffic/benign_traffic.sh from h1"
      echo "5. Run attacks/port_scan.sh from h3"
      ;;
    dos)
      echo "4. Run traffic/benign_traffic.sh from h1"
      echo "5. Run attacks/dos_flood.sh from h3"
      ;;
    *)
      echo "Unknown scenario: ${SCENARIO}"
      exit 1
      ;;
  esac

  echo "6. Stop packet captures: ./scripts/stop_captures.sh"
  echo "7. Collect controller logs and pcap files from captures/output/"
} | tee "${LOG_FILE}"
