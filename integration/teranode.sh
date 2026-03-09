#!/bin/bash

# Teranode regtest management script for Runar integration tests.
# Usage: ./teranode.sh start|stop|clean

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
COMPOSE_DIR="$SCRIPT_DIR/teranode-compose"
COMPOSE_CMD="docker compose -f $COMPOSE_DIR/docker-compose.yml"

if [ "$1" == "" ]; then
  echo "Usage: ./teranode.sh start|stop|clean"
  exit 1
fi

if [ "$1" == "stop" ]; then
  echo "Stopping Teranode regtest..."
  $COMPOSE_CMD down
  exit 0
fi

if [ "$1" == "clean" ]; then
  echo "Stopping Teranode regtest and removing all data..."
  $COMPOSE_CMD down -v
  echo "Cleaned Teranode regtest data."
  exit 0
fi

if [ "$1" == "start" ]; then
  echo "Starting Teranode regtest..."

  # Start all services
  $COMPOSE_CMD up -d
  if [ $? -ne 0 ]; then
    echo "Failed to start Docker Compose services."
    exit 1
  fi

  # Wait for blockchain service to be healthy
  echo "Waiting for blockchain service to be ready..."
  for i in $(seq 1 120); do
    if docker exec runar-tn-blockchain teranode-cli getfsmstate 2>/dev/null; then
      echo "Blockchain service is ready."
      break
    fi
    if [ $i -eq 120 ]; then
      echo "Blockchain service failed to start within 120 seconds."
      $COMPOSE_CMD logs blockchain 2>&1 | tail -30
      exit 1
    fi
    sleep 1
  done

  # Set FSM state to RUNNING (skip if already RUNNING)
  FSM_STATE=$(docker exec runar-tn-blockchain teranode-cli getfsmstate 2>&1 | grep "Current state:" | awk '{print $NF}')
  if [ "$FSM_STATE" == "RUNNING" ]; then
    echo "FSM state is already RUNNING."
  else
    echo "Setting FSM state to RUNNING (current: $FSM_STATE)..."
    for i in $(seq 1 30); do
      if docker exec runar-tn-blockchain teranode-cli setfsmstate --fsmstate RUNNING 2>/dev/null; then
        echo "FSM state set to RUNNING."
        break
      fi
      if [ $i -eq 30 ]; then
        echo "Warning: Could not set FSM state to RUNNING."
        echo "You may need to run manually: docker exec runar-tn-blockchain teranode-cli setfsmstate --fsmstate RUNNING"
      fi
      sleep 2
    done
  fi

  # Wait for RPC to be available
  echo "Waiting for RPC service..."
  for i in $(seq 1 60); do
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" -u bitcoin:bitcoin \
      -X POST http://localhost:19292 \
      -H 'Content-Type: application/json' \
      -d '{"jsonrpc":"1.0","id":"1","method":"getblockchaininfo","params":[]}' 2>/dev/null)
    if [ "$HTTP_CODE" == "200" ]; then
      echo "RPC is ready on port 19292."
      break
    fi
    if [ $i -eq 60 ]; then
      echo "RPC service failed to become available within 60 seconds."
      $COMPOSE_CMD logs rpc 2>&1 | tail -20
      exit 1
    fi
    sleep 1
  done

  # Pre-mine blocks for Genesis activation (regtest GenesisActivationHeight=10000).
  # Coinbase wallet address for privkey=1 (deterministic, regtest format).
  COINBASE_ADDR="mrCDrCybB6J1vRfbwM5hemdJz73FwDBC8r"
  TARGET_HEIGHT=10101  # 10000 (genesis) + 101 (coinbase maturity)

  CURRENT_HEIGHT=$(curl -s -u bitcoin:bitcoin \
    -X POST http://localhost:19292 \
    -H 'Content-Type: application/json' \
    -d '{"jsonrpc":"1.0","id":"1","method":"getblockchaininfo","params":[]}' 2>/dev/null \
    | python3 -c "import sys,json; print(json.load(sys.stdin)['result']['blocks'])" 2>/dev/null)

  if [ -z "$CURRENT_HEIGHT" ]; then
    CURRENT_HEIGHT=0
  fi

  BLOCKS_NEEDED=$((TARGET_HEIGHT - CURRENT_HEIGHT))
  if [ "$BLOCKS_NEEDED" -gt 0 ]; then
    echo "Mining $BLOCKS_NEEDED blocks for Genesis activation (current: $CURRENT_HEIGHT, target: $TARGET_HEIGHT)..."
    curl -s -u bitcoin:bitcoin \
      -X POST http://localhost:19292 \
      -H 'Content-Type: application/json' \
      --max-time 600 \
      -d "{\"jsonrpc\":\"1.0\",\"id\":\"1\",\"method\":\"generatetoaddress\",\"params\":[$BLOCKS_NEEDED, \"$COINBASE_ADDR\"]}" > /dev/null 2>&1
    echo "Mining complete."
  else
    echo "Already at height $CURRENT_HEIGHT (>= $TARGET_HEIGHT), no mining needed."
  fi

  echo ""
  echo "Teranode regtest is running."
  echo "  RPC endpoint: http://localhost:19292"
  echo "  RPC credentials: bitcoin:bitcoin"
  echo ""
  echo "Run integration tests with:"
  echo "  NODE_TYPE=teranode go test -tags integration -v -timeout 600s"
  echo ""
  echo "Stop with: ./teranode.sh stop"
  echo "Clean with: ./teranode.sh clean"
  exit 0
fi

# Pass-through: execute RPC call
METHOD="$1"
shift
PARAMS=$(printf ', "%s"' "$@")
PARAMS="[${PARAMS:2}]"  # Remove leading ", "
if [ "$PARAMS" == "[]" ]; then
  PARAMS="[]"
fi

curl -s -u bitcoin:bitcoin \
  -X POST http://localhost:19292 \
  -H 'Content-Type: application/json' \
  -d "{\"jsonrpc\":\"1.0\",\"id\":\"1\",\"method\":\"$METHOD\",\"params\":$PARAMS}" | python3 -m json.tool 2>/dev/null || echo "RPC call failed"
