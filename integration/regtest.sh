#!/bin/bash
# regtest.sh — manage one or more bitcoin-sv regtest containers.
#
# Backward-compatible single-instance mode (no INSTANCE arg):
#   ./regtest.sh start        # start container "runar-integration-regtest" on 18332/18333/28332
#   ./regtest.sh stop
#   ./regtest.sh clean
#
# Multi-instance mode (Win 6 — parallel-per-language regtest):
#   ./regtest.sh start <name>            # auto-allocate ports based on a hash of <name>
#   ./regtest.sh start <name> <rpcport> <p2pport> <zmqport>
#   ./regtest.sh stop <name>
#   ./regtest.sh clean <name>
#
# Each instance gets its own data dir under regtest-data/<name>/ and its own
# Docker container named "runar-integration-regtest-<name>".

DEFAULT_NAME="default"
DEFAULT_RPC=18332
DEFAULT_P2P=18333
DEFAULT_ZMQ=28332

if [ "$1" == "" ]; then
  echo "Usage: ./regtest.sh start|stop|clean [<name> [<rpcport> <p2pport> <zmqport>]]"
  exit 1
fi

CMD="$1"
INSTANCE="${2:-}"

if [ -z "$INSTANCE" ]; then
  CONTAINER_NAME="runar-integration-regtest"
  DATA_SUBDIR="n1"
  RPC_PORT=$DEFAULT_RPC
  P2P_PORT=$DEFAULT_P2P
  ZMQ_PORT=$DEFAULT_ZMQ
else
  CONTAINER_NAME="runar-integration-regtest-$INSTANCE"
  DATA_SUBDIR="$INSTANCE"
  if [ -n "$3" ] && [ -n "$4" ] && [ -n "$5" ]; then
    RPC_PORT=$3
    P2P_PORT=$4
    ZMQ_PORT=$5
  else
    # Deterministic port allocation: take a 16-bit hash of the instance name
    # and offset from 19000. Keeps each language on a stable port across runs.
    HASH=$(printf '%s' "$INSTANCE" | cksum | awk '{print $1 % 800}')
    RPC_PORT=$((19000 + HASH))
    P2P_PORT=$((20000 + HASH))
    ZMQ_PORT=$((28500 + HASH))
  fi
fi

if [ "$CMD" == "stop" ]; then
  docker exec $CONTAINER_NAME bitcoin-cli -conf=/data/bitcoin.conf stop 2>/dev/null
  docker rm -f $CONTAINER_NAME 2>/dev/null
  exit 0
fi

if [ "$CMD" == "clean" ]; then
  docker rm -f $CONTAINER_NAME 2>/dev/null
  DIR="$(cd "$(dirname "$0")" && pwd)"
  rm -rf "$DIR/regtest-data/$DATA_SUBDIR"
  echo "Cleaned regtest data for $CONTAINER_NAME ($DATA_SUBDIR)."
  exit 0
fi

if [ "$CMD" == "start" ]; then
  DIR="$(cd "$(dirname "$0")" && pwd)"

  mkdir -p $DIR/regtest-data/$DATA_SUBDIR

  if [ ! -f "$DIR/regtest-data/$DATA_SUBDIR/bitcoin.conf" ]; then
    echo "Creating bitcoin.conf for $CONTAINER_NAME (rpc=$RPC_PORT)..."
    cat << EOL > $DIR/regtest-data/$DATA_SUBDIR/bitcoin.conf
port=$P2P_PORT
rpcbind=0.0.0.0
rpcport=$RPC_PORT
rpcuser=bitcoin
rpcpassword=bitcoin
rpcallowip=0.0.0.0/0
dnsseed=0
listenonion=0
listen=1
server=1
rest=1
regtest=1
debug=1
usecashaddr=0
txindex=1
excessiveblocksize=1000000000
maxstackmemoryusageconsensus=100000000
maxscriptsizepolicy=0
maxscriptnumlengthpolicy=0
maxstackmemoryusagepolicy=100000000
maxtxsizepolicy=0
genesisactivationheight=1
chronicleactivationheight=1
minminingtxfee=0.00000001
zmqpubhashblock=tcp://*:$ZMQ_PORT
zmqpubhashtx=tcp://*:$ZMQ_PORT
zmqpubdiscardedfrommempool=tcp://*:$ZMQ_PORT
zmqpubremovedfrommempoolblock=tcp://*:$ZMQ_PORT
zmqpubinvalidtx=tcp://*:$ZMQ_PORT
invalidtxsink=ZMQ
EOL
  fi

  mkdir -p $DIR/regtest-data/$DATA_SUBDIR/regtest

  docker rm -f $CONTAINER_NAME 2>/dev/null

  docker run --platform linux/amd64 --name $CONTAINER_NAME \
    -p $RPC_PORT:$RPC_PORT -p $P2P_PORT:$P2P_PORT -p $ZMQ_PORT:$ZMQ_PORT \
    --volume $DIR/regtest-data/$DATA_SUBDIR:/data \
    -d bitcoinsv/bitcoin-sv:latest \
    bitcoind -conf=/data/bitcoin.conf -printtoconsole

  echo "Waiting for node to start (RPC=$RPC_PORT, container=$CONTAINER_NAME)..."
  for i in $(seq 1 60); do
    if docker exec $CONTAINER_NAME bitcoin-cli -conf=/data/bitcoin.conf getblockcount 2>/dev/null; then
      echo "Node is ready."
      exit 0
    fi
    sleep 1
  done
  echo "Node failed to start within 60 seconds."
  docker logs $CONTAINER_NAME 2>&1 | tail -20
  exit 1

else
  docker exec $CONTAINER_NAME bitcoin-cli -conf=/data/bitcoin.conf $@
fi
