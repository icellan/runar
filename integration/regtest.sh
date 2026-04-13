#!/bin/bash

CONTAINER_NAME="runar-integration-regtest"

if [ "$1" == "" ]; then
  echo "Usage: ./regtest.sh start|stop|clean"
  exit 1
fi

if [ "$1" == "stop" ]; then
  docker exec $CONTAINER_NAME bitcoin-cli -conf=/data/bitcoin.conf stop 2>/dev/null
  docker rm -f $CONTAINER_NAME 2>/dev/null
  exit 0
fi

if [ "$1" == "clean" ]; then
  docker rm -f $CONTAINER_NAME 2>/dev/null
  DIR="$(cd "$(dirname "$0")" && pwd)"
  rm -rf "$DIR/regtest-data"
  echo "Cleaned regtest data."
  exit 0
fi

if [ "$1" == "start" ]; then
  DIR="$(cd "$(dirname "$0")" && pwd)"

  mkdir -p $DIR/regtest-data/n1

  if [ ! -f "$DIR/regtest-data/n1/bitcoin.conf" ]; then
    echo "Creating bitcoin.conf..."
    cat << EOL > $DIR/regtest-data/n1/bitcoin.conf
port=18333
rpcbind=0.0.0.0
rpcport=18332
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
zmqpubhashblock=tcp://*:28332
zmqpubhashtx=tcp://*:28332
zmqpubdiscardedfrommempool=tcp://*:28332
zmqpubremovedfrommempoolblock=tcp://*:28332
zmqpubinvalidtx=tcp://*:28332
invalidtxsink=ZMQ
EOL
  fi

  mkdir -p $DIR/regtest-data/n1/regtest

  docker rm -f $CONTAINER_NAME 2>/dev/null

  docker run --platform linux/amd64 --name $CONTAINER_NAME \
    -p 18332:18332 -p 18333:18333 -p 28332:28332 \
    --volume $DIR/regtest-data/n1:/data \
    -d bitcoinsv/bitcoin-sv:latest \
    bitcoind -conf=/data/bitcoin.conf -printtoconsole

  echo "Waiting for node to start..."
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
