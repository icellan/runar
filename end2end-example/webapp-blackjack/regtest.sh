#!/bin/bash

if [ "$1" == "" ]; then
  echo "Please specify 'start', 'stop' or other bitcoin-cli command"
  exit 1
fi

if [ "$1" == "stop" ]; then
  docker exec bitcoin-sv-regtest bitcoin-cli -conf=/data/bitcoin.conf stop
  exit 0
fi  

if [ "$1" == "start" ]; then

  mkdir -p $HOME/.keystore

  if [ ! -f "$HOME/.keystore/ps.key" ]; then
    echo "Creating $HOME/.keystore/ps.key..."
    echo "tprv8ZgxMBicQKsPfPCcKvAPAhga6QNeC1xPXhPBhFtw1CvRisZHnCF4LAjDbkcY7CwhndHrvTvmRWWwqRM9XzaAVRxwh81wnPV1kX8gU1XbEhx" > $HOME/.keystore/ps.key
  fi

  if [ -L "$0" ]; then
    DIR="$(cd "$($(pwd)/$(readlink "$0"))" && pwd)"
  else
    DIR="$(cd "$(dirname "$0")" && pwd)"
  fi

  for D in $DIR/regtest/n1
  do
    mkdir -p $D

    if [ ! -f "$D/bitcoin.conf" ]; then
      echo "Creating $D/bitcoin.conf..."
      cat << EOL > $D/bitcoin.conf
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
genesisactivationheight=1
minminingtxfee=0.00000001
zmqpubhashblock=tcp://*:28332
zmqpubhashtx=tcp://*:28332
zmqpubdiscardedfrommempool=tcp://*:28332
zmqpubremovedfrommempoolblock=tcp://*:28332

zmqpubinvalidtx=tcp://*:28332
invalidtxsink=ZMQ

EOL
    fi

  done

  mkdir -p $DIR/regtest/n1/regtest

  if [ ! -f "$DIR/regtest/n1/regtest/wallet.dat" ] && [ -f "$DIR/regtest_wallet.dat" ]; then
    echo "Creating $DIR/regtest/n1/regtest/wallet.dat..."
    cp "$DIR/regtest_wallet.dat" "$DIR/regtest/n1/regtest/wallet.dat"
  fi

  #IP=$(docker network inspect bridge --format='{{(index .IPAM.Config 0).Gateway}}')

  docker run --rm --platform linux/amd64 --name bitcoin-sv-regtest -p 18332:18332 -p 18333:18333 -p 28332:28332 --volume $DIR/regtest/n1:/data -d bitcoinsv/bitcoin-sv:latest bitcoind -minminingtxfee=0.00000001

else

  docker exec bitcoin-sv-regtest bitcoin-cli -conf=/data/bitcoin.conf $@

fi
