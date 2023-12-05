#!/bin/bash
cd ..
make clean
make -j DEBUG=1  # compile optionally with PRINTF
mv bin/ tests/bitcoin-bin
make clean
make -j DEBUG=1 COIN=nexa
mv bin/ tests/bitcoin-testnet-bin
