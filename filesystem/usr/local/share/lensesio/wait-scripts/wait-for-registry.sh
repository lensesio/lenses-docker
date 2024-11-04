#!/usr/bin/env bash

W_ITERATIONS=${W_ITERATIONS:-90}
W_PERIOD_SECS=${W_PERIOD_SECS:-2}
W_SR_ADDRESS=${W_SR_ADDRESS:-http://localhost:$REGISTRY_PORT}

for ((i=0;i<$W_ITERATIONS;i++)); do
    sleep $W_PERIOD_SECS
    wget -q -t 1 "$W_SR_ADDRESS" -O - | grep "{}" && break
done

