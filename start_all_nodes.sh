#!/bin/bash

mkdir -p logs

JAR="build/libs/mpc-0.0.1-SNAPSHOT.jar"
if [ ! -f "$JAR" ]; then
  echo "Jar not found: $JAR"
  exit 1
fi

start_node() {
  local node_id="$1"
  local log_file="logs/node${node_id}.out"
  nohup java -jar "$JAR" --spring.profiles.active="node${node_id}" > "$log_file" 2>&1 &
  local pid=$!
  echo "Node ${node_id} started with PID: ${pid}"
  sleep 1
  if ! kill -0 "$pid" >/dev/null 2>&1; then
    echo "Node ${node_id} failed to start (PID ${pid} exited). See ${log_file}"
    if [ -s "$log_file" ]; then
      echo "---- ${log_file} (last 50 lines) ----"
      tail -n 50 "$log_file"
    fi
    exit 1
  fi
}

start_node 1
start_node 2
start_node 3
start_node 4
start_node 5

echo "All nodes started successfully!"
