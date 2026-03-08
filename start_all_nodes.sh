#!/bin/bash

# 启动所有五个节点（后台运行）

# 启动节点1
nohup java -jar build/libs/mpc-0.0.1-SNAPSHOT.jar --spring.profiles.active=node1 &
NODE1_PID=$!
echo "Node 1 started with PID: $NODE1_PID"

# 启动节点2
nohup java -jar build/libs/mpc-0.0.1-SNAPSHOT.jar --spring.profiles.active=node2 &
NODE2_PID=$!
echo "Node 2 started with PID: $NODE2_PID"

# 启动节点3
nohup java -jar build/libs/mpc-0.0.1-SNAPSHOT.jar --spring.profiles.active=node3 &
NODE3_PID=$!
echo "Node 3 started with PID: $NODE3_PID"

# 启动节点4
nohup java -jar build/libs/mpc-0.0.1-SNAPSHOT.jar --spring.profiles.active=node4 &
NODE4_PID=$!
echo "Node 4 started with PID: $NODE4_PID"

# 启动节点5
nohup java -jar build/libs/mpc-0.0.1-SNAPSHOT.jar --spring.profiles.active=node5 &
NODE5_PID=$!
echo "Node 5 started with PID: $NODE5_PID"

echo "All nodes started successfully!"
echo "Node 1 PID: $NODE1_PID"
echo "Node 2 PID: $NODE2_PID"
echo "Node 3 PID: $NODE3_PID"
echo "Node 4 PID: $NODE4_PID"
echo "Node 5 PID: $NODE5_PID"
