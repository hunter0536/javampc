#!/bin/bash

# 关闭已存在的节点并等待完全关闭
echo "Stopping existing nodes..."
pkill -f "java.*javampc" 2>/dev/null

# 等待所有 Java 进程退出
while pgrep -f "java.*javampc" > /dev/null; do
    echo "Waiting for nodes to stop..."
    sleep 1
done

echo "All nodes stopped. Starting new nodes..."
sleep 2

mkdir -p logs

# 启动节点1
nohup java -jar build/libs/mpc-0.0.1-SNAPSHOT.jar --spring.profiles.active=node1 > logs/node1.out 2>&1 &
NODE1_PID=$!
echo "Node 1 started with PID: $NODE1_PID"

# 启动节点2
nohup java -jar build/libs/mpc-0.0.1-SNAPSHOT.jar --spring.profiles.active=node2 > logs/node2.out 2>&1 &
NODE2_PID=$!
echo "Node 2 started with PID: $NODE2_PID"

# 启动节点3
nohup java -jar build/libs/mpc-0.0.1-SNAPSHOT.jar --spring.profiles.active=node3 > logs/node3.out 2>&1 &
NODE3_PID=$!
echo "Node 3 started with PID: $NODE3_PID"

# 启动节点4
nohup java -jar build/libs/mpc-0.0.1-SNAPSHOT.jar --spring.profiles.active=node4 > logs/node4.out 2>&1 &
NODE4_PID=$!
echo "Node 4 started with PID: $NODE4_PID"

# 启动节点5
nohup java -jar build/libs/mpc-0.0.1-SNAPSHOT.jar --spring.profiles.active=node5 > logs/node5.out 2>&1 &
NODE5_PID=$!
echo "Node 5 started with PID: $NODE5_PID"

echo "All nodes started successfully!"
echo "Node 1 PID: $NODE1_PID"
echo "Node 2 PID: $NODE2_PID"
echo "Node 3 PID: $NODE3_PID"
echo "Node 4 PID: $NODE4_PID"
echo "Node 5 PID: $NODE5_PID"
