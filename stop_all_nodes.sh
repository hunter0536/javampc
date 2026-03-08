#!/bin/bash

# 停止所有运行中的MPC节点

echo "正在查找并停止MPC节点进程..."

# 使用jps命令查找运行中的MPC节点进程
MPC_PROCESSES=$(jps | grep "mpc-0.0.1-SNAPSHOT.jar" | awk '{print $1}')

if [ -z "$MPC_PROCESSES" ]; then
    echo "没有找到运行中的MPC节点进程"
    exit 0
fi

echo "找到以下MPC节点进程: $MPC_PROCESSES"

# 终止找到的进程
for PID in $MPC_PROCESSES; do
    echo "终止进程 $PID"
    kill $PID
    if [ $? -eq 0 ]; then
        echo "进程 $PID 终止成功"
    else
        echo "进程 $PID 终止失败"
    fi
done

echo "所有MPC节点已停止"
