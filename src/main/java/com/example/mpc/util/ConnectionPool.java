package com.example.mpc.util;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Map;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

/**
 * 数据库连接池管理类，负责管理数据库连接的创建、获取、回收和销毁
 */
public class ConnectionPool {
    private static final Logger logger = LoggerFactory.getLogger(ConnectionPool.class);
    
    // 连接池配置
    private static final int MAX_POOL_SIZE = 10; // 最大连接数
    private static final int MIN_POOL_SIZE = 2; // 最小连接数
    private static final long CONNECTION_TIMEOUT = 30000; // 连接超时时间（毫秒）
    private static final long IDLE_TIMEOUT = 600000; // 空闲连接超时时间（毫秒）
    private static final long VALIDATION_INTERVAL = 300000; // 连接验证间隔（毫秒）
    
    // 连接池状态
    private final Map<String, ConcurrentLinkedQueue<PooledConnection>> connectionPools = new ConcurrentHashMap<>();
    private final Map<String, AtomicInteger> activeConnectionCounts = new ConcurrentHashMap<>();
    private final AtomicLong connectionCount = new AtomicLong(0);
    private final AtomicLong connectionCreateCount = new AtomicLong(0);
    private final AtomicLong connectionCloseCount = new AtomicLong(0);
    private final AtomicLong connectionReuseCount = new AtomicLong(0);
    
    // 连接池维护任务
    private final ScheduledExecutorService poolMaintenanceExecutor;
    
    public ConnectionPool() {
        // 初始化连接池维护线程
        poolMaintenanceExecutor = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "connection-pool-maintenance");
            t.setDaemon(true);
            return t;
        });
        
        // 启动连接池维护任务
        poolMaintenanceExecutor.scheduleWithFixedDelay(
                this::maintainPools,
                VALIDATION_INTERVAL,
                VALIDATION_INTERVAL,
                TimeUnit.MILLISECONDS
        );
    }
    
    /**
     * 获取数据库连接
     * @param dbPath 数据库路径
     * @return 数据库连接
     */
    public Connection getConnection(String dbPath) throws SQLException, TimeoutException {
        String url = "jdbc:sqlite:" + dbPath;
        
        // 获取或创建对应数据库的连接池
        ConcurrentLinkedQueue<PooledConnection> pool = connectionPools.computeIfAbsent(dbPath, k -> {
            ConcurrentLinkedQueue<PooledConnection> newPool = new ConcurrentLinkedQueue<>();
            activeConnectionCounts.put(dbPath, new AtomicInteger(0));
            return newPool;
        });
        
        AtomicInteger activeCount = activeConnectionCounts.get(dbPath);
        
        // 尝试从池中获取可用连接
        PooledConnection pooledConnection = null;
        while (pooledConnection == null) {
            // 检查是否达到最大连接数
            if (activeCount.get() >= MAX_POOL_SIZE) {
                // 等待一段时间后重试
                try {
                    Thread.sleep(50);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    throw new SQLException("Connection pool interrupted", e);
                }
                continue;
            }
            
            // 从池中获取连接
            pooledConnection = pool.poll();
            if (pooledConnection != null) {
                // 验证连接是否有效
                if (isConnectionValid(pooledConnection)) {
                    pooledConnection.lastUsed = System.currentTimeMillis();
                    activeCount.incrementAndGet();
                    connectionReuseCount.incrementAndGet();
                    logger.debug("Reusing connection for {} (active: {})");
                    return pooledConnection.connection;
                } else {
                    // 连接无效，关闭并创建新连接
                    closeConnection(pooledConnection);
                    connectionCloseCount.incrementAndGet();
                    pooledConnection = null;
                }
            } else {
                // 池中无可用连接，创建新连接
                if (activeCount.get() < MAX_POOL_SIZE) {
                    pooledConnection = createConnection(url, dbPath);
                    activeCount.incrementAndGet();
                    logger.debug("Created new connection for {} (active: {})");
                    return pooledConnection.connection;
                }
            }
        }
        
        throw new TimeoutException("Timeout waiting for database connection");
    }
    
    /**
     * 回收数据库连接
     * @param conn 数据库连接
     * @param dbPath 数据库路径
     */
    public void releaseConnection(Connection conn, String dbPath) {
        if (conn == null) {
            return;
        }
        
        ConcurrentLinkedQueue<PooledConnection> pool = connectionPools.get(dbPath);
        AtomicInteger activeCount = activeConnectionCounts.get(dbPath);
        
        if (pool != null && activeCount != null) {
            // 查找对应的PooledConnection
            for (PooledConnection pooledConn : pool) {
                if (pooledConn.connection == conn) {
                    pooledConn.lastUsed = System.currentTimeMillis();
                    pool.offer(pooledConn);
                    activeCount.decrementAndGet();
                    logger.debug("Released connection for {} (active: {})");
                    return;
                }
            }
            
            // 如果找不到对应的PooledConnection，说明是新创建的连接
            try {
                conn.close();
                connectionCloseCount.incrementAndGet();
                activeCount.decrementAndGet();
                logger.debug("Closed new connection for {}");
            } catch (SQLException e) {
                logger.error("Error closing connection: {}", e.getMessage());
            }
        } else {
            // 连接池不存在，直接关闭连接
            try {
                conn.close();
                connectionCloseCount.incrementAndGet();
                logger.debug("Closed connection (pool not found)");
            } catch (SQLException e) {
                logger.error("Error closing connection: {}", e.getMessage());
            }
        }
    }
    
    /**
     * 创建新的数据库连接
     * @param url 数据库URL
     * @param dbPath 数据库路径
     * @return 池化连接
     */
    private PooledConnection createConnection(String url, String dbPath) throws SQLException {
        Connection conn = DriverManager.getConnection(url);
        PooledConnection pooledConn = new PooledConnection(conn, dbPath);
        connectionCreateCount.incrementAndGet();
        connectionCount.incrementAndGet();
        return pooledConn;
    }
    
    /**
     * 验证连接是否有效
     * @param pooledConnection 池化连接
     * @return 是否有效
     */
    private boolean isConnectionValid(PooledConnection pooledConnection) {
        if (pooledConnection == null || pooledConnection.connection == null) {
            return false;
        }
        
        // 检查连接是否已超时
        if (System.currentTimeMillis() - pooledConnection.lastUsed > IDLE_TIMEOUT) {
            logger.debug("Connection expired: {}");
            return false;
        }
        
        // 检查连接是否已关闭
        try {
            if (pooledConnection.connection.isClosed()) {
                logger.debug("Connection closed: {}");
                return false;
            }
            
            // 执行简单的SQL语句验证连接
            try (Statement stmt = pooledConnection.connection.createStatement()) {
                stmt.execute("SELECT 1");
                return true;
            }
        } catch (SQLException e) {
            logger.debug("Connection validation failed: {}", e.getMessage());
            return false;
        }
    }
    
    /**
     * 关闭连接
     * @param pooledConnection 池化连接
     */
    private void closeConnection(PooledConnection pooledConnection) {
        if (pooledConnection != null && pooledConnection.connection != null) {
            try {
                pooledConnection.connection.close();
                connectionCloseCount.incrementAndGet();
                connectionCount.decrementAndGet();
                logger.debug("Closed connection: {}");
            } catch (SQLException e) {
                logger.error("Error closing connection: {}", e.getMessage());
            }
        }
    }
    
    /**
     * 维护连接池
     * - 移除无效连接
     * - 确保最小连接数
     */
    private void maintainPools() {
        logger.debug("Maintaining connection pools...");
        
        for (Map.Entry<String, ConcurrentLinkedQueue<PooledConnection>> entry : connectionPools.entrySet()) {
            String dbPath = entry.getKey();
            ConcurrentLinkedQueue<PooledConnection> pool = entry.getValue();
            AtomicInteger activeCount = activeConnectionCounts.get(dbPath);
            
            if (pool == null || activeCount == null) {
                continue;
            }
            
            // 清理无效连接
            ConcurrentLinkedQueue<PooledConnection> validConnections = new ConcurrentLinkedQueue<>();
            while (!pool.isEmpty()) {
                PooledConnection conn = pool.poll();
                if (isConnectionValid(conn)) {
                    validConnections.offer(conn);
                } else {
                    closeConnection(conn);
                }
            }
            
            // 将有效连接放回池
            pool.addAll(validConnections);
            
            // 确保最小连接数
            while (pool.size() + activeCount.get() < MIN_POOL_SIZE && activeCount.get() < MAX_POOL_SIZE) {
                try {
                    PooledConnection newConn = createConnection("jdbc:sqlite:" + dbPath, dbPath);
                    pool.offer(newConn);
                    logger.debug("Created min pool connection for {}");
                } catch (SQLException e) {
                    logger.error("Error creating min pool connection: {}", e.getMessage());
                    break;
                }
            }
        }
        
        logger.debug("Connection pool maintenance completed");
    }
    
    /**
     * 关闭指定数据库的连接池
     * @param dbPath 数据库路径
     */
    public void closePool(String dbPath) {
        ConcurrentLinkedQueue<PooledConnection> pool = connectionPools.remove(dbPath);
        activeConnectionCounts.remove(dbPath);
        
        if (pool != null) {
            while (!pool.isEmpty()) {
                PooledConnection conn = pool.poll();
                closeConnection(conn);
            }
            logger.debug("Closed connection pool for {}");
        }
    }
    
    /**
     * 关闭所有连接池
     */
    public void closeAllPools() {
        for (String dbPath : connectionPools.keySet()) {
            closePool(dbPath);
        }
        
        // 关闭维护线程
        poolMaintenanceExecutor.shutdown();
        try {
            if (!poolMaintenanceExecutor.awaitTermination(5, TimeUnit.SECONDS)) {
                poolMaintenanceExecutor.shutdownNow();
            }
        } catch (InterruptedException e) {
            poolMaintenanceExecutor.shutdownNow();
            Thread.currentThread().interrupt();
        }
        
        logger.debug("Closed all connection pools");
    }
    
    /**
     * 获取连接池状态
     * @return 状态信息
     */
    public Map<String, Object> getPoolStatus() {
        Map<String, Object> status = new ConcurrentHashMap<>();
        status.put("totalConnections", connectionCount.get());
        status.put("connectionCreateCount", connectionCreateCount.get());
        status.put("connectionCloseCount", connectionCloseCount.get());
        status.put("connectionReuseCount", connectionReuseCount.get());
        
        Map<String, Object> poolDetails = new ConcurrentHashMap<>();
        for (Map.Entry<String, ConcurrentLinkedQueue<PooledConnection>> entry : connectionPools.entrySet()) {
            String dbPath = entry.getKey();
            ConcurrentLinkedQueue<PooledConnection> pool = entry.getValue();
            AtomicInteger activeCount = activeConnectionCounts.get(dbPath);
            
            if (activeCount != null) {
                Map<String, Object> poolStatus = new ConcurrentHashMap<>();
                poolStatus.put("idleConnections", pool.size());
                poolStatus.put("activeConnections", activeCount.get());
                poolStatus.put("totalConnections", pool.size() + activeCount.get());
                poolDetails.put(dbPath, poolStatus);
            }
        }
        
        status.put("poolDetails", poolDetails);
        return status;
    }
    
    /**
     * 池化连接包装类
     */
    private static class PooledConnection {
        final Connection connection;
        final String dbPath;
        long lastUsed;
        
        PooledConnection(Connection connection, String dbPath) {
            this.connection = connection;
            this.dbPath = dbPath;
            this.lastUsed = System.currentTimeMillis();
        }
    }
}
