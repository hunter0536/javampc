package com.example.mpc.service;

import com.example.mpc.constant.Constants;
import org.springframework.stereotype.Service;

import java.io.File;
import java.sql.*;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.Executor;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

@Service
public class DatabaseService {
    private final AtomicLong statementCount = new AtomicLong(0);
    private final AtomicLong batchStatementCount = new AtomicLong(0);
    private final AtomicLong connectionCount = new AtomicLong(0);
    private final AtomicLong connectionReuseCount = new AtomicLong(0);
    
    // 数据库连接池（按数据库路径分池）
    private final Map<String, ConnectionPool> connectionPools = new java.util.concurrent.ConcurrentHashMap<>();
    private static final int MAX_POOL_SIZE = 10;
    private static final long MAX_IDLE_TIME = 30000; // 30秒
    
    public DatabaseService() {
    }
    
    // 内部连接池类
    private class ConnectionPool {
        private final String dbPath;
        private final BlockingQueue<PooledConnection> pool;
        private final AtomicInteger activeConnections = new AtomicInteger(0);
        private final AtomicInteger totalConnections = new AtomicInteger(0);
        
        public ConnectionPool(String dbPath) {
            this.dbPath = dbPath;
            this.pool = new LinkedBlockingQueue<>(MAX_POOL_SIZE);
        }
        
        public Connection getConnection() throws SQLException, InterruptedException {
            // 尝试从池中获取连接
            PooledConnection conn = pool.poll(500, TimeUnit.MILLISECONDS);
            
            if (conn != null) {
                // 检查连接是否有效
                if (conn.isValid()) {
                    connectionReuseCount.incrementAndGet();
                    activeConnections.incrementAndGet();
                    return conn;
                } else {
                    // 连接无效，关闭并创建新连接
                    try {
                        conn.close();
                        totalConnections.decrementAndGet();
                    } catch (SQLException e) {
                        // 忽略关闭异常
                    }
                }
            }
            
            // 池中没有可用连接，创建新连接
            if (totalConnections.get() < MAX_POOL_SIZE) {
                conn = createConnection();
                activeConnections.incrementAndGet();
                return conn;
            }
            
            // 达到最大连接数，等待
            conn = pool.take();
            while (!conn.isValid()) {
                try {
                    conn.close();
                    totalConnections.decrementAndGet();
                } catch (SQLException e) {
                    // 忽略关闭异常
                }
                conn = pool.take();
            }
            connectionReuseCount.incrementAndGet();
            activeConnections.incrementAndGet();
            return conn;
        }
        
        public void releaseConnection(Connection conn) {
            if (conn instanceof PooledConnection) {
                PooledConnection pooledConn = (PooledConnection) conn;
                try {
                    if (pooledConn.isValid()) {
                        if (!pool.offer(pooledConn, 100, TimeUnit.MILLISECONDS)) {
                            // 池已满，关闭多余的连接
                            pooledConn.close();
                            totalConnections.decrementAndGet();
                        }
                    } else {
                        pooledConn.close();
                        totalConnections.decrementAndGet();
                    }
                } catch (Exception e) {
                    // 忽略异常
                } finally {
                    activeConnections.decrementAndGet();
                }
            }
        }
        
        private PooledConnection createConnection() throws SQLException {
            String url = "jdbc:sqlite:" + dbPath;
            Connection conn = DriverManager.getConnection(url);
            totalConnections.incrementAndGet();
            connectionCount.incrementAndGet();
            return new PooledConnection(conn);
        }
        
        public void close() {
            PooledConnection conn;
            while ((conn = pool.poll()) != null) {
                try {
                    conn.close();
                } catch (SQLException e) {
                    // 忽略关闭异常
                }
            }
        }
        
        public int getActiveConnections() {
            return activeConnections.get();
        }
        
        public int getTotalConnections() {
            return totalConnections.get();
        }
    }
    
    // 包装连接，添加验证功能
    private class PooledConnection implements Connection {
        private final Connection delegate;
        private final long createTime;
        private long lastUsedTime;
        
        public PooledConnection(Connection delegate) {
            this.delegate = delegate;
            this.createTime = System.currentTimeMillis();
            this.lastUsedTime = createTime;
        }
        
        public boolean isValid() {
            try {
                if (delegate.isClosed()) {
                    return false;
                }
                
                if (System.currentTimeMillis() - lastUsedTime > MAX_IDLE_TIME) {
                    delegate.close();
                    return false;
                }
                
                // 测试连接
                try (Statement stmt = delegate.createStatement()) {
                    stmt.executeQuery("SELECT 1");
                }
                
                lastUsedTime = System.currentTimeMillis();
                return true;
            } catch (SQLException e) {
                return false;
            }
        }
        
        @Override
        public void close() throws SQLException {
            delegate.close();
        }
        
        // 其他Connection方法委托给delegate
        @Override
        public <T> T unwrap(Class<T> iface) throws SQLException {
            return delegate.unwrap(iface);
        }
        
        @Override
        public boolean isWrapperFor(Class<?> iface) throws SQLException {
            return delegate.isWrapperFor(iface);
        }
        
        @Override
        public Statement createStatement() throws SQLException {
            lastUsedTime = System.currentTimeMillis();
            return delegate.createStatement();
        }
        
        @Override
        public PreparedStatement prepareStatement(String sql) throws SQLException {
            lastUsedTime = System.currentTimeMillis();
            return delegate.prepareStatement(sql);
        }
        
        @Override
        public CallableStatement prepareCall(String sql) throws SQLException {
            lastUsedTime = System.currentTimeMillis();
            return delegate.prepareCall(sql);
        }
        
        @Override
        public String nativeSQL(String sql) throws SQLException {
            return delegate.nativeSQL(sql);
        }
        
        @Override
        public void setAutoCommit(boolean autoCommit) throws SQLException {
            delegate.setAutoCommit(autoCommit);
        }
        
        @Override
        public boolean getAutoCommit() throws SQLException {
            return delegate.getAutoCommit();
        }
        
        @Override
        public void commit() throws SQLException {
            delegate.commit();
        }
        
        @Override
        public void rollback() throws SQLException {
            delegate.rollback();
        }
        
        @Override
        public boolean isClosed() throws SQLException {
            return delegate.isClosed();
        }
        
        @Override
        public DatabaseMetaData getMetaData() throws SQLException {
            return delegate.getMetaData();
        }
        
        @Override
        public void setReadOnly(boolean readOnly) throws SQLException {
            delegate.setReadOnly(readOnly);
        }
        
        @Override
        public boolean isReadOnly() throws SQLException {
            return delegate.isReadOnly();
        }
        
        @Override
        public void setCatalog(String catalog) throws SQLException {
            delegate.setCatalog(catalog);
        }
        
        @Override
        public String getCatalog() throws SQLException {
            return delegate.getCatalog();
        }
        
        @Override
        public void setTransactionIsolation(int level) throws SQLException {
            delegate.setTransactionIsolation(level);
        }
        
        @Override
        public int getTransactionIsolation() throws SQLException {
            return delegate.getTransactionIsolation();
        }
        
        @Override
        public Savepoint setSavepoint() throws SQLException {
            return delegate.setSavepoint();
        }
        
        @Override
        public Savepoint setSavepoint(String name) throws SQLException {
            return delegate.setSavepoint(name);
        }
        
        @Override
        public void rollback(Savepoint savepoint) throws SQLException {
            delegate.rollback(savepoint);
        }
        
        @Override
        public void releaseSavepoint(Savepoint savepoint) throws SQLException {
            delegate.releaseSavepoint(savepoint);
        }
        
        @Override
        public void setTypeMap(Map<String, Class<?>> map) throws SQLException {
            delegate.setTypeMap(map);
        }
        
        @Override
        public Map<String, Class<?>> getTypeMap() throws SQLException {
            return delegate.getTypeMap();
        }
        
        @Override
        public void setHoldability(int holdability) throws SQLException {
            delegate.setHoldability(holdability);
        }
        
        @Override
        public int getHoldability() throws SQLException {
            return delegate.getHoldability();
        }
        
        @Override
        public Statement createStatement(int resultSetType, int resultSetConcurrency) throws SQLException {
            lastUsedTime = System.currentTimeMillis();
            return delegate.createStatement(resultSetType, resultSetConcurrency);
        }
        
        @Override
        public PreparedStatement prepareStatement(String sql, int resultSetType, int resultSetConcurrency) throws SQLException {
            lastUsedTime = System.currentTimeMillis();
            return delegate.prepareStatement(sql, resultSetType, resultSetConcurrency);
        }
        
        @Override
        public CallableStatement prepareCall(String sql, int resultSetType, int resultSetConcurrency) throws SQLException {
            lastUsedTime = System.currentTimeMillis();
            return delegate.prepareCall(sql, resultSetType, resultSetConcurrency);
        }
        
        @Override
        public Statement createStatement(int resultSetType, int resultSetConcurrency, int resultSetHoldability) throws SQLException {
            lastUsedTime = System.currentTimeMillis();
            return delegate.createStatement(resultSetType, resultSetConcurrency, resultSetHoldability);
        }
        
        @Override
        public PreparedStatement prepareStatement(String sql, int resultSetType, int resultSetConcurrency, int resultSetHoldability) throws SQLException {
            lastUsedTime = System.currentTimeMillis();
            return delegate.prepareStatement(sql, resultSetType, resultSetConcurrency, resultSetHoldability);
        }
        
        @Override
        public CallableStatement prepareCall(String sql, int resultSetType, int resultSetConcurrency, int resultSetHoldability) throws SQLException {
            lastUsedTime = System.currentTimeMillis();
            return delegate.prepareCall(sql, resultSetType, resultSetConcurrency, resultSetHoldability);
        }
        
        @Override
        public PreparedStatement prepareStatement(String sql, int autoGeneratedKeys) throws SQLException {
            lastUsedTime = System.currentTimeMillis();
            return delegate.prepareStatement(sql, autoGeneratedKeys);
        }
        
        @Override
        public PreparedStatement prepareStatement(String sql, int[] columnIndexes) throws SQLException {
            lastUsedTime = System.currentTimeMillis();
            return delegate.prepareStatement(sql, columnIndexes);
        }
        
        @Override
        public PreparedStatement prepareStatement(String sql, String[] columnNames) throws SQLException {
            lastUsedTime = System.currentTimeMillis();
            return delegate.prepareStatement(sql, columnNames);
        }
        
        @Override
        public Clob createClob() throws SQLException {
            return delegate.createClob();
        }
        
        @Override
        public Blob createBlob() throws SQLException {
            return delegate.createBlob();
        }
        
        @Override
        public NClob createNClob() throws SQLException {
            return delegate.createNClob();
        }
        
        @Override
        public SQLXML createSQLXML() throws SQLException {
            return delegate.createSQLXML();
        }
        
        @Override
        public boolean isValid(int timeout) throws SQLException {
            return delegate.isValid(timeout);
        }
        
        @Override
        public SQLWarning getWarnings() throws SQLException {
            return delegate.getWarnings();
        }
        
        @Override
        public void clearWarnings() throws SQLException {
            delegate.clearWarnings();
        }
        
        @Override
        public void setClientInfo(String name, String value) throws SQLClientInfoException {
            delegate.setClientInfo(name, value);
        }
        
        @Override
        public void setClientInfo(Properties properties) throws SQLClientInfoException {
            delegate.setClientInfo(properties);
        }
        
        @Override
        public String getClientInfo(String name) throws SQLException {
            return delegate.getClientInfo(name);
        }
        
        @Override
        public Properties getClientInfo() throws SQLException {
            return delegate.getClientInfo();
        }
        
        @Override
        public Array createArrayOf(String typeName, Object[] elements) throws SQLException {
            return delegate.createArrayOf(typeName, elements);
        }
        
        @Override
        public Struct createStruct(String typeName, Object[] attributes) throws SQLException {
            return delegate.createStruct(typeName, attributes);
        }
        
        @Override
        public void setSchema(String schema) throws SQLException {
            delegate.setSchema(schema);
        }
        
        @Override
        public String getSchema() throws SQLException {
            return delegate.getSchema();
        }
        
        @Override
        public void abort(Executor executor) throws SQLException {
            delegate.abort(executor);
        }
        
        @Override
        public void setNetworkTimeout(Executor executor, int milliseconds) throws SQLException {
            delegate.setNetworkTimeout(executor, milliseconds);
        }
        
        @Override
        public int getNetworkTimeout() throws SQLException {
            return delegate.getNetworkTimeout();
        }
    }
    
    /**
     * 初始化份额数据库
     * @param shareIndex 份额索引
     */
    public void initShareDatabase(int shareIndex) throws SQLException {
        // 创建数据库目录
        File dir = new File(Constants.DATABASES_DIR);
        if (!dir.exists()) {
            dir.mkdirs();
        }
        
        // 数据库文件路径
        String dbPath = Constants.DATABASES_DIR + File.separator + "share_" + shareIndex + ".db";
        
        // 连接数据库
        Connection conn = null;
        try {
            conn = getConnection(dbPath);
            // 创建密钥份额表
            String createTableSql = """
                CREATE TABLE IF NOT EXISTS key_shares (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    share_index INTEGER NOT NULL,
                    key_share TEXT NOT NULL,
                    group_public_key TEXT NOT NULL,
                    dkg_task_id TEXT NOT NULL
                )
                """;
            
            try (Statement stmt = conn.createStatement()) {
                stmt.execute(createTableSql);
                statementCount.incrementAndGet();
                ensureKeyShareColumn(stmt, "group_public_key", "TEXT");
                ensureKeyShareColumn(stmt, "dkg_task_id", "TEXT");
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new SQLException("Connection interrupted", e);
        } finally {
            // 释放连接
            if (conn != null) {
                releaseConnection(conn, dbPath);
            }
        }
    }

    private void ensureKeyShareColumn(Statement stmt, String columnName, String columnType) {
        try {
            boolean exists = false;
            try (ResultSet rs = stmt.executeQuery("PRAGMA table_info(key_shares)")) {
                while (rs.next()) {
                    String name = rs.getString("name");
                    if (columnName.equalsIgnoreCase(name)) {
                        exists = true;
                        break;
                    }
                }
            }
            if (!exists) {
                stmt.execute("ALTER TABLE key_shares ADD COLUMN " + columnName + " " + columnType);
                statementCount.incrementAndGet();
            }
        } catch (SQLException e) {
            // Ignore migration errors to avoid breaking startup on existing DBs.
        }
    }
    
    /**
     * 获取数据库连接
     * @param dbPath 数据库路径
     * @return 数据库连接
     */
    private Connection getConnection(String dbPath) throws SQLException, InterruptedException {
        // 获取或创建对应数据库的连接池
        ConnectionPool pool = connectionPools.computeIfAbsent(dbPath, ConnectionPool::new);
        return pool.getConnection();
    }
    
    /**
     * 释放数据库连接
     * @param conn 数据库连接
     * @param dbPath 数据库路径
     */
    private void releaseConnection(Connection conn, String dbPath) {
        if (conn != null) {
            ConnectionPool pool = connectionPools.get(dbPath);
            if (pool != null) {
                pool.releaseConnection(conn);
            } else {
                try {
                    conn.close();
                } catch (SQLException e) {
                    // 忽略关闭异常
                }
            }
        }
    }
    
    /**
     * 获取份额数据库连接
     * @param shareIndex 份额索引
     * @return 数据库连接
     */
    public Connection getShareConnection(int shareIndex) throws SQLException {
        String dbPath = Constants.DATABASES_DIR + File.separator + "share_" + shareIndex + ".db";
        try {
            return getConnection(dbPath);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new SQLException("Connection interrupted", e);
        }
    }
    
    /**
     * 回收份额数据库连接
     * @param conn 数据库连接
     * @param shareIndex 份额索引
     */
    public void releaseShareConnection(Connection conn, int shareIndex) {
        String dbPath = Constants.DATABASES_DIR + File.separator + "share_" + shareIndex + ".db";
        releaseConnection(conn, dbPath);
    }
    
    /**
     * 批量执行SQL语句
     * @param conn 数据库连接
     * @param sql SQL语句
     * @param batchParams 批量参数
     * @return 影响的行数
     */
    public int[] executeBatch(Connection conn, String sql, List<Object[]> batchParams) throws SQLException {
        try (PreparedStatement pstmt = conn.prepareStatement(sql)) {
            for (Object[] params : batchParams) {
                for (int i = 0; i < params.length; i++) {
                    pstmt.setObject(i + 1, params[i]);
                }
                pstmt.addBatch();
            }
            int[] result = pstmt.executeBatch();
            batchStatementCount.incrementAndGet();
            return result;
        }
    }
    
    /**
     * 关闭数据库连接
     * @param conn 数据库连接
     * @param shareIndex 份额索引
     */
    public void closeConnection(Connection conn, int shareIndex) {
        if (conn != null) {
            releaseShareConnection(conn, shareIndex);
        }
    }
    
    /**
     * 获取数据库操作统计信息
     * @return 统计信息
     */
    public Map<String, Object> getDatabaseStats() {
        Map<String, Object> stats = new HashMap<>();
        stats.put("statementCount", statementCount.get());
        stats.put("batchStatementCount", batchStatementCount.get());
        stats.put("connectionCount", connectionCount.get());
        stats.put("connectionReuseCount", connectionReuseCount.get());
        
        // 添加连接池详细信息
        Map<String, Object> poolStats = new HashMap<>();
        for (Map.Entry<String, ConnectionPool> entry : connectionPools.entrySet()) {
            ConnectionPool pool = entry.getValue();
            Map<String, Object> poolInfo = new HashMap<>();
            poolInfo.put("activeConnections", pool.getActiveConnections());
            poolInfo.put("totalConnections", pool.getTotalConnections());
            poolStats.put(entry.getKey(), poolInfo);
        }
        stats.put("connectionPools", poolStats);
        
        return stats;
    }
}
