package com.example.mpc.service;

import com.example.mpc.constant.Constants;
import com.example.mpc.util.ConnectionPool;
import org.springframework.stereotype.Service;

import java.io.File;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicLong;

@Service
public class DatabaseService {
    // 数据库连接池
    private final ConnectionPool connectionPool;
    private final AtomicLong statementCount = new AtomicLong(0);
    private final AtomicLong batchStatementCount = new AtomicLong(0);
    
    public DatabaseService() {
        // 初始化连接池
        this.connectionPool = new ConnectionPool();
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
                    wallet_id INTEGER NOT NULL,
                    share_index INTEGER NOT NULL,
                    key_share TEXT NOT NULL
                )
                """;
            
            try (Statement stmt = conn.createStatement()) {
                stmt.execute(createTableSql);
                statementCount.incrementAndGet();
            }
        } catch (TimeoutException e) {
            throw new SQLException("Timeout waiting for database connection", e);
        } finally {
            // 回收连接
            if (conn != null) {
                releaseConnection(conn, dbPath);
            }
        }
    }
    
    /**
     * 获取数据库连接（带连接池）
     * @param dbPath 数据库路径
     * @return 数据库连接
     */
    private Connection getConnection(String dbPath) throws SQLException, TimeoutException {
        return connectionPool.getConnection(dbPath);
    }
    
    /**
     * 回收数据库连接
     * @param conn 数据库连接
     * @param dbPath 数据库路径
     */
    private void releaseConnection(Connection conn, String dbPath) {
        connectionPool.releaseConnection(conn, dbPath);
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
        } catch (TimeoutException e) {
            throw new SQLException("Timeout waiting for database connection", e);
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
     * 关闭指定数据库的连接池
     * @param shareIndex 份额索引
     */
    public void closePool(int shareIndex) {
        String dbPath = Constants.DATABASES_DIR + File.separator + "share_" + shareIndex + ".db";
        connectionPool.closePool(dbPath);
    }
    
    /**
     * 关闭所有连接池
     */
    public void closeAllPools() {
        connectionPool.closeAllPools();
    }
    
    /**
     * 获取数据库操作统计信息
     * @return 统计信息
     */
    public Map<String, Object> getDatabaseStats() {
        Map<String, Object> stats = new HashMap<>();
        stats.put("statementCount", statementCount.get());
        stats.put("batchStatementCount", batchStatementCount.get());
        stats.putAll(connectionPool.getPoolStatus());
        return stats;
    }
}