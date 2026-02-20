package com.example.mpc.service;

import com.example.mpc.constant.Constants;
import org.springframework.stereotype.Service;

import java.io.File;
import java.sql.*;

@Service
public class DatabaseService {
    // 数据库连接池
    private final ConcurrentHashMap<String, Connection> connectionPool = new ConcurrentHashMap<>();
    private final AtomicInteger activeConnections = new AtomicInteger(0);
    private final AtomicLong connectionCount = new AtomicLong(0);
    private final AtomicLong statementCount = new AtomicLong(0);
    private final AtomicLong batchStatementCount = new AtomicLong(0);
    
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
        try (Connection conn = getConnection(dbPath)) {
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
        }
    }
    
    /**
     * 获取数据库连接（带连接池）
     * @param dbPath 数据库路径
     * @return 数据库连接
     */
    private Connection getConnection(String dbPath) throws SQLException {
        return connectionPool.computeIfAbsent(dbPath, k -> {
            try {
                Connection conn = DriverManager.getConnection("jdbc:sqlite:" + dbPath);
                activeConnections.incrementAndGet();
                connectionCount.incrementAndGet();
                return conn;
            } catch (SQLException e) {
                throw new RuntimeException(e);
            }
        });
    }
    
    /**
     * 获取份额数据库连接
     * @param shareIndex 份额索引
     * @return 数据库连接
     */
    public Connection getShareConnection(int shareIndex) throws SQLException {
        String dbPath = Constants.DATABASES_DIR + File.separator + "share_" + shareIndex + ".db";
        return getConnection(dbPath);
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
     */
    public void closeConnection(Connection conn) {
        // 注意：由于使用连接池，这里不关闭连接，而是保持在池中
        // 实际应用中，应该实现连接池的管理和连接的回收
    }
    
    /**
     * 获取数据库操作统计信息
     * @return 统计信息
     */
    public Map<String, Object> getDatabaseStats() {
        Map<String, Object> stats = new HashMap<>();
        stats.put("activeConnections", activeConnections.get());
        stats.put("connectionCount", connectionCount.get());
        stats.put("connectionPoolSize", connectionPool.size());
        stats.put("statementCount", statementCount.get());
        stats.put("batchStatementCount", batchStatementCount.get());
        return stats;
    }
}