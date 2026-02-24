package com.example.mpc.dao;

import com.example.mpc.model.AuxInfo;
import com.example.mpc.service.DatabaseService;
import com.example.mpc.common.util.ThreadPoolUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.util.concurrent.CompletableFuture;

@Repository
public class AuxInfoDao {
    private static final Logger logger = LoggerFactory.getLogger(AuxInfoDao.class);

    private static final String INSERT_SQL = "INSERT INTO aux_info (node_id, task_id, paillier_p, paillier_q, paillier_n, paillier_g, paillier_bit_length, pedersen_hat_n, pedersen_s, pedersen_t) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
    private static final String SELECT_LAST_ID_SQL = "SELECT last_insert_rowid()";
    private static final String SELECT_LATEST_SQL = "SELECT id, node_id, task_id, paillier_p, paillier_q, paillier_n, paillier_g, paillier_bit_length, pedersen_hat_n, pedersen_s, pedersen_t FROM aux_info WHERE node_id = ? ORDER BY id DESC LIMIT 1";

    @Autowired
    private DatabaseService databaseService;

    public void save(AuxInfo info) throws SQLException {
        Connection conn = null;
        PreparedStatement insertStmt = null;
        PreparedStatement selectStmt = null;
        try {
            conn = databaseService.getShareConnection(info.getNodeId());
            insertStmt = conn.prepareStatement(INSERT_SQL);
            selectStmt = conn.prepareStatement(SELECT_LAST_ID_SQL);

            int index = 1;
            insertStmt.setInt(index++, info.getNodeId());
            insertStmt.setString(index++, info.getTaskId());
            insertStmt.setString(index++, info.getPaillierP());
            insertStmt.setString(index++, info.getPaillierQ());
            insertStmt.setString(index++, info.getPaillierN());
            insertStmt.setString(index++, info.getPaillierG());
            insertStmt.setInt(index++, info.getPaillierBitLength() == null ? 0 : info.getPaillierBitLength());
            insertStmt.setString(index++, info.getPedersenHatN());
            insertStmt.setString(index++, info.getPedersenS());
            insertStmt.setString(index, info.getPedersenT());
            insertStmt.executeUpdate();

            var rs = selectStmt.executeQuery();
            if (rs.next()) {
                info.setId(rs.getLong(1));
            }
        } finally {
            closeStatement(selectStmt);
            closeStatement(insertStmt);
            if (conn != null) {
                databaseService.releaseShareConnection(conn, info.getNodeId());
            }
        }
    }

    public CompletableFuture<AuxInfo> loadLatest(int nodeId) {
        return CompletableFuture.supplyAsync(() -> loadLatestSync(nodeId), ThreadPoolUtil.getIoThreadPool());
    }

    public AuxInfo loadLatestSync(int nodeId) {
        Connection conn = null;
        PreparedStatement pstmt = null;
        try {
            conn = databaseService.getShareConnection(nodeId);
            pstmt = conn.prepareStatement(SELECT_LATEST_SQL);
            pstmt.setInt(1, nodeId);
            var rs = pstmt.executeQuery();
            if (rs.next()) {
                AuxInfo info = new AuxInfo();
                info.setId(rs.getLong("id"));
                info.setNodeId(rs.getInt("node_id"));
                info.setTaskId(rs.getString("task_id"));
                info.setPaillierP(rs.getString("paillier_p"));
                info.setPaillierQ(rs.getString("paillier_q"));
                info.setPaillierN(rs.getString("paillier_n"));
                info.setPaillierG(rs.getString("paillier_g"));
                info.setPaillierBitLength(rs.getInt("paillier_bit_length"));
                info.setPedersenHatN(rs.getString("pedersen_hat_n"));
                info.setPedersenS(rs.getString("pedersen_s"));
                info.setPedersenT(rs.getString("pedersen_t"));
                return info;
            }
            return null;
        } catch (Exception e) {
            logger.error("Error loading aux info: {}", e.getMessage());
            throw new RuntimeException(e);
        } finally {
            closeStatement(pstmt);
            if (conn != null) {
                databaseService.releaseShareConnection(conn, nodeId);
            }
        }
    }

    private void closeStatement(PreparedStatement stmt) {
        if (stmt != null) {
            try {
                stmt.close();
            } catch (SQLException e) {
                logger.error("Error closing statement: {}", e.getMessage());
            }
        }
    }
}
