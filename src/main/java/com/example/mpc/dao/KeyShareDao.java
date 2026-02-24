package com.example.mpc.dao;

import com.example.mpc.model.KeyShare;
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
public class KeyShareDao {
    private static final Logger logger = LoggerFactory.getLogger(KeyShareDao.class);

    private static final String INSERT_SQL = "INSERT INTO key_shares (share_index, key_share, group_public_key, dkg_task_id, public_shares, index_map, chain_code) VALUES (?, ?, ?, ?, ?, ?, ?)";
    private static final String SELECT_LAST_ID_SQL = "SELECT last_insert_rowid()";
    private static final String SELECT_BY_GROUP_KEY_SQL = "SELECT id, share_index, key_share, group_public_key, dkg_task_id, public_shares, index_map, chain_code FROM key_shares WHERE group_public_key = ? ORDER BY id DESC LIMIT 1";

    @Autowired
    private DatabaseService databaseService;

    public void save(KeyShare keyShare) throws SQLException {
        Connection conn = null;
        PreparedStatement insertStmt = null;
        PreparedStatement selectStmt = null;
        try {
            conn = databaseService.getShareConnection(keyShare.getShareIndex());
            insertStmt = conn.prepareStatement(INSERT_SQL);
            selectStmt = conn.prepareStatement(SELECT_LAST_ID_SQL);

            int index = 1;
            insertStmt.setInt(index++, keyShare.getShareIndex());
            insertStmt.setString(index++, keyShare.getKeyShare());
            insertStmt.setString(index++, keyShare.getGroupPublicKey());
            insertStmt.setString(index++, keyShare.getDkgTaskId());
            insertStmt.setString(index++, keyShare.getPublicShares());
            insertStmt.setString(index++, keyShare.getIndexMap());
            insertStmt.setString(index, keyShare.getChainCode());
            insertStmt.executeUpdate();

            var rs = selectStmt.executeQuery();
            if (rs.next()) {
                keyShare.setId(rs.getLong(1));
            }
        } finally {
            closeStatement(selectStmt);
            closeStatement(insertStmt);
            if (conn != null) {
                databaseService.releaseShareConnection(conn, keyShare.getShareIndex());
            }
        }
    }

    public CompletableFuture<KeyShare> findByGroupPublicKey(int shareIndex, String groupPublicKey) {
        return CompletableFuture.supplyAsync(() -> findByGroupPublicKeySync(shareIndex, groupPublicKey), ThreadPoolUtil.getIoThreadPool());
    }

    public KeyShare findByGroupPublicKeySync(int shareIndex, String groupPublicKey) {
        Connection conn = null;
        PreparedStatement pstmt = null;
        try {
            logger.info("Loading key share for group public key: {}", groupPublicKey);
            logger.info("Share index: {}", shareIndex);

            conn = databaseService.getShareConnection(shareIndex);
            pstmt = conn.prepareStatement(SELECT_BY_GROUP_KEY_SQL);
            pstmt.setString(1, groupPublicKey);
            var rs = pstmt.executeQuery();

            if (rs.next()) {
                logger.info("Found key share in database!");
                KeyShare keyShare = new KeyShare();
                keyShare.setId(rs.getLong("id"));
                keyShare.setShareIndex(rs.getInt("share_index"));
                keyShare.setKeyShare(rs.getString("key_share"));
                keyShare.setGroupPublicKey(rs.getString("group_public_key"));
                keyShare.setDkgTaskId(rs.getString("dkg_task_id"));
                keyShare.setPublicShares(rs.getString("public_shares"));
                keyShare.setIndexMap(rs.getString("index_map"));
                keyShare.setChainCode(rs.getString("chain_code"));
                logger.info("Loaded key share: {}", keyShare);
                return keyShare;
            } else {
                logger.info("No key share found for group public key: {}", groupPublicKey);
                return null;
            }
        } catch (Exception e) {
            logger.error("Error loading key share: {}", e.getMessage());
            e.printStackTrace();
            throw new RuntimeException(e);
        } finally {
            closeStatement(pstmt);
            if (conn != null) {
                databaseService.releaseShareConnection(conn, shareIndex);
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
