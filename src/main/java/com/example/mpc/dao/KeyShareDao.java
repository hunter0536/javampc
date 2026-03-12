package com.example.mpc.dao;

import com.example.mpc.common.util.ThreadPoolUtil;
import com.example.mpc.dto.KeyShare;
import com.example.mpc.service.DatabaseService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;

@Repository
public class KeyShareDao {
    private static final Logger logger = LoggerFactory.getLogger(KeyShareDao.class);

    private static final String INSERT_SQL = "INSERT INTO key_shares (share_index, key_share, group_public_key, dkg_task_id, public_shares, index_map, chain_code, is_hot_wallet) VALUES (?, ?, ?, ?, ?, ?, ?, ?)";
    private static final String SELECT_LAST_ID_SQL = "SELECT last_insert_rowid()";
    private static final String SELECT_BY_GROUP_KEY_SQL = "SELECT id, share_index, key_share, group_public_key, dkg_task_id, public_shares, index_map, chain_code, is_hot_wallet FROM key_shares WHERE group_public_key = ? ORDER BY id DESC LIMIT 1";
    private static final String SELECT_LATEST_SQL = "SELECT id, share_index, key_share, group_public_key, dkg_task_id, public_shares, index_map, chain_code, is_hot_wallet FROM key_shares WHERE share_index = ? ORDER BY id DESC LIMIT 1";
    private static final String SELECT_HOT_WALLET_LATEST_SQL = "SELECT id, share_index, key_share, group_public_key, dkg_task_id, public_shares, index_map, chain_code, is_hot_wallet FROM key_shares WHERE share_index = ? AND is_hot_wallet = 1 ORDER BY id DESC LIMIT 1";
    private static final String SELECT_ALL_HOT_WALLET_SQL = "SELECT id, share_index, key_share, group_public_key, dkg_task_id, public_shares, index_map, chain_code, is_hot_wallet FROM key_shares WHERE share_index = ? AND is_hot_wallet = 1 ORDER BY id DESC";
    private static final String COUNT_HOT_WALLET_SQL = "SELECT COUNT(1) FROM key_shares WHERE share_index = ? AND is_hot_wallet = 1";

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
            insertStmt.setString(index++, keyShare.getChainCode());
            insertStmt.setBoolean(index, keyShare.getIsHotWallet() != null ? keyShare.getIsHotWallet() : false);
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
                keyShare.setIsHotWallet(rs.getBoolean("is_hot_wallet"));
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

    public CompletableFuture<KeyShare> findLatest(int shareIndex) {
        return CompletableFuture.supplyAsync(() -> findLatestSync(shareIndex), ThreadPoolUtil.getIoThreadPool());
    }

    public KeyShare findLatestSync(int shareIndex) {
        Connection conn = null;
        PreparedStatement pstmt = null;
        try {
            logger.info("Loading latest key share for share index: {}", shareIndex);

            conn = databaseService.getShareConnection(shareIndex);
            pstmt = conn.prepareStatement(SELECT_LATEST_SQL);
            pstmt.setInt(1, shareIndex);
            var rs = pstmt.executeQuery();

            if (rs.next()) {
                logger.info("Found latest key share in database!");
                KeyShare keyShare = new KeyShare();
                keyShare.setId(rs.getLong("id"));
                keyShare.setShareIndex(rs.getInt("share_index"));
                keyShare.setKeyShare(rs.getString("key_share"));
                keyShare.setGroupPublicKey(rs.getString("group_public_key"));
                keyShare.setDkgTaskId(rs.getString("dkg_task_id"));
                keyShare.setPublicShares(rs.getString("public_shares"));
                keyShare.setIndexMap(rs.getString("index_map"));
                keyShare.setChainCode(rs.getString("chain_code"));
                keyShare.setIsHotWallet(rs.getBoolean("is_hot_wallet"));
                logger.info("Loaded latest key share: {}", keyShare);
                return keyShare;
            } else {
                logger.info("No key share found for share index: {}", shareIndex);
                return null;
            }
        } catch (Exception e) {
            logger.error("Error loading latest key share: {}", e.getMessage());
            e.printStackTrace();
            throw new RuntimeException(e);
        } finally {
            closeStatement(pstmt);
            if (conn != null) {
                databaseService.releaseShareConnection(conn, shareIndex);
            }
        }
    }

    public KeyShare findHotWalletLatestSync(int shareIndex) {
        Connection conn = null;
        PreparedStatement pstmt = null;
        try {
            logger.info("Loading latest hot wallet key share for share index: {}", shareIndex);

            conn = databaseService.getShareConnection(shareIndex);
            pstmt = conn.prepareStatement(SELECT_HOT_WALLET_LATEST_SQL);
            pstmt.setInt(1, shareIndex);
            var rs = pstmt.executeQuery();

            if (rs.next()) {
                logger.info("Found latest hot wallet key share in database!");
                KeyShare keyShare = new KeyShare();
                keyShare.setId(rs.getLong("id"));
                keyShare.setShareIndex(rs.getInt("share_index"));
                keyShare.setKeyShare(rs.getString("key_share"));
                keyShare.setGroupPublicKey(rs.getString("group_public_key"));
                keyShare.setDkgTaskId(rs.getString("dkg_task_id"));
                keyShare.setPublicShares(rs.getString("public_shares"));
                keyShare.setIndexMap(rs.getString("index_map"));
                keyShare.setChainCode(rs.getString("chain_code"));
                keyShare.setIsHotWallet(rs.getBoolean("is_hot_wallet"));
                logger.info("Loaded latest hot wallet key share: {}", keyShare);
                return keyShare;
            } else {
                logger.info("No hot wallet key share found for share index: {}", shareIndex);
                return null;
            }
        } catch (Exception e) {
            logger.error("Error loading latest hot wallet key share: {}", e.getMessage());
            e.printStackTrace();
            throw new RuntimeException(e);
        } finally {
            closeStatement(pstmt);
            if (conn != null) {
                databaseService.releaseShareConnection(conn, shareIndex);
            }
        }
    }

    public CompletableFuture<KeyShare> findHotWalletLatest(int shareIndex) {
        return CompletableFuture.supplyAsync(() -> findHotWalletLatestSync(shareIndex), ThreadPoolUtil.getIoThreadPool());
    }
    
    public List<KeyShare> findAllHotWalletSync(int shareIndex) {
        Connection conn = null;
        PreparedStatement pstmt = null;
        try {
            logger.info("Loading all hot wallet key shares for share index: {}", shareIndex);

            conn = databaseService.getShareConnection(shareIndex);
            pstmt = conn.prepareStatement(SELECT_ALL_HOT_WALLET_SQL);
            pstmt.setInt(1, shareIndex);
            var rs = pstmt.executeQuery();

            List<KeyShare> keyShares = new ArrayList<>();
            while (rs.next()) {
                KeyShare keyShare = new KeyShare();
                keyShare.setId(rs.getLong("id"));
                keyShare.setShareIndex(rs.getInt("share_index"));
                keyShare.setKeyShare(rs.getString("key_share"));
                keyShare.setGroupPublicKey(rs.getString("group_public_key"));
                keyShare.setDkgTaskId(rs.getString("dkg_task_id"));
                keyShare.setPublicShares(rs.getString("public_shares"));
                keyShare.setIndexMap(rs.getString("index_map"));
                keyShare.setChainCode(rs.getString("chain_code"));
                keyShare.setIsHotWallet(rs.getBoolean("is_hot_wallet"));
                keyShares.add(keyShare);
            }
            logger.info("Found {} hot wallet key shares for share index: {}", keyShares.size(), shareIndex);
            return keyShares;
        } catch (Exception e) {
            logger.error("Error loading all hot wallet key shares: {}", e.getMessage());
            e.printStackTrace();
            throw new RuntimeException(e);
        } finally {
            closeStatement(pstmt);
            if (conn != null) {
                databaseService.releaseShareConnection(conn, shareIndex);
            }
        }
    }

    public int countHotWalletSync(int shareIndex) {
        Connection conn = null;
        PreparedStatement pstmt = null;
        try {
            conn = databaseService.getShareConnection(shareIndex);
            pstmt = conn.prepareStatement(COUNT_HOT_WALLET_SQL);
            pstmt.setInt(1, shareIndex);
            var rs = pstmt.executeQuery();
            if (rs.next()) {
                return rs.getInt(1);
            }
            return 0;
        } catch (Exception e) {
            logger.error("Error counting hot wallet key shares: {}", e.getMessage());
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
