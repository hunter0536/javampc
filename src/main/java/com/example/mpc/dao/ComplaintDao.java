package com.example.mpc.dao;

import com.example.mpc.service.DatabaseService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

@Repository
public class ComplaintDao {
    private static final Logger logger = LoggerFactory.getLogger(ComplaintDao.class);

    private static final String INSERT_SQL = "INSERT INTO complaints (ts, task_id, sender_id, offender_id, reason, evidence) VALUES (?, ?, ?, ?, ?, ?)";
    private static final String SELECT_LATEST_SQL = "SELECT ts, task_id, sender_id, offender_id, reason, evidence FROM complaints ORDER BY id DESC LIMIT ? OFFSET ?";
    private static final String SELECT_BY_TASK_SQL = "SELECT ts, task_id, sender_id, offender_id, reason, evidence FROM complaints WHERE task_id = ? ORDER BY id DESC LIMIT ? OFFSET ?";
    private static final String SELECT_BY_FILTER_SQL = "SELECT ts, task_id, sender_id, offender_id, reason, evidence FROM complaints WHERE (? IS NULL OR task_id = ?) AND (? IS NULL OR reason = ?) AND (? IS NULL OR reason LIKE ?) AND (? IS NULL OR sender_id = ?) AND (? IS NULL OR offender_id = ?) AND (? IS NULL OR ts >= ?) AND (? IS NULL OR ts <= ?) ORDER BY id DESC LIMIT ? OFFSET ?";

    @Autowired
    private DatabaseService databaseService;

    public void save(long ts, String taskId, int senderId, Integer offenderId, String reason, String evidence) {
        Connection conn = null;
        PreparedStatement stmt = null;
        try {
            conn = databaseService.getShareConnection(senderId);
            stmt = conn.prepareStatement(INSERT_SQL);
            stmt.setLong(1, ts);
            stmt.setString(2, taskId);
            stmt.setInt(3, senderId);
            if (offenderId == null) {
                stmt.setObject(4, null);
            } else {
                stmt.setInt(4, offenderId);
            }
            stmt.setString(5, reason);
            stmt.setString(6, evidence);
            stmt.executeUpdate();
        } catch (SQLException e) {
            logger.warn("Failed to save complaint: {}", e.getMessage());
        } finally {
            if (stmt != null) {
                try {
                    stmt.close();
                } catch (SQLException e) {
                    logger.warn("Failed to close statement: {}", e.getMessage());
                }
            }
            if (conn != null) {
                databaseService.releaseShareConnection(conn, senderId);
            }
        }
    }

    public List<ComplaintRecord> list(int shareIndex, String taskId, int limit, int offset) {
        Connection conn = null;
        PreparedStatement stmt = null;
        ResultSet rs = null;
        List<ComplaintRecord> out = new ArrayList<>();
        try {
            conn = databaseService.getShareConnection(shareIndex);
            if (taskId == null || taskId.isBlank()) {
                stmt = conn.prepareStatement(SELECT_LATEST_SQL);
                stmt.setInt(1, limit);
                stmt.setInt(2, offset);
            } else {
                stmt = conn.prepareStatement(SELECT_BY_TASK_SQL);
                stmt.setString(1, taskId);
                stmt.setInt(2, limit);
                stmt.setInt(3, offset);
            }
            rs = stmt.executeQuery();
            while (rs.next()) {
                out.add(new ComplaintRecord(
                        rs.getLong("ts"),
                        rs.getString("task_id"),
                        rs.getInt("sender_id"),
                        rs.getObject("offender_id") == null ? null : rs.getInt("offender_id"),
                        rs.getString("reason"),
                        rs.getString("evidence")
                ));
            }
        } catch (SQLException e) {
            logger.warn("Failed to list complaints: {}", e.getMessage());
        } finally {
            if (rs != null) {
                try {
                    rs.close();
                } catch (SQLException e) {
                    logger.warn("Failed to close result set: {}", e.getMessage());
                }
            }
            if (stmt != null) {
                try {
                    stmt.close();
                } catch (SQLException e) {
                    logger.warn("Failed to close statement: {}", e.getMessage());
                }
            }
            if (conn != null) {
                databaseService.releaseShareConnection(conn, shareIndex);
            }
        }
        return out;
    }

    public List<ComplaintRecord> listFiltered(int shareIndex,
                                              String taskId,
                                              String reason,
                                              String reasonLike,
                                              Integer senderId,
                                              Integer offenderId,
                                              Long fromTs,
                                              Long toTs,
                                              int limit,
                                              int offset) {
        Connection conn = null;
        PreparedStatement stmt = null;
        ResultSet rs = null;
        List<ComplaintRecord> out = new ArrayList<>();
        try {
            conn = databaseService.getShareConnection(shareIndex);
            stmt = conn.prepareStatement(SELECT_BY_FILTER_SQL);
            stmt.setObject(1, taskId);
            stmt.setObject(2, taskId);
            stmt.setObject(3, reason);
            stmt.setObject(4, reason);
            stmt.setObject(5, reasonLike == null ? null : "%" + reasonLike + "%");
            stmt.setObject(6, reasonLike == null ? null : "%" + reasonLike + "%");
            stmt.setObject(7, senderId);
            stmt.setObject(8, senderId);
            stmt.setObject(9, offenderId);
            stmt.setObject(10, offenderId);
            stmt.setObject(11, fromTs);
            stmt.setObject(12, fromTs);
            stmt.setObject(13, toTs);
            stmt.setObject(14, toTs);
            stmt.setInt(15, limit);
            stmt.setInt(16, offset);
            rs = stmt.executeQuery();
            while (rs.next()) {
                out.add(new ComplaintRecord(
                        rs.getLong("ts"),
                        rs.getString("task_id"),
                        rs.getInt("sender_id"),
                        rs.getObject("offender_id") == null ? null : rs.getInt("offender_id"),
                        rs.getString("reason"),
                        rs.getString("evidence")
                ));
            }
        } catch (SQLException e) {
            logger.warn("Failed to list complaints: {}", e.getMessage());
        } finally {
            if (rs != null) {
                try {
                    rs.close();
                } catch (SQLException e) {
                    logger.warn("Failed to close result set: {}", e.getMessage());
                }
            }
            if (stmt != null) {
                try {
                    stmt.close();
                } catch (SQLException e) {
                    logger.warn("Failed to close statement: {}", e.getMessage());
                }
            }
            if (conn != null) {
                databaseService.releaseShareConnection(conn, shareIndex);
            }
        }
        return out;
    }

    public record ComplaintRecord(long ts,
                                  String taskId,
                                  int senderId,
                                  Integer offenderId,
                                  String reason,
                                  String evidence) {
    }
}
