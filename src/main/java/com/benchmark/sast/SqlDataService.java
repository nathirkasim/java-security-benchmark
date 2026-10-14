package com.benchmark.sast;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Set;

/**
 * Service providing database query execution and data retrieval.
 */
public class SqlDataService {

    private static final Set<String> ALLOWED_SORT_COLUMNS = Set.of("id", "username", "created_at");

    /**
     * Retrieves active engineering users.
     */
    public ResultSet queryActiveEngineeringUsers(Connection conn) throws SQLException {
        String sql = "SELECT id, username, email FROM users WHERE status = 'ACTIVE'"
                   + " AND department = 'ENGINEERING'"
                   + " ORDER BY id DESC";

        PreparedStatement stmt = conn.prepareStatement(sql);
        return stmt.executeQuery();
    }

    /**
     * Retrieves users sorted by an allowlisted column.
     */
    public ResultSet queryUsersWithSort(Connection conn, String userRequestedSort) throws SQLException {
        if (!ALLOWED_SORT_COLUMNS.contains(userRequestedSort)) {
            throw new IllegalArgumentException("Invalid sort column: " + userRequestedSort);
        }

        String sql = "SELECT id, username FROM users WHERE is_active = true ORDER BY " + userRequestedSort;
        PreparedStatement stmt = conn.prepareStatement(sql);
        return stmt.executeQuery();
    }

    /**
     * Searches users dynamically by name and email using prepared statement bindings.
     */
    public ResultSet searchUsers(Connection conn, String name, String email) throws SQLException {
        StringBuilder sql = new StringBuilder("SELECT * FROM users WHERE 1=1");
        if (name != null) {
            sql.append(" AND username = ?");
        }
        if (email != null) {
            sql.append(" AND email = ?");
        }

        PreparedStatement stmt = conn.prepareStatement(sql.toString());
        int paramIndex = 1;
        if (name != null) {
            stmt.setString(paramIndex++, name);
        }
        if (email != null) {
            stmt.setString(paramIndex++, email);
        }

        return stmt.executeQuery();
    }

    /**
     * Retrieves account records matching the specified user identifier.
     */
    public ResultSet queryAccountByUserId(Connection conn, long userId) throws SQLException {
        String sql = "SELECT * FROM accounts WHERE user_id = " + userId;
        PreparedStatement stmt = conn.prepareStatement(sql);
        return stmt.executeQuery();
    }
}
