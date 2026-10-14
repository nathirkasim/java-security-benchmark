package com.benchmark.falsepositives.sast;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.List;
import java.util.Set;

/**
 * SAST False Positive Benchmark - SQL Injection
 * Reference Rules:
 *  - SonarQube: java:S2077 (SQL queries should not be vulnerable to injection)
 *  - Wiz / Checkmarx: SQL_Injection
 *  - CWE-89: Improper Neutralization of Special Elements used in an SQL Command
 */
public class SqlInjectionFalsePositives {

    private static final Set<String> ALLOWED_SORT_COLUMNS = Set.of("id", "username", "created_at");

    /**
     * TRAP 1: Static String Constant Concatenation
     * Scanner Mistake: Naive regex/AST matching flags ANY string concatenation (`+`) inside SQL statements.
     * Ground Truth: FALSE POSITIVE. Both operands are compile-time static string literals.
     */
    public ResultSet queryWithConstantConcatenation(Connection conn) throws SQLException {
        // String split across lines for readability using string concatenation
        String sql = "SELECT id, username, email FROM users WHERE status = 'ACTIVE'"
                   + " AND department = 'ENGINEERING'"
                   + " ORDER BY id DESC";

        PreparedStatement stmt = conn.prepareStatement(sql);
        return stmt.executeQuery();
    }

    /**
     * TRAP 2: Allowlist-Validated Dynamic Identifier (ORDER BY)
     * Scanner Mistake: Dynamic ORDER BY / identifier cannot be parameterized in JDBC. Scanners flag
     * any variable in ORDER BY as SQLi without recognizing the strict pre-validation guard.
     * Ground Truth: FALSE POSITIVE. Column is validated against an immutable allowlist Set before interpolation.
     */
    public ResultSet queryWithAllowlistedSort(Connection conn, String userRequestedSort) throws SQLException {
        if (!ALLOWED_SORT_COLUMNS.contains(userRequestedSort)) {
            throw new IllegalArgumentException("Invalid sort column: " + userRequestedSort);
        }

        // userRequestedSort is guaranteed to be one of "id", "username", or "created_at"
        String sql = "SELECT id, username FROM users WHERE is_active = true ORDER BY " + userRequestedSort;
        PreparedStatement stmt = conn.prepareStatement(sql);
        return stmt.executeQuery();
    }

    /**
     * TRAP 3: Fully Parameterized PreparedStatement with Dynamic Clause Composition
     * Scanner Mistake: Dynamic WHERE construction triggers taint warning even though all values
     * are strictly bound through positional parameters `?`.
     * Ground Truth: FALSE POSITIVE. All external input is passed via setString().
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
     * TRAP 4: Strongly-Typed Primitive Long Parameter
     * Scanner Mistake: String concatenation of primitive numeric value (`long id`).
     * Ground Truth: FALSE POSITIVE. A primitive `long` cannot contain SQL control characters or escape syntax.
     */
    public ResultSet queryByPrimitiveId(Connection conn, long userId) throws SQLException {
        // userId is an immutable 64-bit signed integer primitive
        String sql = "SELECT * FROM accounts WHERE user_id = " + userId;
        PreparedStatement stmt = conn.prepareStatement(sql);
        return stmt.executeQuery();
    }
}
