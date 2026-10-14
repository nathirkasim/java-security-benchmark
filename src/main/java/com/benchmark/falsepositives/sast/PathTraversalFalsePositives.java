package com.benchmark.falsepositives.sast;

import org.apache.commons.io.FilenameUtils;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Set;

/**
 * SAST False Positive Benchmark - Path Traversal (Directory Traversal)
 * Reference Rules:
 *  - SonarQube: java:S2083 (I/O function calls should not be vulnerable to path traversal)
 *  - Wiz: Path_Traversal
 *  - CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')
 */
public class PathTraversalFalsePositives {

    private final Path baseStorageDir = Paths.get("/var/app/data").toAbsolutePath().normalize();
    private static final Set<String> ALLOWED_TEMPLATES = Set.of("header.html", "footer.html", "sidebar.html");

    /**
     * TRAP 1: Base Filename Extraction with FilenameUtils.getName()
     * Scanner Mistake: Flags `new File(dir, fileName)` as vulnerable because fileName originated from user.
     * Misses the fact that `FilenameUtils.getName()` strips all directory components, `/`, and `../`.
     * Ground Truth: FALSE POSITIVE. Cannot traverse outside base directory.
     */
    public FileInputStream readUserReport(String untrustedFilePath) throws IOException {
        String cleanBaseName = FilenameUtils.getName(untrustedFilePath);
        File safeFile = new File(baseStorageDir.toFile(), cleanBaseName);
        return new FileInputStream(safeFile);
    }

    /**
     * TRAP 2: Canonicalization with Prefix / Sandbox Verification
     * Scanner Mistake: AST-based scanners flag dynamic path resolution even when guarded by
     * canonical path `.normalize().startsWith(baseDir)`.
     * Ground Truth: FALSE POSITIVE. Verified to reside strictly within the intended base boundary.
     */
    public FileInputStream readSandboxedFile(String requestedSubPath) throws IOException {
        Path resolvedPath = baseStorageDir.resolve(requestedSubPath).normalize();

        // Enforce strict confinement inside baseStorageDir
        if (!resolvedPath.startsWith(baseStorageDir)) {
            throw new SecurityException("Directory traversal attempt detected: " + requestedSubPath);
        }

        return new FileInputStream(resolvedPath.toFile());
    }

    /**
     * TRAP 3: Strict Filename Allowlist Set
     * Scanner Mistake: Flags file loading based on user selection.
     * Ground Truth: FALSE POSITIVE. Filename is restricted to fixed set of static templates.
     */
    public FileInputStream loadAllowedTemplate(String templateName) throws IOException {
        if (!ALLOWED_TEMPLATES.contains(templateName)) {
            throw new IllegalArgumentException("Template not permitted: " + templateName);
        }

        File templateFile = new File("/var/app/templates", templateName);
        return new FileInputStream(templateFile);
    }
}
