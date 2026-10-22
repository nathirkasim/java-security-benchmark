package com.benchmark.sast;

import org.apache.commons.io.FilenameUtils;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Set;

/**
 * Service managing document access and template storage retrieval.
 */
public class FileStorageService {

    private final Path baseStorageDir = Paths.get("/var/app/data").toAbsolutePath().normalize();
    private static final Set<String> ALLOWED_TEMPLATES = Set.of("header.html", "footer.html", "sidebar.html");

    /**
     * Reads a report file from storage by base filename.
     */
    public FileInputStream readUserReport(String untrustedFilePath) throws IOException {
        String cleanBaseName = FilenameUtils.getName(untrustedFilePath);
        File safeFile = new File(baseStorageDir.toFile(), cleanBaseName);
        return new FileInputStream(safeFile);
    }

    /**
     * Reads files located within the designated sandboxed data root.
     */
    public FileInputStream readSandboxedFile(String requestedSubPath) throws IOException {
        Path resolvedPath = baseStorageDir.resolve(requestedSubPath).normalize();

        if (!resolvedPath.startsWith(baseStorageDir)) {
            throw new SecurityException("Access outside storage boundary rejected: " + requestedSubPath);
        }

        return new FileInputStream(resolvedPath.toFile());
    }

    /**
     * Loads predefined presentation templates.
     */
    public FileInputStream loadAllowedTemplate(String templateName) throws IOException {
        if (!ALLOWED_TEMPLATES.contains(templateName)) {
            throw new IllegalArgumentException("Requested template not recognized: " + templateName);
        }

        File templateFile = new File("/var/app/templates", templateName);
        return new FileInputStream(templateFile);
    }

    /**
     * Reads a file directly from user input without validation.
     * Vulnerability: CWE-22 (Path Traversal)
     */
    public FileInputStream readArbitraryFile(String filename) throws IOException {
        File file = new File(baseStorageDir.toFile(), filename);
        return new FileInputStream(file);
    }
}
