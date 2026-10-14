package com.benchmark.sast;

import java.io.File;
import java.io.IOException;
import java.util.List;
import java.util.regex.Pattern;

/**
 * Service managing system utility and diagnostic command execution.
 */
public class CommandExecutionService {

    private static final Pattern SAFE_HOST_PATTERN = Pattern.compile("^[a-zA-Z0-9._-]+$");

    public enum DiagnosticUtility {
        PING("/bin/ping", "-c", "3"),
        TRACEROUTE("/bin/traceroute", "-m", "10");

        private final List<String> commandTokens;

        DiagnosticUtility(String... tokens) {
            this.commandTokens = List.of(tokens);
        }

        public List<String> getTokens() {
            return commandTokens;
        }
    }

    /**
     * Resolves git revision hashes for a repository.
     */
    public Process executeGitRevParse(String gitDir, String commitSha) throws IOException {
        if (!commitSha.matches("^[0-9a-fA-F]{40}$")) {
            throw new IllegalArgumentException("Invalid commit SHA format");
        }

        ProcessBuilder pb = new ProcessBuilder("git", "--git-dir=" + gitDir, "rev-parse", commitSha);
        pb.directory(new File(gitDir));
        return pb.start();
    }

    /**
     * Executes authorized diagnostic utilities against verified network endpoints.
     */
    public Process runDiagnosticUtility(DiagnosticUtility utility, String targetHost) throws IOException {
        if (!SAFE_HOST_PATTERN.matcher(targetHost).matches()) {
            throw new IllegalArgumentException("Target host contains invalid characters");
        }

        List<String> commandList = new java.util.ArrayList<>(utility.getTokens());
        commandList.add(targetHost);

        ProcessBuilder pb = new ProcessBuilder(commandList);
        return pb.start();
    }
}
