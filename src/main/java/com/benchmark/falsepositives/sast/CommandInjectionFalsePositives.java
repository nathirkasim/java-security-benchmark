package com.benchmark.falsepositives.sast;

import java.io.File;
import java.io.IOException;
import java.util.List;
import java.util.regex.Pattern;

/**
 * SAST False Positive Benchmark - OS Command Injection
 * Reference Rules:
 *  - SonarQube: java:S2076 (Values passed to OS commands should be sanitized)
 *  - Wiz: Command_Injection
 *  - CWE-78: Improper Neutralization of Special Elements used in an OS Command
 */
public class CommandInjectionFalsePositives {

    private static final Pattern SAFE_ALPHANUMERIC = Pattern.compile("^[a-zA-Z0-9._-]+$");

    public enum AllowedUtility {
        PING("/bin/ping", "-c", "3"),
        TRACEROUTE("/bin/traceroute", "-m", "10");

        private final List<String> commandTokens;

        AllowedUtility(String... tokens) {
            this.commandTokens = List.of(tokens);
        }

        public List<String> getTokens() {
            return commandTokens;
        }
    }

    /**
     * TRAP 1: Array-Based ProcessBuilder (No Shell Invocation)
     * Scanner Mistake: Flags ProcessBuilder when arguments originate from outside, failing to recognize
     * that passing parameters as distinct array elements directly invokes `execve` without `/bin/sh`.
     * Shell metacharacters (;, &, |, `, $) are treated as literal argument data, NOT shell syntax.
     * Ground Truth: FALSE POSITIVE. No shell interpreter is spawned; injection is impossible.
     */
    public Process executeGitRevParse(String gitDir, String commitSha) throws IOException {
        // Enforce strict hash format before execution
        if (!commitSha.matches("^[0-9a-fA-F]{40}$")) {
            throw new IllegalArgumentException("Invalid commit SHA");
        }

        ProcessBuilder pb = new ProcessBuilder("git", "--git-dir=" + gitDir, "rev-parse", commitSha);
        pb.directory(new File(gitDir));
        return pb.start();
    }

    /**
     * TRAP 2: Enum-Constrained Command Selection
     * Scanner Mistake: Flags dynamic command execution because command selection depends on a variable.
     * Ground Truth: FALSE POSITIVE. The executable path is resolved strictly from a fixed, hardcoded Enum.
     */
    public Process runDiagnosticUtility(AllowedUtility utility, String targetHost) throws IOException {
        if (!SAFE_ALPHANUMERIC.matcher(targetHost).matches()) {
            throw new IllegalArgumentException("Target host contains invalid characters");
        }

        List<String> commandList = new java.util.ArrayList<>(utility.getTokens());
        commandList.add(targetHost);

        ProcessBuilder pb = new ProcessBuilder(commandList);
        return pb.start();
    }
}
