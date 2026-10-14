package com.benchmark.falsepositives.sast;

import org.apache.commons.io.serialization.ValidatingObjectInputStream;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.ObjectInputFilter;
import java.io.ObjectInputStream;
import java.io.Serializable;

/**
 * SAST False Positive Benchmark - Insecure Deserialization
 * Reference Rules:
 *  - SonarQube: java:S5804 (ObjectInputStream should use ObjectInputFilter)
 *  - Wiz / Semgrep: java.lang.security.audit.deserialization
 *  - CWE-502: Deserialization of Untrusted Data
 */
public class DeserializationFalsePositives {

    public static class SafeDataPayload implements Serializable {
        private static final long serialVersionUID = 1L;
        private String message;
        private int count;

        public String getMessage() { return message; }
        public int setCount() { return count; }
    }

    /**
     * TRAP 1: Java Standard JEP 290 Filtered Deserialization
     * Scanner Mistake: Flags `ois.readObject()` unconditionally upon seeing ObjectInputStream.
     * Misses the standard JEP 290 `setObjectInputFilter` configured to allow ONLY SafeDataPayload and reject all gadgets (`!*`).
     * Ground Truth: FALSE POSITIVE. RCE deserialization gadget chains are strictly blocked by JVM filter.
     */
    public Object deserializeWithJep290Filter(byte[] serializedBytes) throws IOException, ClassNotFoundException {
        try (ByteArrayInputStream bais = new ByteArrayInputStream(serializedBytes);
             ObjectInputStream ois = new ObjectInputStream(bais)) {

            // Allow only SafeDataPayload, block everything else (!*)
            ObjectInputFilter filter = ObjectInputFilter.Config.createFilter(
                "com.benchmark.falsepositives.sast.DeserializationFalsePositives$SafeDataPayload;!*"
            );
            ois.setObjectInputFilter(filter);

            return ois.readObject();
        }
    }

    /**
     * TRAP 2: Apache Commons IO ValidatingObjectInputStream
     * Scanner Mistake: Scanners without semantic symbol tracking flag `readObject()` on subclasses of ObjectInputStream.
     * Ground Truth: FALSE POSITIVE. Class whitelist explicitly accepts only SafeDataPayload.
     */
    public Object deserializeWithValidatingStream(byte[] serializedBytes) throws IOException, ClassNotFoundException {
        try (ByteArrayInputStream bais = new ByteArrayInputStream(serializedBytes);
             ValidatingObjectInputStream vois = new ValidatingObjectInputStream(bais)) {

            vois.accept(SafeDataPayload.class);
            return vois.readObject();
        }
    }
}
