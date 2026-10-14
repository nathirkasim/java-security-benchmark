package com.benchmark.sast;

import org.apache.commons.io.serialization.ValidatingObjectInputStream;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.ObjectInputFilter;
import java.io.ObjectInputStream;
import java.io.Serializable;

/**
 * Service managing serialized object payload decoding and type filtering.
 */
public class PayloadDeserializerService {

    public static class SafeDataPayload implements Serializable {
        private static final long serialVersionUID = 1L;
        private String message;
        private int count;

        public String getMessage() { return message; }
        public int getCount() { return count; }
    }

    /**
     * Deserializes binary payloads using standard JVM ObjectInputFilter restrictions.
     */
    public Object deserializeWithJep290Filter(byte[] serializedBytes) throws IOException, ClassNotFoundException {
        try (ByteArrayInputStream bais = new ByteArrayInputStream(serializedBytes);
             ObjectInputStream ois = new ObjectInputStream(bais)) {

            ObjectInputFilter filter = ObjectInputFilter.Config.createFilter(
                "com.benchmark.sast.PayloadDeserializerService$SafeDataPayload;!*"
            );
            ois.setObjectInputFilter(filter);

            return ois.readObject();
        }
    }

    /**
     * Deserializes payloads using validating input stream class filters.
     */
    public Object deserializeWithValidatingStream(byte[] serializedBytes) throws IOException, ClassNotFoundException {
        try (ByteArrayInputStream bais = new ByteArrayInputStream(serializedBytes);
             ValidatingObjectInputStream vois = new ValidatingObjectInputStream(bais)) {

            vois.accept(SafeDataPayload.class);
            return vois.readObject();
        }
    }
}
