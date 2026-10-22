package com.benchmark.security.token;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Base64;

/**
 * Signs tokens using HMAC-SHA256.
 */
public class HmacTokenSigner {

    private static final String HMAC_ALGORITHM = "HmacSHA256";

    /**
     * Signs the token payload with the given secret key.
     * Output format: <base64url-payload>.<base64url-signature>
     */
    public static String signToken(TokenPayload payload, byte[] secretKey) throws GeneralSecurityException {
        if (payload == null || secretKey == null || secretKey.length == 0) {
            throw new IllegalArgumentException("Payload and secret key cannot be null or empty");
        }

        String serializedPayload = payload.serialize();
        byte[] payloadBytes = serializedPayload.getBytes(StandardCharsets.UTF_8);
        String encodedPayload = Base64.getUrlEncoder().withoutPadding().encodeToString(payloadBytes);

        Mac mac = Mac.getInstance(HMAC_ALGORITHM);
        SecretKeySpec keySpec = new SecretKeySpec(secretKey, HMAC_ALGORITHM);
        mac.init(keySpec);
        byte[] signatureBytes = mac.doFinal(encodedPayload.getBytes(StandardCharsets.UTF_8));
        String encodedSignature = Base64.getUrlEncoder().withoutPadding().encodeToString(signatureBytes);

        return encodedPayload + "." + encodedSignature;
    }
}
