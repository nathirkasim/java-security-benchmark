package com.benchmark;

import com.benchmark.sast.CryptoSecurityService;
import org.junit.Assert;
import org.junit.Test;

public class ApplicationServiceTest {

    @Test
    public void testEtagCalculation() throws Exception {
        CryptoSecurityService crypto = new CryptoSecurityService();
        String etag = crypto.calculateEtagCacheKey("test-content-payload".getBytes());
        Assert.assertNotNull(etag);
        Assert.assertTrue(etag.startsWith("\"") && etag.endsWith("\""));
    }

    @Test
    public void testExponentialBackoffJitter() {
        CryptoSecurityService crypto = new CryptoSecurityService();
        long delay = crypto.calculateExponentialBackoffWithJitter(2, 100);
        Assert.assertTrue(delay >= 400 && delay <= 600);
    }
}
