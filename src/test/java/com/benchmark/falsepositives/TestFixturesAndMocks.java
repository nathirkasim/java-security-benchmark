package com.benchmark.falsepositives;

import com.benchmark.falsepositives.sast.CryptoFalsePositives;
import com.benchmark.falsepositives.sast.PathTraversalFalsePositives;
import com.benchmark.falsepositives.sast.XssFalsePositives;
import org.junit.Assert;
import org.junit.Test;

public class TestFixturesAndMocks {

    @Test
    public void testEtagCalculation() throws Exception {
        CryptoFalsePositives crypto = new CryptoFalsePositives();
        String etag = crypto.calculateEtagCacheKey("benchmark-test-payload".getBytes());
        Assert.assertNotNull(etag);
        Assert.assertTrue(etag.startsWith("\"") && etag.endsWith("\""));
    }

    @Test
    public void testExponentialBackoffJitter() {
        CryptoFalsePositives crypto = new CryptoFalsePositives();
        long delay = crypto.calculateExponentialBackoffWithJitter(2, 100);
        Assert.assertTrue(delay >= 400 && delay <= 600);
    }
}
