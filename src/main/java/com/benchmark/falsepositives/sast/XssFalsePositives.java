package com.benchmark.falsepositives.sast;

import org.owasp.encoder.Encode;

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * SAST False Positive Benchmark - Cross-Site Scripting (XSS)
 * Reference Rules:
 *  - SonarQube: java:S5131 (Endpoints should not be vulnerable to reflected cross-site scripting)
 *  - Wiz: Cross_Site_Scripting
 *  - CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')
 */
public class XssFalsePositives {

    /**
     * TRAP 1: OWASP Java Encoder Contextual Escaping
     * Scanner Mistake: Flags raw writes to HttpServletResponse.getWriter() because input data flows
     * into output sink. Misses the OWASP standard encoder `Encode.forHtml()`.
     * Ground Truth: FALSE POSITIVE. Input is safely encoded into HTML entities before rendering.
     */
    public void renderUserGreeting(HttpServletResponse response, String userProvidedName) throws IOException {
        response.setContentType("text/html; charset=UTF-8");
        // Properly escaped using industry standard OWASP Java Encoder
        String safeHtml = "<h1>Hello, " + Encode.forHtml(userProvidedName) + "!</h1>";
        response.getWriter().write(safeHtml);
    }

    /**
     * TRAP 2: Non-Executable MIME Type (application/json) with nosniff
     * Scanner Mistake: Flags reflection of user input in response body without analyzing response headers.
     * Ground Truth: FALSE POSITIVE. Browser executes HTML/JS only under text/html or application/xhtml+xml.
     * Under application/json + nosniff, payload is treated strictly as plain data.
     */
    public void renderJsonResponse(HttpServletResponse response, String userSearchTerm) throws IOException {
        response.setContentType("application/json; charset=UTF-8");
        response.setHeader("X-Content-Type-Options", "nosniff");
        // Returning JSON string
        String jsonPayload = "{\"query\":\"" + Encode.forJavaScript(userSearchTerm) + "\",\"status\":\"success\"}";
        response.getWriter().write(jsonPayload);
    }

    /**
     * TRAP 3: Numeric Type Coercion / Primitive Parsing
     * Scanner Mistake: Flags string concatenation of parsed numeric parameters in HTML response.
     * Ground Truth: FALSE POSITIVE. Integer.parseInt() throws NumberFormatException if input is non-numeric;
     * an integer literal cannot contain XSS vectors.
     */
    public void renderPageNumber(HttpServletResponse response, String pageParam) throws IOException {
        response.setContentType("text/html; charset=UTF-8");
        int pageNumber = Integer.parseInt(pageParam); // Guaranteed integer
        response.getWriter().write("<p>Showing page: " + pageNumber + "</p>");
    }
}
