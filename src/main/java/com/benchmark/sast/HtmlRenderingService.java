package com.benchmark.sast;

import org.owasp.encoder.Encode;

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * Service managing web response rendering and template generation.
 */
public class HtmlRenderingService {

    /**
     * Renders a formatted greeting page.
     */
    public void renderUserGreeting(HttpServletResponse response, String userProvidedName) throws IOException {
        response.setContentType("text/html; charset=UTF-8");
        String safeHtml = "<h1>Hello, " + Encode.forHtml(userProvidedName) + "!</h1>";
        response.getWriter().write(safeHtml);
    }

    /**
     * Renders API query results in JSON format with strict nosniff options.
     */
    public void renderJsonResponse(HttpServletResponse response, String userSearchTerm) throws IOException {
        response.setContentType("application/json; charset=UTF-8");
        response.setHeader("X-Content-Type-Options", "nosniff");
        String jsonPayload = "{\"query\":\"" + Encode.forJavaScript(userSearchTerm) + "\",\"status\":\"success\"}";
        response.getWriter().write(jsonPayload);
    }

    /**
     * Outputs pagination controls for requested page index.
     */
    public void renderPageNumber(HttpServletResponse response, String pageParam) throws IOException {
        response.setContentType("text/html; charset=UTF-8");
        int pageNumber = Integer.parseInt(pageParam);
        response.getWriter().write("<p>Showing page: " + pageNumber + "</p>");
    }
}
