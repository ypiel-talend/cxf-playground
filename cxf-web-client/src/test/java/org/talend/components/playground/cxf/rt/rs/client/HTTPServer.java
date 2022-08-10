package org.talend.components.playground.cxf.rt.rs.client;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import lombok.AllArgsConstructor;
import lombok.Data;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.stream.Collectors;

public class HTTPServer {

    public final static String HTTP_ECHO = "/echo";

    private HTTPServer() {
        /** Don't instantiate **/
    }

    public static TestHTTPServer createServer() {
        try {
            HttpServer server = HttpServer.create(new InetSocketAddress(0), 0);
            int port = server.getAddress().getPort();

            configureServer(server);

            return new TestHTTPServer(server, port);
        } catch (IOException e) {
            System.err.println(String.format("Can't start the test HTTP server from %s : %s",
                    HTTPServer.class.getName(), e.getMessage()));
            throw new RuntimeException(e);
        }
    }

    private static void configureServer(HttpServer server) {
        simpleContext(server);
    }

    private static void simpleContext(HttpServer server) {
        server.createContext(HTTP_ECHO, new HttpHandler() {

            @Override
            public void handle(HttpExchange exchange) throws IOException {
                String content = ResourcesUtils.getString(exchange.getRequestBody());

                Map<String, String> headers = exchange.getRequestHeaders().entrySet().stream().collect(Collectors.toMap(e -> e.getKey(), e -> {
                    return e.getValue().stream().collect(Collectors.joining(","));
                }));

                StringBuilder sb = new StringBuilder();
                sb.append("QUERY:").append(exchange.getRequestURI()).append("\n");
                sb.append("========== HEADERS =================================\n");
                headers.entrySet().forEach(e -> sb.append(e.getKey()+ " = " + e.getValue()+"\n"));
                sb.append("=========== BODY ================================\n");
                sb.append(content);

                exchange.sendResponseHeaders(200, 0);
                OutputStream os = exchange.getResponseBody();
                os.write(sb.toString().getBytes(StandardCharsets.UTF_8));
                os.close();
            }
        });
    }

    @Data
    @AllArgsConstructor
    public static class TestHTTPServer {

        private HttpServer httpServer;

        private int port;
    }

}
