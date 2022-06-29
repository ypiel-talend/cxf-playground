package org.talend.components.playground.cxf.rt.rs.client;

import static org.junit.jupiter.api.Assertions.*;

import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.UnknownHostException;
import java.security.cert.X509Certificate;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import javax.ws.rs.core.Response;

import org.apache.cxf.configuration.jsse.TLSClientParameters;
import org.apache.cxf.configuration.security.AuthorizationPolicy;
import org.apache.cxf.jaxrs.client.WebClient;
import org.apache.cxf.transport.http.HTTPConduit;
import org.apache.cxf.transport.https.SSLUtils;
import org.apache.cxf.transports.http.configuration.HTTPClientPolicy;
import org.json.JSONObject;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

class MainTest {

    /**
     * First
     */
    @Test
    public void postCallWithParamsHeaderBody() {

        // The base URL
        WebClient client = WebClient.create("https://httpbin.org");

        // Timeout configuration
        final HTTPConduit conduit = WebClient.getConfig(client).getHttpConduit();
        conduit.getClient().setConnectionTimeout(1000 * 2);
        conduit.getClient().setReceiveTimeout(1000 * 2);

        // Can add simple query parameter
        client.query("name", "Peter");

        // Can add array query parameter
        client.query("roles", "admin", "user", "supervisor");

        // Can add header with simple value
        client.header("monoValuedHeader", "A Simple header value");

        // Can add header with multiple values
        client.header("multiValuedHeader", "one", "two", "three");


        final Response resp = client.path("{verb}", "post")  // 2nd part of the query with substitution
                .accept("application/json")        // Set acceptance type
                .invoke("POST"          // Set the HTTP verb
                        , "Body content");   // Body content as String

        final int status = resp.getStatus(); // Retrieve the status code

        // Retrieve answer body as String
        final String strResponse = resp.readEntity(String.class);

        JSONObject jsonResponse = new JSONObject(strResponse);
        Assertions.assertEquals(200, status);
        Assertions.assertEquals("{", strResponse.substring(0, 1)); // I retrieve the body
        Assertions.assertEquals("Body content", jsonResponse.getString("data"));
        Assertions.assertEquals("httpbin.org", jsonResponse.getJSONObject("headers").getString("Host"));
        Assertions.assertEquals("org.json.JSONArray", jsonResponse.getJSONObject("args").get("roles").getClass().getName());
        Assertions.assertEquals("user", jsonResponse.getJSONObject("args").getJSONArray("roles").get(1));
        Assertions.assertEquals("Peter", jsonResponse.getJSONObject("args").getString("name"));
        Assertions.assertEquals("A Simple header value", jsonResponse.getJSONObject("headers").getString("Monovaluedheader"));
        Assertions.assertEquals("one,two,three", jsonResponse.getJSONObject("headers").getString("Multivaluedheader"));
    }


    /**
     * Disable certificate verification and do basic authent.
     */
    @Test
    public void disabledCertificateAndBasicAuthent() {
        WebClient client = WebClient.create("https://restimprove:44300/", "peter", "aze123#", null);

        boolean acceptAllCertificates = true;
        if (acceptAllCertificates) {
            final HTTPConduit conduit = WebClient.getConfig(client).getHttpConduit();

            // Disabled certificates verification
            TLSClientParameters params = conduit.getTlsClientParameters();
            if (params == null) {
                params = new TLSClientParameters();
                conduit.setTlsClientParameters(params);
            }
            params.setTrustManagers(new TrustManager[]{new BlindTrustManager()});
            params.setDisableCNCheck(true);
        }


        final Response resp = client.path("basic_authent.json").accept("application/json").invoke("GET", (Object) null);
        final int status = resp.getStatus();
        final String strResponse = resp.readEntity(String.class);
        Assertions.assertEquals(200, status);
    }


    /**
     * Disable certificate verification and do digest authent.
     */
    @Test
    public void disabledCertificateAndDigestAuthent() {
        WebClient client = WebClient.create("https://restimprove:45300/");

        // Get the conduit
        final HTTPConduit conduit = WebClient.getConfig(client).getHttpConduit();

        boolean acceptAllCertificates = true;
        if (acceptAllCertificates) {

            // Disable certificate verification
            TLSClientParameters params = conduit.getTlsClientParameters();
            if (params == null) {
                params = new TLSClientParameters();
                conduit.setTlsClientParameters(params);
            }
            params.setTrustManagers(new TrustManager[]{new BlindTrustManager()});
            params.setDisableCNCheck(true);
        }

        // Disgest authent support
        AuthorizationPolicy authPolicy = new AuthorizationPolicy();
        authPolicy.setAuthorizationType("Digest");
        authPolicy.setUserName("john");
        authPolicy.setPassword("abcde");
        conduit.setAuthorization(authPolicy);


        final Response resp = client.path("digest_authent.json").accept("application/json").invoke("GET", (Object) null);
        final int status = resp.getStatus();
        final String strResponse = resp.readEntity(String.class);
        Assertions.assertEquals(200, status);
    }

    /**
     * NTLM authent.
     */
    @Test
    public void certificateCheckingAndNTLMAuthent() {
        WebClient client = WebClient.create("https://mytestclient.demo1.freeipa.org");

        // Get the conduit
        final HTTPConduit conduit = WebClient.getConfig(client).getHttpConduit();

        boolean acceptAllCertificates = true;
        if (acceptAllCertificates) {
            // Disable certificate verification
            TLSClientParameters params = conduit.getTlsClientParameters();
            if (params == null) {
                params = new TLSClientParameters();
                conduit.setTlsClientParameters(params);
            }
            params.setTrustManagers(new TrustManager[]{new BlindTrustManager()});
            params.setDisableCNCheck(true);
        }

        // Disgest authent support
        AuthorizationPolicy authPolicy = new AuthorizationPolicy();
        authPolicy.setAuthorizationType("NTLM");
        authPolicy.setUserName("admin");
        authPolicy.setPassword("Secret123");
        conduit.setAuthorization(authPolicy);


        final Response resp = client.accept("application/json").invoke("POST", "{\"method\":\"stageuser_find\",\"params\":[[\"\"],{\"pkey_only\":true,\"sizelimit\":0,\"version\":\"2.240\"}]}");
        final int status = resp.getStatus();
        final String strResponse = resp.readEntity(String.class);
        Assertions.assertEquals(200, status);
    }

    /**
     * Manage redirection:
     * - auto-redirect
     * - max redirect
     * - relative redirect : https://stackoverflow.com/questions/8250259/is-a-302-redirect-to-relative-url-valid-or-invalid
     */
    @Test
    public void maxRelativeRedirect() {
        // The base URL
        WebClient client = WebClient.create("https://httpbin.org");

        // Get the conduit
        final HTTPConduit conduit = WebClient.getConfig(client).getHttpConduit();

        // Redirection
        WebClient.getConfig(client).getRequestContext().put("http.redirect.relative.uri", "true"); // Allow or not relative redirect
        final HTTPClientPolicy policy = conduit.getClient();
        policy.setAutoRedirect(true);
        policy.setMaxRetransmits(5);

        final Response resp = client.path("/{action}/{n}", "redirect", "5")  // 2nd part of the query
                .accept("application/json")        // Set acceptance type
                .invoke("GET", (Object) null); // Set the HTTP verb and no body

        final int status = resp.getStatus(); // Retrieve the status code
        Assertions.assertEquals(200, status);
    }

    /**
     * It misses the force GET on a 302
     */
    @ParameterizedTest
    @CsvSource({"redirect, true, 6, true", // relative redirect, accept relative, 6 authorized redirects, success expected
            "redirect, true, 4, false", // relative redirect, accept relative, 4 authorized redirects but 5 needed, failure expected
            "redirect, false, 6, false", // relative redirect, refuse relative, 6 authorized redirects, failure expected
            "absolute-redirect, false, 6, true", // relative redirect, refuse relative, 6 authorized redirects, success expected
            "absolute-redirect, true, 6, true", // relative redirect, accept relative, 6 authorized redirects, success expected
            "absolute-redirect, true, 4, false" // relative redirect, accept relative, 6 authorized redirects, success expected
    })
    public void maxAbsoluteRedirect(String endpoint, boolean acceptRelativeRedirect, int maxRedirect, boolean isSuccess) {
        // The base URL
        WebClient client = WebClient.create("https://httpbin.org");

        // Get the conduit
        final HTTPConduit conduit = WebClient.getConfig(client).getHttpConduit();

        // Redirection
        WebClient.getConfig(client).getRequestContext().put("http.redirect.relative.uri", acceptRelativeRedirect); // Allow or not relative redirect
        WebClient.getConfig(client).getRequestContext().put("http.redirect.same.host.only", true); // Redirect only on the same host or not
        final HTTPClientPolicy policy = conduit.getClient();
        policy.setAutoRedirect(true);
        policy.setMaxRetransmits(maxRedirect);

        try {
            final Response resp = client.path("/{action}/{n}", endpoint, "5")  // 2nd part of the query
                    .accept("application/json")        // Set acceptance type
                    .invoke("GET", (Object) null); // Set the HTTP verb and no body

            final int status = resp.getStatus(); // Retrieve the status code
            Assertions.assertEquals(isSuccess, 200 == status);
        } catch (Throwable e) {
            Assertions.assertFalse(isSuccess);
        }
    }


    /**
     * Implement a check connection :
     * - Check URI
     * - Resolve domain's name to IP
     * - Validate certificate
     * - Validate authentication
     */
    @ParameterizedTest
    @CsvSource({"https://httpbin.org/get?param=aaa, SUCCESS", // All is ok
            "https://htt % pbin.org/get?param=aaa, MALFORMED_URI", // Malformed URI
            "https://restimprove:45300/,SUCCESS"
    })
    public void checkConnection(String suri, String result) {
        URI uri;
        try {
           uri = new URI(suri);
        } catch (URISyntaxException e) {
            Assertions.assertEquals("MALFORMED_URI", result);
            return;
        }

        // Resolve hostname
        try {
            InetAddress address = InetAddress.getByName("httpbin.org");
            System.out.println(suri + " address: " + address.getHostAddress());
        } catch (UnknownHostException e) {
            Assertions.fail("Unresolved host: " + e.getMessage());
            return;
        }

        WebClient client = WebClient.create("https://httpbin.org");
        final HTTPConduit conduit = WebClient.getConfig(client).getHttpConduit();
        TLSClientParameters tlsClient = conduit.getTlsClientParameters();
        if (tlsClient == null) {
            tlsClient = new TLSClientParameters();
            conduit.setTlsClientParameters(tlsClient);
        }

        /*try {
            final SSLEngine clientSSLEngine = SSLUtils.createClientSSLEngine(tlsClient);
            final HostnameVerifier hostnameVerifier = SSLUtils.getHostnameVerifier(tlsClient);
            final boolean verify = hostnameVerifier.verify(suri, clientSSLEngine.getSession());
            Assertions.assertTrue(verify);
        } catch (Exception e) {
            System.err.println("TLS verification error message: " + e.getMessage());
            Assertions.assertEquals("TLS_VERIFICATION", result);
            return;
        }*/

        HttpURLConnection connection; // = new HttpsU
        HttpURLConnection.

        Assertions.assertEquals("SUCCESS", result);
    }


    /**
     * This dumb X509TrustManager trusts all certificate. TThis SHOULD NOT be used in Production.
     */
    public static class BlindTrustManager implements X509TrustManager {

        public void checkClientTrusted(X509Certificate[] chain,
                                       String authType) throws java.security.cert.CertificateException {
        }

        public void checkServerTrusted(X509Certificate[] chain,
                                       String authType) throws java.security.cert.CertificateException {
        }

        public X509Certificate[] getAcceptedIssuers() {
            return null;
        }
    }

}
