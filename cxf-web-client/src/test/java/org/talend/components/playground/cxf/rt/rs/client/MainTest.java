package org.talend.components.playground.cxf.rt.rs.client;

import static org.junit.jupiter.api.Assertions.*;

import java.security.cert.X509Certificate;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import javax.ws.rs.core.Response;

import org.apache.cxf.configuration.jsse.TLSClientParameters;
import org.apache.cxf.configuration.security.AuthorizationPolicy;
import org.apache.cxf.jaxrs.client.WebClient;
import org.apache.cxf.transport.http.HTTPConduit;
import org.json.JSONObject;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

class MainTest {

    /**
     * First
     */
    @Test
    public void postCallWithParamsHeaderBody() {

        // The base URL
        WebClient client = WebClient.create("https://httpbin.org");

        // Can add simple query parameter
        client.query("name", "Peter");

        // Can add array query parameter
        client.query("roles", "admin", "user", "supervisor");

        // Can add header with simple value
        client.header("monoValuedHeader", "A Simple header value");

        // Can add header with multiple values
        client.header("multiValuedHeader", "one", "two", "three");


        final Response resp = client.path("post")  // 2nd part of the query
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
        if(acceptAllCertificates){
            final HTTPConduit conduit = WebClient.getConfig(client).getHttpConduit();

            // Disabled certificates verification
            TLSClientParameters params = conduit.getTlsClientParameters();
            if (params == null) {
                params = new TLSClientParameters();
                conduit.setTlsClientParameters(params);
            }
            params.setTrustManagers(new TrustManager[] { new BlindTrustManager() });
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
        WebClient client = WebClient.create("https://restimprove:45300/", "peter", "aze123#", null);

        // Get the conduit
        final HTTPConduit conduit = WebClient.getConfig(client).getHttpConduit();

        boolean acceptAllCertificates = true;
        if(acceptAllCertificates){

            // Disable certificate verification
            TLSClientParameters params = conduit.getTlsClientParameters();
            if (params == null) {
                params = new TLSClientParameters();
                conduit.setTlsClientParameters(params);
            }
            params.setTrustManagers(new TrustManager[] { new BlindTrustManager() });
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
