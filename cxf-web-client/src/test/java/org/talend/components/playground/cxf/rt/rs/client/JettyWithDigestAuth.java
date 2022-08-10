package org.talend.components.playground.cxf.rt.rs.client;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.apache.cxf.configuration.security.AuthorizationPolicy;
import org.apache.cxf.jaxrs.client.WebClient;
import org.apache.cxf.transport.http.HTTPConduit;
import org.apache.cxf.transport.http.auth.HttpAuthHeader;
import org.eclipse.jetty.security.ConstraintMapping;
import org.eclipse.jetty.security.ConstraintSecurityHandler;
import org.eclipse.jetty.security.HashLoginService;
import org.eclipse.jetty.security.LoginService;
import org.eclipse.jetty.security.authentication.DigestAuthenticator;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.ServerConnector;
import org.eclipse.jetty.servlet.ServletHandler;
import org.eclipse.jetty.util.security.Constraint;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import javax.ws.rs.core.Response;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.net.URL;
import java.util.Collections;

public class JettyWithDigestAuth {

    public static Server createServer(int port) throws FileNotFoundException {
        // Create a basic jetty server object that will listen on port 8080.
        // Note that if you set this to port 0 then a randomly available port
        // will be assigned that you can either look in the logs for the port,
        // or programmatically obtain it for use in test cases.
        Server server = new Server(port);

        // Since this example is for our test webapp, we need to setup a
        // LoginService so this shows how to create a very simple hashmap based
        // one. The name of the LoginService needs to correspond to what is
        // configured a webapp's web.xml and since it has a lifecycle of its own
        // we register it as a bean with the Jetty server object so it can be
        // started and stopped according to the lifecycle of the server itself.
        // In this example the name can be whatever you like since we are not
        // dealing with webapp realms.
        String realmResourceName = "realm.properties";
        ClassLoader classLoader = JettyWithDigestAuth.class.getClassLoader();
        URL realmProps = classLoader.getResource(realmResourceName);
        if (realmProps == null)
            throw new FileNotFoundException("Unable to find " + realmResourceName);

        LoginService loginService = new HashLoginService("MyRealm",
                realmProps.toExternalForm());
        server.addBean(loginService);

        // A security handler is a jetty handler that secures content behind a
        // particular portion of a url space. The ConstraintSecurityHandler is a
        // more specialized handler that allows matching of urls to different
        // constraints. The server sets this as the first handler in the chain,
        // effectively applying these constraints to all subsequent handlers in
        // the chain.
        ConstraintSecurityHandler security = new ConstraintSecurityHandler();
        server.setHandler(security);

        // This constraint requires authentication and in addition that an
        // authenticated user be a member of a given set of roles for
        // authorization purposes.
        Constraint constraint = new Constraint();
        constraint.setName("auth");
        constraint.setAuthenticate(true);
        constraint.setRoles(new String[]{"user", "admin"});

        // Binds a url pattern with the previously created constraint. The roles
        // for this constraint mapping are mined from the Constraint itself
        // although methods exist to declare and bind roles separately as well.
        ConstraintMapping mapping = new ConstraintMapping();
        mapping.setPathSpec("/*");
        mapping.setConstraint(constraint);

        // First you see the constraint mapping being applied to the handler as
        // a singleton list, however you can passing in as many security
        // constraint mappings as you like so long as they follow the mapping
        // requirements of the servlet api. Next we set a BasicAuthenticator
        // instance which is the object that actually checks the credentials
        // followed by the LoginService which is the store of known users, etc.
        security.setConstraintMappings(Collections.singletonList(mapping));
        security.setAuthenticator(new DigestAuthenticator());
        security.setLoginService(loginService);

        // The Hello Handler is the handler we are securing so we create one,
        // and then set it as the handler on the
        // security handler to complain the simple handler chain.
        // HelloHandler hh = new HelloHandler();

        // chain the hello handler into the security handler
        //security.setHandler(hh);

        ServletHandler sh = new ServletHandler();
        sh.addServletWithMapping(JettyWithDigestAuth.OKServlet.class, "/ok");
        security.setHandler(sh);

        return server;
    }

    public static void call(int port) {
        WebClient client = WebClient.create("http://127.0.0.1:" + port);

        HTTPConduit httpConduit = WebClient.getConfig(client).getHttpConduit();
        AuthorizationPolicy digestAuthPolicy = new AuthorizationPolicy();
        digestAuthPolicy.setUserName("plain");
        digestAuthPolicy.setPassword("plain");
        digestAuthPolicy.setAuthorizationType(HttpAuthHeader.AUTH_TYPE_DIGEST);
        httpConduit.setAuthorization(digestAuthPolicy);


        Response response = client.path("ok")
                .accept("application/json")
                .invoke("GET", "");

        Assertions.assertEquals(200, response.getStatus());

        InputStream is = (InputStream) response.getEntity();

        byte[] bytes = new byte[0];
        try {
            bytes = is.readAllBytes();


            String responsePayload = new String(bytes);
            System.out.println(responsePayload);

            System.out.printf("Done");
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

    }


    @Test
    public void jettyTest() throws Exception {
        Server server = createServer(0);
        server.start();

        int port = ((ServerConnector) server.getConnectors()[0]).getLocalPort();
        System.out.println("Port will be: " + port);
        call(port);


    }

    public final static class OKServlet extends HttpServlet {
        protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
            response.setContentType("application/json");
            response.setStatus(HttpServletResponse.SC_OK);
            response.getWriter().println("{ \"status\": \"ok\"}");
            response.flushBuffer();
        }
    }

}
