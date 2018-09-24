package org.schambon.mongodb.demo.krb5;

import com.mongodb.MongoClient;
import com.mongodb.MongoClientOptions;
import com.mongodb.MongoCredential;
import com.mongodb.ServerAddress;
import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.Options;
import org.bson.Document;
import org.eclipse.jetty.server.Connector;
import org.eclipse.jetty.server.Request;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.ServerConnector;
import org.eclipse.jetty.server.handler.AbstractHandler;
import org.ietf.jgss.*;

import javax.security.auth.Subject;
import javax.security.auth.login.LoginContext;
import javax.security.sasl.Sasl;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.*;
import java.security.Principal;
import java.security.PrivilegedExceptionAction;
import java.util.*;


/**
 * Starts a web server that will accept any request, perform SPNEGO authentication and forward the
 * credentials to MongoDB.
 *
 * Usage: java -jar AppServer -p principal -k keytab --host host [--realm REALM] [--kdc KDC]
 * Where:
 *   - principal: the service principal (SPN) for the web app, starting with HTTP/
 *   - keytab: the keytab to log in as SPN
 *   - host: the MongoDB hostname
 *   - realm: the Kerberos realm (optional, should be fine from principal / krb5.conf)
 *   - kdc: the Kerberos KDC (optional, should be fine from krb5.conf)
 *
 * HOWTO: In your KDC, create a service principal for the web server (eg HTTP/fqdn@REALM) and export its keytab.
 * Then run the app. Make sure your browser is configured both for SPNEGO and credentials forwarding - in
 * Windows (IE, Edge) this should work out of the box in an AD domain. In Firefox, that's configured with
 * about:config, keys: network.negotiate-auth.trusted-uris and network.negotiate-auth.delegation-uris (both
 * should be set to your web server's fqdn). Then kinit as a valid user, and run!
 */
public class AppServer {

    private final GSSCredential serverCredential;
    private final String mongoDBHost;
    private Server server;

    private AppServer(GSSCredential serverCredential, String mongoDBHost) {
        this.serverCredential = serverCredential;
        this.mongoDBHost = mongoDBHost;
    }

    public void start() throws Exception {
        server = new Server();
        ServerConnector connector = new ServerConnector(server);
        connector.setPort(8080);
        server.setConnectors(new Connector[]{connector});
        server.setHandler(new TestHandler(this.serverCredential, this.mongoDBHost));
        server.start();
        server.join();
    }

    public static void main(String[] args) throws Exception {

        Options options = new Options();
        options.addOption("p", "principal", true, "Service Principal Name to run under");
        options.addOption("k", "keytab", true, "Keytab for the SPN");
        options.addOption("h", "host", true, "MongoDB host");
        options.addOption(null, "realm", true, "Kerberos realm");
        options.addOption(null, "kdc", true, "Kerberos KDC");

        CommandLineParser parser = new DefaultParser();
        CommandLine commandLine = parser.parse(options, args);

        if (!commandLine.hasOption("p") || !commandLine.hasOption("k") || !commandLine.hasOption("h")) {
            System.err.println("Usage: java -jar AppServer.jar -p <principal> -k <keytab> -h <MongoDB host>");
            System.exit(1);
        }

        final File jaasConfFile;
        try
        {
            jaasConfFile = File.createTempFile("jaas.conf", null);
            final PrintStream bos = new PrintStream(new FileOutputStream(jaasConfFile));
            bos.print(String.format(
                    "Krb5LC { com.sun.security.auth.module.Krb5LoginModule required " +
                            "refreshKrb5Config=true useTicketCache=false debug=true " +
                            "useKeyTab=true storeKey=true principal=\"%s\" " +
                            "keyTab=\"%s\"; };",
                    commandLine.getOptionValue('p'), commandLine.getOptionValue('k')
            ));
            bos.close();
            jaasConfFile.deleteOnExit();
        }
        catch (final IOException ex)
        {
            throw new IOError(ex);
        }

        // set the properties
        if (commandLine.hasOption("realm") && commandLine.hasOption("kdc")) {
            System.setProperty("java.security.krb5.realm", commandLine.getOptionValue("realm"));
            System.setProperty("java.security.krb5.kdc", commandLine.getOptionValue("kdc"));
        }
        System.setProperty("java.security.auth.login.config",jaasConfFile.getAbsolutePath());

        final Subject subject = new Subject();
        final LoginContext lc = new LoginContext("Krb5LC", subject);
        lc.login();

        final Set<Principal> principalSet = subject.getPrincipals();
        if (principalSet.size() != 1)
            throw new AssertionError("No or several principals: " + principalSet);
        final Principal userPrincipal = principalSet.iterator().next();

        GSSCredential serverCredential = Subject.doAs(subject,
                (PrivilegedExceptionAction<GSSCredential>) () -> GSSManager.getInstance().createCredential(null, GSSCredential.DEFAULT_LIFETIME, new Oid[]{
                        new Oid("1.3.6.1.5.5.2"),
                        new Oid("1.2.840.113554.1.2.2")
                }, GSSCredential.ACCEPT_ONLY));

        System.out.println(String.format("Successfully initialized, SPN is: %s", userPrincipal.toString()));


        new AppServer(serverCredential, commandLine.getOptionValue("host")).start();
    }

}

class TestHandler extends AbstractHandler {

    private static final String AUTHORIZATION = "Authorization";
    private static final String NEGOTIATE = "Negotiate";
    private static final String WWW_AUTHENTICATE = "WWW-Authenticate";

    private final GSSCredential serverCredential;
    private String mongoDBHost;

    public TestHandler(GSSCredential serverCredential, String mongoDBHost) {
        this.serverCredential = serverCredential;
        this.mongoDBHost = mongoDBHost;
    }

    @Override
    public void handle(String target, Request baseRequest, HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException {
        String authorization = request.getHeader(AUTHORIZATION);
        if (authorization == null) {
            response.setHeader(WWW_AUTHENTICATE, NEGOTIATE);
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.getWriter().println("Please authenticate");
            try {
                response.flushBuffer();
            } catch (IOException e) {
                System.out.println("Cannot flush response");
                e.printStackTrace();
            }
            return;
        }

        if (!authorization.startsWith(NEGOTIATE)) {
            System.out.println("Received invalid Authorization header (expected: Negotiate then SPNEGO blob)");
            return;
        }

        byte[] token = Base64.getDecoder().decode(authorization.substring(NEGOTIATE.length() + 1));
        byte[] respToken;

        try {
            GSSContext context = GSSManager.getInstance().createContext(serverCredential);
            respToken = context.acceptSecContext(token, 0, token.length);

            if (context.isEstablished()) {
                String principal = context.getSrcName().toString();
                response.setStatus(HttpServletResponse.SC_OK);
                PrintWriter writer = response.getWriter();
                writer.println(String.format("Hello, %s!", principal));

                // get delegate creds if we can
                if (!context.getCredDelegState()) {
                    writer.println("\nCredentials cannot be delegated");
                } else {
                    writer.println("\nCredentails ARE delegated! Woohoo!");
                    GSSCredential delegateCredential = context.getDelegCred();

                    Map<String, Object> config = new HashMap<>();
                    config.put(Sasl.CREDENTIALS, delegateCredential);
                    MongoCredential credential = MongoCredential.createGSSAPICredential(principal).withMechanismProperty(MongoCredential.JAVA_SASL_CLIENT_PROPERTIES_KEY, config);

                    MongoClient client = new MongoClient(Arrays.asList(new ServerAddress(mongoDBHost)),
                            credential,
                            MongoClientOptions.builder().retryWrites(true).build());
                    Document connectionStatus = client.getDatabase("test").runCommand(new Document("connectionStatus", 1));
                    String loggedInUser = ((Document) (((List) ((Document) connectionStatus.get("authInfo")).get("authenticatedUsers")).get(0))).getString("user");

                    writer.println(String.format("\nLogged in user from MongoDB: %s", loggedInUser));
                    writer.println(connectionStatus.toJson());

                }


            } else {
                response.setHeader(WWW_AUTHENTICATE, NEGOTIATE + " " + Base64.getEncoder().encodeToString(respToken));
            }
        } catch (GSSException e) {
            e.printStackTrace();
        }

        baseRequest.setHandled(true);
    }
}