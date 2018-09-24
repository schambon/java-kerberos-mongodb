package org.schambon.mongodb.demo.krb5;

import com.mongodb.MongoClient;
import com.mongodb.MongoClientOptions;
import com.mongodb.MongoCredential;
import com.mongodb.ServerAddress;
import com.mongodb.client.MongoCollection;
import com.sun.security.auth.callback.DialogCallbackHandler;
import org.apache.commons.cli.*;
import org.bson.Document;

import javax.security.auth.Subject;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;
import java.io.*;
import java.security.Principal;
import java.security.PrivilegedAction;
import java.time.Instant;
import java.util.Arrays;
import java.util.Set;


/**
 * Simplest example:
 * Get a ticket from the local cache and use that to connect to MongoDB
 */
public class Krb5Demo {
    public static void main(String[] args) throws LoginException, ParseException {

        Options options = new Options();
        options.addOption("h", "host", true, "MongoDB host to connect to");
        options.addOption(null, "realm", true, "Kerberos realm");
        options.addOption(null, "kdc", true, "Kerberos KDC");

        CommandLineParser parser = new DefaultParser();
        CommandLine commandLine = parser.parse(options, args);

        if (!commandLine.hasOption("host")) {
            System.err.println("Usage: Krb5Demo --host <MongoDB Host:Port> [--realm REALM] [--kdc KDC]");
            System.exit(1);
        }

        final File jaasConfFile;
        try
        {
            jaasConfFile = File.createTempFile("jaas.conf", null);
            final PrintStream bos = new PrintStream(new FileOutputStream(jaasConfFile));
            bos.print(String.format(
                    "Krb5LoginContext { com.sun.security.auth.module.Krb5LoginModule required refreshKrb5Config=true useTicketCache=true debug=false ; };"
            ));
            bos.close();
            jaasConfFile.deleteOnExit();
        }
        catch (final IOException ex)
        {
            throw new IOError(ex);
        }

        // set the properties
        if (commandLine.hasOption("realm")) {
            System.setProperty("java.security.krb5.realm", commandLine.getOptionValue("realm"));
        }
        if (commandLine.hasOption("kdc")) {
            System.setProperty("java.security.krb5.kdc", commandLine.getOptionValue("kdc"));
        }
        System.setProperty("java.security.auth.login.config",jaasConfFile.getAbsolutePath());

        final Subject subject = new Subject();
        final LoginContext lc = new LoginContext("Krb5LoginContext", subject, new DialogCallbackHandler());
        lc.login();

        final Set<Principal> principalSet = subject.getPrincipals();
        if (principalSet.size() != 1)
            throw new AssertionError("No or several principals: " + principalSet);
        final Principal userPrincipal = principalSet.iterator().next();

        System.out.println(String.format("Logged in: %s", userPrincipal.toString()));

        class LogIn implements PrivilegedAction<Document> {
            public Document run() {
                MongoClient client = new MongoClient(Arrays.asList(new ServerAddress(commandLine.getOptionValue("host"))),
                MongoCredential.createGSSAPICredential(userPrincipal.toString()),
                MongoClientOptions.builder().retryWrites(true).build());

                return client.getDatabase("test").runCommand(new Document("connectionStatus", 1));
            }
        }

        Document loginInfo = Subject.doAsPrivileged(subject, new LogIn(), null);

        System.out.println(String.format("Login successful, result from { connectionStatus: 1 } command: %s", loginInfo.toJson()));
    }
}
