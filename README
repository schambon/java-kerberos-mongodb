MongoDB and Kerberos samples
============================

This contains two minimalistic demos of using MongoDB, Java and Kerberos authentication.

- Krb5Demo simply takes a local ticket (or pops up a Java Swing dialog for credentials if there aren't any) and uses that to authenticate to MongoDB

- AppServer starts a web application on port 8080, performs SPNEGO authentication, and forwards that to MongoDB for a desktop -> app -> database SSO

In both cases, you'll need to setup MongoDB correctly with Kerberos (ie create a SPN and keytab, etc.)

For AppServer, you also need to create an SPN for the app server (using the FQDN!) and export its keytab. You'll also need to configure your browser for SPNEGO including delegation (in Firefox, that's the `network.negotiate-auth.trusted-uris` and `network.negotiate-auth.delegation-uris` keys in `about:config`)

Build instructions
------------------

`./gradlew build` at the project root should work fine. That will produce two artifacts (Krb5Demo.jar and AppServer.jar). To run, use either of:

 - `java -jar Krb5Demo.jar -h <MongoDB host name>`
 - `java -jar AppServer -p <SPN> -k <keytab> -h <MongoDB host name>`


