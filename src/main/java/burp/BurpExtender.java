package burp;

import burp.j2ee.PassiveScanner;
import burp.j2ee.annotation.RunOnlyOnce;
import burp.j2ee.issues.IModule;
import java.io.File;
import java.io.IOException;
import java.io.PrintWriter;
import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.net.URL;
import java.net.URLDecoder;
import java.sql.SQLException;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;


public class BurpExtender implements IBurpExtender, IScannerCheck, IExtensionStateListener {

    private PrintWriter stdout;
    private PrintWriter stderr;
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private Connection conn;
    private File j2eeDBState;

    //
    // implement IBurpExtender
    //
    @Override
    public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks) {
        // keep a reference to our callbacks object
        this.callbacks = callbacks;

        this.callbacks.registerExtensionStateListener(this);

        // obtain an extension helpers object
        helpers = callbacks.getHelpers();

        // obtain our output stream
        stdout = new PrintWriter(callbacks.getStdout(), true);
        stderr = new PrintWriter(callbacks.getStderr(), true);

        // set our extension name
        callbacks.setExtensionName("J2EE Advanced Tests");
        stdout.println("J2EEscan plugin loaded. ");
        stdout.println("Extended security checks for J2EE applications");
        stdout.println("https://github.com/ilmila/J2EEScan");

        String DISCLAIMER = " * DISCLAIMER: This tool is intended for security engineers. \n"
                + "Attacking targets without prior mutual consent is illegal. \n"
                + "It is the end user's responsibility to obey all applicable local, \n"
                + "state and federal laws. Developers assume no liability and are not \n"
                + "responsible for any misuse or damage caused by this program \n";

        try {
            List<String> m = getClassNamesFromPackage("burp.j2ee.issues.impl.");

            stdout.println(String.format("\nLoaded %s J2EE extended tests\n\n", m.size()));

            stdout.println(DISCLAIMER);

        } catch (IOException ex) {
            stderr.println(ex);
        }

        try {

            j2eeDBState = File.createTempFile("burpsuite-j2eescan-state", ".db");
            stdout.println("Using temporary db state file: " + j2eeDBState.getAbsolutePath());
            stdout.println("This internal state is used to avoid duplicate infrastructure security "
                    + "checks on the same host, improving the scan performance");

            connectToDatabase(j2eeDBState.getAbsolutePath());

        } catch (IOException ex) {
            stderr.println(ex);
        } catch (SQLException ex) {
            stderr.println(ex);
        } catch (ClassNotFoundException ex) {
            stderr.println(ex);
        }

        // register ourselves as a custom scanner check
        callbacks.registerScannerCheck(this);
    }

    //
    // implement IScannerCheck
    //
    @Override
    public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse) {
        List<IScanIssue> issues = new ArrayList<>();

        PassiveScanner.scanVulnerabilities(baseRequestResponse, callbacks);

        return issues;
    }

    private ArrayList<String> getClassNamesFromPackage(String packageName) throws IOException {
        URL packageURL;
        ArrayList<String> names = new ArrayList<>();

        packageName = packageName.replace(".", "/");
        packageURL = getClass().getClassLoader().getResource(packageName);

        if ((packageURL != null) && (packageURL.getProtocol().equals("jar"))) {
            String jarFileName;
            JarFile jf;
            Enumeration<JarEntry> jarEntries;
            String entryName;

            // build jar file name, then loop through zipped entries
            jarFileName = URLDecoder.decode(packageURL.getFile(), "UTF-8");
            jarFileName = jarFileName.substring(5, jarFileName.indexOf("!"));
            jf = new JarFile(jarFileName);
            jarEntries = jf.entries();
            while (jarEntries.hasMoreElements()) {
                entryName = jarEntries.nextElement().getName();
                if (entryName.startsWith(packageName) && entryName.length() > packageName.length() + 5) {
                    entryName = entryName.substring(packageName.length(), entryName.lastIndexOf('.'));
                    names.add(entryName.replace("/", ""));
                }
            }

            // loop through files in classpath
        } else {
            File folder = new File(packageURL.getFile());
            File[] contents = folder.listFiles();
            String entryName;
            for (File actual : contents) {
                entryName = actual.getCanonicalPath();
                names.add(entryName);
            }
        }
        return names;
    }

    @Override
    public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {

        List<IScanIssue> issues = new ArrayList<>();
        List<String> j2eeTests;

        try {

            j2eeTests = getClassNamesFromPackage("burp.j2ee.issues.impl.");

            for (String module : j2eeTests) {

                if (module.contains("$")) {
                    continue;
                }

                //if (!module.contains("OpenRedirectExtended")) {
                //    continue;
                //}
                Constructor<?> c = Class.forName("burp.j2ee.issues.impl." + module).getConstructor();
                IModule j2eeModule = (IModule) c.newInstance();

                for (Method m : j2eeModule.getClass().getMethods()) {

                    if (m.getName().equals("scan")) {

                        RunOnlyOnce annotationRunOnlyOnce = m.getAnnotation(RunOnlyOnce.class);

                        // Detect if the module must be run once.
                        // Some infrastructure tests or generic administrative console checks
                        // should be run once for every host.
                        // If the annotation is detected verify and execute the module
                        // only once for the same host and port.
                        if (annotationRunOnlyOnce != null) {

                            IRequestInfo reqInfo;
                            reqInfo = helpers.analyzeRequest(baseRequestResponse);

                            URL url = reqInfo.getUrl();
                            String host = url.getHost();
                            int port = url.getPort();

                            try {

                                // log the plugin is executed once
                                pluginExecutedOnce(module, host, port);

                                // Execute the single module and save the vulnerabilities
                                List<IScanIssue> results = j2eeModule.scan(callbacks, baseRequestResponse, insertionPoint);

                                issues.addAll(results);

                                if (!results.isEmpty()) {
                                    for (IScanIssue result : results) {
                                        stdout.println(String.format("[New Issue] Detected %s on URI %s", result.getIssueName(), result.getUrl()));
                                    }
                                }

                            } catch (SQLException e) {
                                stderr.println("Ignoring already executed module " + module);
                            } catch (Exception e) {
                                stderr.println("Error during module execution " + module);
                                e.printStackTrace(stderr);
                            }

                        } else {

                            try {

                                // Execute the single module and save the vulnerabilities
                                List<IScanIssue> results = j2eeModule.scan(callbacks, baseRequestResponse, insertionPoint);

                                issues.addAll(results);

                                if (!results.isEmpty()) {
                                    for (IScanIssue result : results) {
                                        stdout.println(String.format("[New Issue] Detected %s on URI %s", result.getIssueName(), result.getUrl()));
                                    }
                                }

                            } catch (Exception e) {
                                stderr.println("Error during module execution " + module);
                                e.printStackTrace(stderr);
                            }

                        }

                    }

                }
            }

        } catch (NoSuchMethodException | SecurityException | ClassNotFoundException ex) {
            stderr.println(ex);
        } catch (Exception ex) {
            ex.printStackTrace(stderr);
        }

        return issues;

    }

    @Override
    public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue) {
        // This method is called when multiple issues are reported for the same URL 
        // path by the same extension-provided check. The value we return from this 
        // method determines how/whether Burp consolidates the multiple issues
        // to prevent duplication
        //
        // Since the issue name is sufficient to identify our issues as different,
        // if both issues have the same name, only report the existing issue
        // otherwise report both issues
        if (existingIssue.getIssueName().equals(newIssue.getIssueName())) {
            return -1;
        } else {
            return 0;
        }
    }

    public void connectToDatabase(final String dbFile) throws IOException, SQLException, ClassNotFoundException {

        if (conn == null) {
            Class.forName("org.sqlite.JDBC");
        }
        conn = DriverManager.getConnection("jdbc:sqlite:" + dbFile);
        conn.setAutoCommit(true);

        String fields = "plugin, host, port";

        conn.createStatement().executeUpdate("CREATE TABLE IF NOT EXISTS executed_plugins ("
                + " plugin TEXT PRIMARY KEY,"
                + " host TEXT,"
                + " port INTEGER,"
                + " UNIQUE(" + fields + "))");

    }

    public void pluginExecutedOnce(String pluginClass, String host, int port) throws SQLException {

        PreparedStatement stmt = conn.prepareStatement("INSERT INTO executed_plugins VALUES(?,?,?)");
        stmt.setString(1, pluginClass);
        stmt.setString(2, host);
        stmt.setInt(3, port);

        stmt.executeUpdate();

    }

    @Override
    public void extensionUnloaded() {

        if (j2eeDBState.delete()) {
            System.out.println("Removed J2EEScan db state file " + j2eeDBState.getAbsolutePath());
        } else {
            System.out.println("Error while removing J2EEScan db state file " + j2eeDBState.getAbsolutePath());
        }
    }

}
