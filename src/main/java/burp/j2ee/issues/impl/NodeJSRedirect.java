package burp.j2ee.issues.impl;

import burp.CustomHttpRequestResponse;
import burp.HTTPParser;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IRequestInfo;
import burp.IResponseInfo;
import burp.IScanIssue;
import burp.IScannerInsertionPoint;
import burp.j2ee.Confidence;
import burp.j2ee.CustomScanIssue;
import burp.j2ee.IssuesHandler;
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
 * Test for NodeJS Server HTTP redirect
 *
 * Reference: https://nodesecurity.io/advisories/serve-static-open-redirect
 *
 * Example:
 *
 * http://example.com//www.example.com/%2e%2e
 *
 * the server replies with a 303 to: 
 * Location: //www.example.com/%2e%2e
 *
 * This issue could afflict some browser (ex: firefox). 
 * Google Chrome is not vulnerable
 *
 *
 *
 */
public class NodeJSRedirect implements IModule {

    // List of host and port system already tested
    private static LinkedHashSet hs = new LinkedHashSet();

    private static final String TITLE = "NodeJS Open Redirect";
    private static final String DESCRIPTION = "J2EEscan identified a vulnerable installation"
            + " of NodeJS. In some circumstances the open redirect vulnerability could be used "
            + " in phishing attacks to get users to visit malicious sites without realizing it.<br /><br />"
            + "<b>References</b>:<br /><br />"
            + "https://nodesecurity.io/advisories/serve-static-open-redirect<br />"
            + "https://cwe.mitre.org/data/definitions/601.html";

    private static final String REMEDY = "Update the software with the last security patches";

    private static final String NODEJS_PATH = "///www.example.com/%2e%2e";

    private PrintWriter stderr;

    @Override
    public List<IScanIssue> scan(IBurpExtenderCallbacks callbacks, IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {

        List<IScanIssue> issues = new ArrayList<>();

        IExtensionHelpers helpers = callbacks.getHelpers();
        stderr = new PrintWriter(callbacks.getStderr(), true);

        IRequestInfo reqInfo = helpers.analyzeRequest(baseRequestResponse);

        URL url = reqInfo.getUrl();
        String host = url.getHost();
        int port = url.getPort();

        String system = host.concat(Integer.toString(port));

        // System not yet tested for this vulnerability
        if (!hs.contains(system)) {

            hs.add(system);

            String protocol = url.getProtocol();
            Boolean isSSL = (protocol.equals("https"));      

            // skip if the NodeJS has not been found on the system
            if (!IssuesHandler.isvulnerabilityFound(callbacks,
                    "NodeJS detected",
                    protocol,
                    host)) {
                return issues;

            } 

            URL urlToTest;

            try {

                urlToTest = new URL(protocol, url.getHost(), url.getPort(), NODEJS_PATH);

                byte[] nodejstest = helpers.buildHttpRequest(urlToTest);

                byte[] response = callbacks.makeHttpRequest(url.getHost(),
                        url.getPort(), isSSL, nodejstest);

                IResponseInfo nodejsInfo = helpers.analyzeResponse(response);

                if (nodejsInfo.getStatusCode() == 301
                        || nodejsInfo.getStatusCode() == 302
                        || nodejsInfo.getStatusCode() == 303) {

                    String locationHeader = HTTPParser.getResponseHeaderValue(nodejsInfo, "Location");

                    if (locationHeader != null && locationHeader.startsWith("/www.example.com")) {

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

        }

        return issues;

    }
}
