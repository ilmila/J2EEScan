package burp.j2ee.issues.impl;

import static burp.HTTPMatcher.getMatches;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IRequestInfo;
import burp.IScanIssue;
import burp.IScannerInsertionPoint;
import burp.j2ee.Confidence;
import burp.j2ee.CustomScanIssue;
import burp.j2ee.Risk;
import burp.j2ee.annotation.RunOnlyOnce;
import burp.j2ee.issues.IModule;
import java.io.PrintWriter;
import java.net.URL;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;

/**
 * HTTP Open Proxy detection
 *
 */
public class HTTPProxy implements IModule {

    private static final String TITLE = "HTTP Open Proxy";
    private static final String DESCRIPTION = "J2EEscan identified a remote HTTP open proxy service.<br /> "
            + "It was possible to request via the remote HTTP service the resource http://www.google.com/humans.txt.<br />"
            + "This configuration may allow an attacker to interact potentially with the internal network."
            + "<br /><br />"
            + "<b>References</b>:<br /><br />"
            + "http://www.suretecsystems.com/our_docs/proxy-guide-en/index.html<br />"
            + "http://www.web-cache.com/Writings/Internet-Drafts/draft-luotonen-web-proxy-tunneling-01.txt<br />"
            + "https://www.kb.cert.org/vuls/id/150227<br />";

    private static final String REMEDY = "Change the current configuration in order to preventi the current behaviour.<br />";
    private static final byte[] GREP_STRING = "Google is built by a large".getBytes();

    // List of host and port system already tested
    private static LinkedHashSet hs = new LinkedHashSet();

    private PrintWriter stderr;

    @RunOnlyOnce
    public List<IScanIssue> scan(IBurpExtenderCallbacks callbacks, IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {

        stderr = new PrintWriter(callbacks.getStderr(), true);

        List<IScanIssue> issues = new ArrayList<>();
        IExtensionHelpers helpers = callbacks.getHelpers();

        IRequestInfo reqInfo = helpers.analyzeRequest(baseRequestResponse);

        URL url = reqInfo.getUrl();
        String host = url.getHost();
        int port = url.getPort();

        String system = host.concat(Integer.toString(port));

        // System not yet tested for this vulnerability
        if (!hs.contains(system)) {
            hs.add(system);

            // TODO implement GET @www.google.com/humans.txt? HTTP/1.0\r\n\r\n
            byte[] rawrequestHTTPConnect = "CONNECT http://www.google.com/humans.txt HTTP/1.0\r\n\r\n".getBytes();

            // Execute a CONNECT method
            IHttpRequestResponse checkRequestResponse = callbacks.makeHttpRequest(
                    baseRequestResponse.getHttpService(), rawrequestHTTPConnect);

            
            // Get the response body
            byte[] responseBytesHTTPConnect = checkRequestResponse.getResponse();
            
            if (responseBytesHTTPConnect != null) {
                List<int[]> matchesHTTPConnect = getMatches(responseBytesHTTPConnect, GREP_STRING, helpers);
                if (matchesHTTPConnect.size() > 0) {

                    issues.add(new CustomScanIssue(
                            baseRequestResponse.getHttpService(),
                            reqInfo.getUrl(),
                            checkRequestResponse,
                            TITLE,
                            DESCRIPTION,
                            REMEDY,
                            Risk.High,
                            Confidence.Certain
                    ));
                }
            }

            // Execute a GET method
            byte[] rawrequestGETHTTPConnect = "GET http://www.google.com/humans.txt HTTP/1.0\r\n".getBytes();
            IHttpRequestResponse checkRequestResponseGETHTTPConnect = callbacks.makeHttpRequest(
                    baseRequestResponse.getHttpService(), rawrequestGETHTTPConnect);

            // Get the response body
            byte[] responseBytesGETHTTPConnect = checkRequestResponseGETHTTPConnect.getResponse();

            if (responseBytesGETHTTPConnect != null) {
                List<int[]> matchesGETHTTPConnect = getMatches(responseBytesGETHTTPConnect, GREP_STRING, helpers);
                if (matchesGETHTTPConnect.size() > 0) {

                    issues.add(new CustomScanIssue(
                            baseRequestResponse.getHttpService(),
                            reqInfo.getUrl(),
                            checkRequestResponse,
                            TITLE,
                            DESCRIPTION,
                            REMEDY,
                            Risk.High,
                            Confidence.Certain
                    ));
                }
            }

        }

        return issues;
    }
}
