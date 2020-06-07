package burp.j2ee.issues.impl;

import burp.CustomHttpRequestResponse;
import static burp.HTTPMatcher.getMatches;
import burp.IBurpCollaboratorClientContext;
import burp.IBurpCollaboratorInteraction;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IRequestInfo;
import burp.IResponseInfo;
import burp.IScanIssue;
import burp.IScannerInsertionPoint;
import burp.j2ee.Confidence;
import burp.j2ee.CustomScanIssue;
import burp.j2ee.Risk;
import burp.j2ee.annotation.RunOnlyOnce;
import burp.j2ee.issues.IModule;
import java.io.PrintWriter;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.List;

/**
 *
 * Weblogic Web Service Test Page - Remote Command Execution
 *
 *
 * The Weblogic "Web Service Test Page" is vulnerable to an arbitrary file
 * upload vulnerability which leads to a remote command execution. The "Web
 * Service Test Page" is not open in the "production mode", but only in the
 * test/debug.
 *
 * References:
 *
 *  - http://www.oracle.com/technetwork/security-advisory/cpujul2018-4258247.html
 *  - https://nvd.nist.gov/vuln/detail/CVE-2018-2894
 *
 */
public class WeblogicWebServiceTestPageCVE20182894 implements IModule {

    private static final String TITLE = "Weblogic - Web Service Test Page - Remote Command Execution";
    private static final String DESCRIPTION = "J2EEscan identified a potential remote command execution the Weblogic \"Web Service Test Page\".<br />"
            + "The vulnerability is affecting the Web Services (WLS) subcomponent. <br />"
            + "The path: <code>/ws_utc/config.do</code> is by default reachable without any authentication when Weblogic is configured in <b>development mode</b>.<br />"
            + "The Weblogic \"Web Service Test Page\" is vulnerable to an arbitrary file upload vulnerability which leads to a remote command execution.<br />"
            + "Due to the nature of the issue, this check did not tried to exploit the issue. "
            + "<b>References:</b>"
            + "<ul>"
            + "<li>https://nvd.nist.gov/vuln/detail/CVE-2018-2894</li>"
            + "<li>https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/CVE%20Exploits/WebLogic%20CVE-2018-2894.py</li>"
            + "<li>https://github.com/111ddea/cve-2018-2894</li>"
            + "</ul>";

    private static final String REMEDY = "Update the Weblogic componenent with the last security patches provided by Oracle. <br />"
            + "Enable Web Service Test Page <code>disabled</code> in (Console -> domain -> advanced).";

    // List of host and port system already tested
    private static LinkedHashSet hs = new LinkedHashSet();
    private PrintWriter stderr;

    private static final List<byte[]> GREP_STRINGS = Arrays.asList(
            "<title>settings</title>".getBytes()
    );

    private static final List<String> WS_TEST_PAGES = Arrays.asList(
            "/ws_utc/config.do"
    );

    @RunOnlyOnce
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

            for (String WS_TEST_PAGE : WS_TEST_PAGES) {

                try {

                    URL urlToTest = new URL(protocol, url.getHost(), url.getPort(), WS_TEST_PAGE);
                    byte[] udditest = helpers.buildHttpRequest(urlToTest);
                    byte[] response = callbacks.makeHttpRequest(url.getHost(),
                            url.getPort(), isSSL, udditest);

                    IResponseInfo wsInfo = helpers.analyzeResponse(response);

                    if (wsInfo.getStatusCode() == 200) {
                        for (byte[] GREP_STRING : GREP_STRINGS) {

                            List<int[]> matches = getMatches(response, GREP_STRING, helpers);

                            if (matches.size() > 0) {
                                issues.add(new CustomScanIssue(
                                        baseRequestResponse.getHttpService(),
                                        reqInfo.getUrl(),
                                        new CustomHttpRequestResponse(udditest, response, baseRequestResponse.getHttpService()),
                                        TITLE,
                                        DESCRIPTION,
                                        REMEDY,
                                        Risk.High,
                                        Confidence.Tentative
                                ));
                            }
                        }
                    }
                } catch (MalformedURLException ex) {
                    stderr.println("Malformed URL Exception " + ex);
                }

                return issues;
            }

        }

        return issues;
    }

}
