package burp.j2ee.issues.impl;

import static burp.HTTPParser.getResponseHeaderValue;
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
import java.net.URL;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;

/**
 *
 * Test for NodeJS Response Splitting
 *
 * Reference:
 * https://nodejs.org/en/blog/vulnerability/february-2016-security-releases/
 * http://blog.safebreach.com/2016/02/09/http-response-splitting-in-node-js-root-cause-analysis/
 * http://info.safebreach.com/hubfs/Node-js-Response-Splitting.pdf
 *
 */
public class NodeJSResponseSplitting implements IModule {

    private static final String TITLE = "NodeJS Response Splitting";
    private static final String DESCRIPTION = "J2EEscan identified a vulnerable installation"
            + " of NodeJS. A Response Splitting vulnerability has been found.<br /><br />"
            + "<b>References</b>:<br /><br />"
            + "http://info.safebreach.com/hubfs/Node-js-Response-Splitting.pdf<br />"
            + "https://nodejs.org/en/blog/vulnerability/february-2016-security-releases/";

    private static final String REMEDY = "Update the software with the last security patches";

    private static final byte[] NODEJS_INJ = "%c4%8d%c4%8aInjectionHeader:%2020%c4%8d%c4%8a".getBytes();

    private PrintWriter stderr;

    @Override
    public List<IScanIssue> scan(IBurpExtenderCallbacks callbacks, IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {

        List<IScanIssue> issues = new ArrayList<>();

        IExtensionHelpers helpers = callbacks.getHelpers();
        IRequestInfo reqInfo = helpers.analyzeRequest(baseRequestResponse);

        URL url = reqInfo.getUrl();
        String host = url.getHost();

        String protocol = url.getProtocol();

        // skip if the NodeJS has not been found on the system
        if (!IssuesHandler.isvulnerabilityFound(callbacks,
                "NodeJS detected",
                protocol,
                host)) {
            return issues;

        }

        // make a request containing our injection test in the insertion point
        byte[] checkRequest = insertionPoint.buildRequest(NODEJS_INJ);

        IHttpRequestResponse checkRequestResponse = callbacks.makeHttpRequest(
                baseRequestResponse.getHttpService(), checkRequest);

        byte[] response = checkRequestResponse.getResponse();

        IResponseInfo respInfo = helpers.analyzeResponse(response);
        
        if (getResponseHeaderValue(respInfo, "InjectionHeader") != null) {
            issues.add(new CustomScanIssue(
                    baseRequestResponse.getHttpService(),
                    helpers.analyzeRequest(baseRequestResponse).getUrl(),
                    checkRequestResponse,
                    TITLE,
                    DESCRIPTION,
                    REMEDY,
                    Risk.Medium,
                    Confidence.Certain
            ));
        }

        return issues;

    }
}
