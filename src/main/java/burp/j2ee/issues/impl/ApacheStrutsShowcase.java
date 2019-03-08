package burp.j2ee.issues.impl;

import static burp.HTTPMatcher.URIMutator;
import static burp.HTTPMatcher.getApplicationContext;
import static burp.HTTPMatcher.getMatches;
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
import burp.j2ee.issues.IModule;
import java.io.PrintWriter;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.List;

public class ApacheStrutsShowcase implements IModule {

    private static final String TITLE = "Apache Struts - ShowCase Application";
    private static final String DESCRIPTION = "J2EEscan identified the Apache Struts ShowCase application. <br />"
            + "Based on the installed version, the application could be vulnerable to different kind of issues"
            + " such as XSS, RCE via OGNL injection, etc.<br /><br />"
            + "<b>References:</b><br />"
            + "https://bugzilla.redhat.com/show_bug.cgi?id=967655<br />"
            + "http://struts.apache.org/docs/s2-012.html";

    private static final String REMEDY = "Remove all unused applications from production environment";

    private static final byte[] GREP_STRING = "<title>Struts2 Showcase</title>".getBytes();
    private static final List<String> STRUTS_SHOWCASE_PATHS = Arrays.asList(
            "/struts2-showcase/showcase.action"
    );

    // List of host and port system already tested
    private static LinkedHashSet hs = new LinkedHashSet();

    private PrintWriter stderr;

    @Override
    public List<IScanIssue> scan(IBurpExtenderCallbacks callbacks, IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {

        IExtensionHelpers helpers = callbacks.getHelpers();
        stderr = new PrintWriter(callbacks.getStderr(), true);

        List<IScanIssue> issues = new ArrayList<>();

        IRequestInfo reqInfo = callbacks.getHelpers().analyzeRequest(baseRequestResponse);

        URL url = reqInfo.getUrl();
        String host = url.getHost();
        int port = url.getPort();
        String protocol = url.getProtocol();

        String system = host.concat(Integer.toString(port));

        // System not yet tested for this vulnerability
        if (!hs.contains(system)) {

            hs.add(system);

            for (String SHOWCASE_PATH : STRUTS_SHOWCASE_PATHS) {

                try {
                    URL urlToTest = new URL(protocol, url.getHost(), url.getPort(), SHOWCASE_PATH);
                    byte[] showcaseRequest = helpers.buildHttpRequest(urlToTest);

                    // make a request containing our injection test in the insertion point
                    IHttpRequestResponse checkRequestResponse = callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), showcaseRequest);

                    byte[] response = checkRequestResponse.getResponse();
                    IResponseInfo responseInfo = helpers.analyzeResponse(response);

                    if (responseInfo.getStatusCode() == 200) {
                        // look for matches of our active check grep string
                        List<int[]> matches = getMatches(response, GREP_STRING, helpers);

                        if (matches.size() > 0) {

                            issues.add(new CustomScanIssue(
                                    baseRequestResponse.getHttpService(),
                                    reqInfo.getUrl(),
                                    checkRequestResponse,
                                    TITLE,
                                    DESCRIPTION,
                                    REMEDY,
                                    Risk.Low,
                                    Confidence.Certain
                            ));
                        }
                    }
                } catch (MalformedURLException ex) {
                    stderr.println("Error creating URL " + ex.getMessage());
                }
            }
        }

        return issues;
    }
}
