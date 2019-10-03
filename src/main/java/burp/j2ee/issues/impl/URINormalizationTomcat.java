package burp.j2ee.issues.impl;

import burp.CustomHttpRequestResponse;
import static burp.HTTPMatcher.getApplicationContext;
import static burp.HTTPMatcher.getApplicationContextAndNestedPath;
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

/**
 *
 * Strategy to identify URI Path Normalization Issues - Tomcat specific strategy
 *
 * Reference: -
 * https://i.blackhat.com/us-18/Wed-August-8/us-18-Orange-Tsai-Breaking-Parser-Logic-Take-Your-Path-Normalization-Off-And-Pop-0days-Out-2.pdf
 *
 *
 */
public class URINormalizationTomcat implements IModule {

    private static final String TITLE = "URI Normalization Issue - Tomcat";
    private static final String DESCRIPTION = "J2EEscan identified a URI Normalization Issue. <br />"
            + "The remote infrastructure composed by the reverse proxy and the application Servlet Container fails to normalize some URLs containing <i>path parameters</i>;<br />"
            + " the current configuration introduces a potential security risk allowing to bypass the ACLs in place and access to the protected Tomcat Manager console."
            + "<br /><br />"
            + "<b>References</b>:<br /><br />"
            + "https://i.blackhat.com/us-18/Wed-August-8/us-18-Orange-Tsai-Breaking-Parser-Logic-Take-Your-Path-Normalization-Off-And-Pop-0days-Out-2.pdf<br />"
            + "https://gist.github.com/orangetw/d0d396d01b5ca31fe3b9125718a14d9d";

    private static final String REMEDY = "This issue seems to affect the infrastructure components (reverse proxy and Servlet Container). <br />" +
          "A possible mitigation is to isolate the back-end application, by removing the management console and other private Servlet contexts.";

    private PrintWriter stderr;
    private PrintWriter stdout;

    private static LinkedHashSet hsc = new LinkedHashSet();

    // TODO FIXME Find a more generic strategy
    private static final List<String> TOMCAT_URI_NORMALIZATIONS = Arrays.asList(
            "..;/manager/html",
            "..;/"
    );

    @Override
    public List<IScanIssue> scan(IBurpExtenderCallbacks callbacks, IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {

        IExtensionHelpers helpers = callbacks.getHelpers();
        stderr = new PrintWriter(callbacks.getStderr(), true);
        stdout = new PrintWriter(callbacks.getStdout(), true);

        IRequestInfo reqInfo = helpers.analyzeRequest(baseRequestResponse);

        List<IScanIssue> issues = new ArrayList<>();

        URL curURL = reqInfo.getUrl();
        String context = getApplicationContext(curURL);
        String contextAndNestedPath = getApplicationContextAndNestedPath(curURL);

        if (context.isEmpty() && contextAndNestedPath.isEmpty()) {
            return issues;
        }

        List<String> contexts = Arrays.asList(
                context,
                contextAndNestedPath
        );

        String host = curURL.getHost();
        int port = curURL.getPort();
        String system = host.concat(Integer.toString(port));

        String contextURI = system + context;
        String contextURIAndNestedPath = system + contextAndNestedPath;

        String protocol = curURL.getProtocol();
        Boolean isSSL = (protocol.equals("https"));

        if (!hsc.contains(contextURI) || !hsc.contains(contextURIAndNestedPath)) {

            hsc.add(contextURI);
            hsc.add(contextURIAndNestedPath);

            for (String tomcat_uri_normalization : TOMCAT_URI_NORMALIZATIONS) {

                URL urlToTest;

                for (String cur_context : contexts) {

                    if (cur_context.isEmpty()) {
                        continue;
                    }

                    try {

                        urlToTest = new URL(protocol, curURL.getHost(), curURL.getPort(), cur_context + tomcat_uri_normalization);

                        stdout.println("Testing URINormalization issue at " + urlToTest);

                        byte[] uriNormalizationAttempt = helpers.buildHttpRequest(urlToTest);

                        byte[] responseBytes = callbacks.makeHttpRequest(curURL.getHost(),
                                curURL.getPort(), isSSL, uriNormalizationAttempt);

                        IResponseInfo tomcatManagerInfo = helpers.analyzeResponse(responseBytes);

                        if (tomcatManagerInfo.getStatusCode() == 401) {
                            // Check Authorization header

                            List<String> responseHeaders = tomcatManagerInfo.getHeaders();
                            for (int h = 0; h < responseHeaders.size(); h++) {
                                if (responseHeaders.get(h).toLowerCase().startsWith("www-authenticate")
                                        && responseHeaders.get(h).toLowerCase().contains("tomcat manager")) {

                                    issues.add(new CustomScanIssue(
                                            baseRequestResponse.getHttpService(),
                                            urlToTest,
                                            new CustomHttpRequestResponse(uriNormalizationAttempt, responseBytes, baseRequestResponse.getHttpService()),
                                            TITLE,
                                            DESCRIPTION,
                                            REMEDY,
                                            Risk.High,
                                            Confidence.Certain
                                    ));

                                }
                            }
                        }

                        // URI Normalization test case successful but the Application server replies with:
                        // - /manager/html -> 403 Forbidden
                        // - / -> default apache tomcat page
                        // 
                        // The vulnerability is detected but the business impact is usually lower, if it's not 
                        // possible to access directly to the Tomcat Manager Console
                        
                        final byte[] GREP_STRING = "Apache Tomcat".getBytes();

                        // look for matches of our active check grep string
                        List<int[]> matches = getMatches(responseBytes, GREP_STRING, helpers);
                        if ((matches.size() > 0) && (tomcatManagerInfo.getStatusCode() == 200)) {
                            issues.add(new CustomScanIssue(
                                    baseRequestResponse.getHttpService(),
                                    urlToTest,
                                    new CustomHttpRequestResponse(uriNormalizationAttempt, responseBytes, baseRequestResponse.getHttpService()),
                                    TITLE,
                                    DESCRIPTION,
                                    REMEDY,
                                    Risk.Medium,
                                    Confidence.Certain
                            ));
                        }

                    } catch (MalformedURLException ex) {
                        stderr.println(ex);
                        return issues;
                    }

                }
            }
        }

        return issues;

    }
}
