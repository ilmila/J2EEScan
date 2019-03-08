package burp.j2ee.issues.impl;

import burp.CustomHttpRequestResponse;
import static burp.HTTPMatcher.URIMutator;
import static burp.HTTPMatcher.getApplicationContext;
import static burp.HTTPMatcher.getMatches;
import static burp.HTTPMatcher.isJavaApplicationByURL;
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
 * Apache Struts S2-043 Using the Config Browser Plugin
 *
 * https://struts.apache.org/docs/s2-043.html
 *
 */
public class ApacheStrutsS2043 implements IModule {

    private static final String TITLE = "Apache Struts S2-043 Config Browser Plugin";
    private static final String DESCRIPTION = "J2EEscan identified a test/debug component in a production"
            + "environment.<br /> "
            + "A remote user could be able to access to multiple internal information such as:<br><ul>"
            + "<li>All Struts2 entry points into the application</li>"
            + "<li>Variable names</li>"
            + "<li>Stacktraces</li>"
            + "</ul>"
            + "<br /><br />"
            + "<b>References</b>:<br /><br />"
            + "https://struts.apache.org/docs/config-browser-plugin.html<br />"
            + "https://struts.apache.org/docs/s2-043.html<br />"
            + "http://security.coverity.com/blog/2013/Sep/making-struts2-app-more-secure-dont-include-config-browser.html";

    private static final String REMEDY = "Disable the Config Browser Plugin";

    // List of host and port system already tested
    private static LinkedHashSet hs = new LinkedHashSet();
    // List of host port and context already tested
    private static LinkedHashSet hsc = new LinkedHashSet();
    private static final List<String> BROWSER_PATHS = Arrays.asList(
            "/config-browser/actionNames",
            "/config-browser/actionNames.action"
    );
    private static final byte[] GREP_STRING = "<title>Actions in namespace</title>".getBytes();

    private PrintWriter stderr;
    private PrintWriter stdout;

    @Override
    public List<IScanIssue> scan(IBurpExtenderCallbacks callbacks, IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {

        IExtensionHelpers helpers = callbacks.getHelpers();
        stderr = new PrintWriter(callbacks.getStderr(), true);
        stdout = new PrintWriter(callbacks.getStderr(), true);

        IRequestInfo reqInfo = helpers.analyzeRequest(baseRequestResponse);

        URL url = reqInfo.getUrl();
        String host = url.getHost();
        int port = url.getPort();

        String system = host.concat(Integer.toString(port));

        List<IScanIssue> issues = new ArrayList<>();

        if (!isJavaApplicationByURL(url)) {
            return issues;
        }

        List<String> BROWSER_PATHS_MUTATED = URIMutator(BROWSER_PATHS);
        
        // System not yet tested for this vulnerability
        if (!hs.contains(system)) {
            hs.add(system);

            String protocol = url.getProtocol();
            Boolean isSSL = (protocol.equals("https"));

            
            for (String BROWSER_PATH : BROWSER_PATHS_MUTATED) {
                try {

                    // Test for happy axies
                    URL browserUrlToTest = new URL(protocol, url.getHost(), url.getPort(), BROWSER_PATH);
                    byte[] strutsBrowserTest = helpers.buildHttpRequest(browserUrlToTest);
                    byte[] browserResponse = callbacks.makeHttpRequest(url.getHost(),
                            url.getPort(), isSSL, strutsBrowserTest);
                    IResponseInfo strutsBrowserInfo = helpers.analyzeResponse(browserResponse);

                    if (strutsBrowserInfo.getStatusCode() == 200) {

                        String browserResp = helpers.bytesToString(browserResponse);
                        String strutsBrowserRespBody = browserResp.substring(strutsBrowserInfo.getBodyOffset());

                        // look for matches of our active check grep string
                        List<int[]> matchStrutsBrowser = getMatches(helpers.stringToBytes(strutsBrowserRespBody),
                                GREP_STRING, helpers);

                        if ((matchStrutsBrowser.size() > 0)) {
                            stdout.println("Struts Browser detected " + browserUrlToTest.toString());

                            issues.add(new CustomScanIssue(
                                    baseRequestResponse.getHttpService(),
                                    browserUrlToTest,
                                    new CustomHttpRequestResponse(strutsBrowserTest, browserResponse, baseRequestResponse.getHttpService()),
                                    TITLE,
                                    DESCRIPTION,
                                    REMEDY,
                                    Risk.Medium,
                                    Confidence.Certain
                            ));
                        }
                    }
                } catch (MalformedURLException ex) {
                    stderr.println("Malformed URL Exception " + ex);
                }
            }
        }

        /**
         * Test on the application context
         *
         * Ex: http://www.example.com/myapp/Login
         *
         * Retrieve the myapp context and test the issue
         *
         * Ex: http://www.example.com/myapp/manage/env
         */
        String context = getApplicationContext(url);

        if (context.isEmpty()) {
            return issues;
        }

        String contextURI = system + context;

        if (!hsc.contains(contextURI)) {

            hsc.add(contextURI);
            String protocol = url.getProtocol();
            Boolean isSSL = (protocol.equals("https"));

            for (String BROWSER_PATH : BROWSER_PATHS_MUTATED) {
                try {

                    // Test for happy axies
                    URL browserUrlToTest = new URL(protocol, url.getHost(), url.getPort(), context + BROWSER_PATH);
                    byte[] strutsBrowserTest = helpers.buildHttpRequest(browserUrlToTest);
                    byte[] browserResponse = callbacks.makeHttpRequest(url.getHost(),
                            url.getPort(), isSSL, strutsBrowserTest);
                    IResponseInfo strutsBrowserInfo = helpers.analyzeResponse(browserResponse);

                    if (strutsBrowserInfo.getStatusCode() == 200) {

                        String browserResp = helpers.bytesToString(browserResponse);
                        String strutsBrowserRespBody = browserResp.substring(strutsBrowserInfo.getBodyOffset());

                        // look for matches of our active check grep string
                        List<int[]> matchStrutsBrowser = getMatches(helpers.stringToBytes(strutsBrowserRespBody),
                                GREP_STRING, helpers);

                        if ((matchStrutsBrowser.size() > 0)) {
                            stdout.println("Struts Browser detected " + browserUrlToTest.toString());

                            issues.add(new CustomScanIssue(
                                    baseRequestResponse.getHttpService(),
                                    browserUrlToTest,
                                    new CustomHttpRequestResponse(strutsBrowserTest, browserResponse, baseRequestResponse.getHttpService()),
                                    TITLE,
                                    DESCRIPTION,
                                    REMEDY,
                                    Risk.Medium,
                                    Confidence.Certain
                            ));
                        }
                    }
                } catch (MalformedURLException ex) {
                    stderr.println("Malformed URL Exception " + ex);
                }
            }
        }

        return issues;
    }
}
