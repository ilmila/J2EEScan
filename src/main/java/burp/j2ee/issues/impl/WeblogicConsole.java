package burp.j2ee.issues.impl;

import burp.CustomHttpRequestResponse;
import static burp.HTTPMatcher.URIMutator;
import static burp.HTTPMatcher.getMatches;
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
import burp.j2ee.Risk;
import burp.j2ee.annotation.RunOnlyOnce;
import burp.j2ee.issues.IModule;
import java.io.PrintWriter;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.AbstractMap;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;

/**
 *
 * Test for Weblogic Admin Console
 *
 *
 */
public class WeblogicConsole implements IModule {

    private static final String TITLE = "Weblogic Admin Console";
    private static final String DESCRIPTION = "J2EEscan identified the weblogic admin console.";

    private static final String TITLE_WEAK_PASSWORD = "Weblogic Admin Console - Weak Password";
    private static final String DESCRIPTION__WEAK_PASSWORD = "J2EEscan identified the weblogic admin console password<br /><br />";

    private static final String REMEDY = "-";

    // List of host and port system already tested
    private static LinkedHashSet hs = new LinkedHashSet();
    private PrintWriter stderr;

    //private static final byte[] GREP_STRING = "<title>BEA WebLogic UDDI Explorer Home</title>".getBytes();
    private static final List<byte[]> GREP_WEBLOGIC_STRINGS = Arrays.asList(
            "<TITLE>BEA WebLogic Server Administration Console".getBytes(),
            "<title>Oracle WebLogic Server Administration Console".getBytes(),
            "<TITLE>WebLogic Server".getBytes()
    );

    private static final List<String> WEBLOGIC_CONSOLE_PATHS = Arrays.asList(
            "/console/login/LoginForm.jsp;ADMINCONSOLESESSION=TynPs0LnRt9BLctc13WMYmhQpsp3cG1LCNDp78TJyDfHMWhC4Kln!1225542286"
    );

    
    private String weblogicAdminBruteforcer(URL url, IBurpExtenderCallbacks callbacks, IHttpRequestResponse baseRequestResponse) {

        // Weak password
        List<Map.Entry<String, String>> credentials = new ArrayList<>();
        credentials.add(new AbstractMap.SimpleEntry<>("weblogic", "weblogic"));
        credentials.add(new AbstractMap.SimpleEntry<>("weblogic", "weblogic1"));
        credentials.add(new AbstractMap.SimpleEntry<>("weblogic", "weblogic01"));
        credentials.add(new AbstractMap.SimpleEntry<>("weblogic", "welcome1"));

        String body;

        IExtensionHelpers helpers = callbacks.getHelpers();

        List<String> headers = new ArrayList<>();
        headers.add("POST /console/j_security_check HTTP/1.1");
        headers.add("Host: " + url.getHost() + ":" + url.getPort());
        headers.add("Content-Type: application/x-www-form-urlencoded");
        headers.add("Cookie: ADMINCONSOLESESSION=pTsBVcsdVx2g20mxPJyyPDvqTwQmQDtw7R541DGJGGXD2qh4rDBJ!1211788216");

        for (Map.Entry<String, String> credential : credentials) {
            String user = credential.getKey();
            String pwd = credential.getValue();
            body = "userName=" + user + "&password=" + pwd + "&submit=+Login+&j_character_encoding=UTF-8&j_username=" + user + "&j_password=" + pwd;

            byte[] loginMessage = helpers.buildHttpMessage(headers, body.getBytes());
            IHttpRequestResponse resp = callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), loginMessage);

            // look for matches of our active check grep string in the response body
            byte[] httpResponse = resp.getResponse();
            IResponseInfo weblogicInfo = helpers.analyzeResponse(httpResponse);

            String locationHeader = HTTPParser.getResponseHeaderValue(weblogicInfo, "Location");

            /***
             * 
             * On WebLogic Server Version: 10.3.5.0 successful login with static cookies 
             * 
             * HTTP/1.1 302 Moved Temporarily
             * Location: http://<host>:7001/console
             * Set-Cookie: ADMINCONSOLESESSION=dGyhp1pMQH8NgtmPbN2v7TYcRZfdy21RJ1dXWVL4t3GrSR8ltGBM!-1002201200; path=/
             * X-Powered-By: Servlet/2.5 JSP/2.1
             * Content-Length: 263
             * 
             */
            
            if ((locationHeader != null) && (locationHeader.contains("/index.jsp") || locationHeader.endsWith("/console"))) {
                return String.format("%s:%s", user, pwd);
            }
        }

        return null;
    }

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

            List<String> WEBLOGIC_CONSOLE_PATHS_MUTATED = URIMutator(WEBLOGIC_CONSOLE_PATHS);
            for (String WEBLOGIC_CONSOLE_PATH : WEBLOGIC_CONSOLE_PATHS) {

                try {

                    URL urlToTest = new URL(protocol, url.getHost(), url.getPort(), WEBLOGIC_CONSOLE_PATH);
                    byte[] weblogictest = helpers.buildHttpRequest(urlToTest);
                    byte[] response = callbacks.makeHttpRequest(url.getHost(),
                            url.getPort(), isSSL, weblogictest);

                    IResponseInfo weblogicInfo = helpers.analyzeResponse(response);

                    // Weblogic Console available
                    if (weblogicInfo.getStatusCode() == 200) {
                        for (byte[] GREP_WEBLOGIC_STRING : GREP_WEBLOGIC_STRINGS) {
                            List<int[]> matches_weblogic = getMatches(response, GREP_WEBLOGIC_STRING, helpers);
                            if (matches_weblogic.size() > 0) {
                                issues.add(new CustomScanIssue(
                                        baseRequestResponse.getHttpService(),
                                        helpers.analyzeRequest(baseRequestResponse).getUrl(),
                                        new CustomHttpRequestResponse(weblogictest, response, baseRequestResponse.getHttpService()),
                                        TITLE,
                                        DESCRIPTION,
                                        REMEDY,
                                        Risk.Information,
                                        Confidence.Certain
                                ));

                                // Test for common password
                                // There isn't a default password for the console
                                String result = weblogicAdminBruteforcer(urlToTest, callbacks, baseRequestResponse);
                                if (result != null) {
                                    issues.add(new CustomScanIssue(
                                            baseRequestResponse.getHttpService(),
                                            helpers.analyzeRequest(baseRequestResponse).getUrl(),
                                            new CustomHttpRequestResponse(weblogictest, response, baseRequestResponse.getHttpService()),
                                            TITLE_WEAK_PASSWORD,
                                            DESCRIPTION__WEAK_PASSWORD + "<br /><b>" + result +"</b>",
                                            REMEDY,
                                            Risk.High,
                                            Confidence.Certain
                                    ));

                                }
                            }

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
