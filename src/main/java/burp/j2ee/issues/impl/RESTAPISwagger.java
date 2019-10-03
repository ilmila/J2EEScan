
package burp.j2ee.issues.impl;

import burp.CustomHttpRequestResponse;
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
 * REST API Swagger End-Point detection
 * 
 * 
 * 
 */
public class RESTAPISwagger  implements IModule {

    // List of host and port system already tested
    private static LinkedHashSet hs = new LinkedHashSet();
    // List of host  port and context already tested
    private static LinkedHashSet hsc = new LinkedHashSet();
    private PrintWriter stderr;

    private static final List<String> SWAGGER_APIS = Arrays.asList(
            "/swagger-ui.html",
            "/swagger/swagger-ui.html",
            "/api/swagger-ui.html",
            "/swagger/index.html",
            "/%20/swagger-ui.html"
    );

    private static final byte[] GREP_STRING = "<title>Swagge".getBytes();

    private static final String TITLE = "REST API Swagger Endpoint";
    private static final String REMEDY = "Verify if test/pre-production REST API are defined in a production environment.";
               
    private static final String DESCRIPTION = "J2EEscan identified the REST Swagger endpoint <br /><br />"
            + "<b>References</b>:<br /><br />"
            + "https://swagger.io/<br>"
            + "https://hawkinsecurity.com/2017/12/13/rce-via-spring-engine-ssti/";

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

        /**
         * Attempt on the web root
         *
         * http://www.example.com/swagger-ui.html
         */
        // System not yet tested for this vulnerability
        if (!hs.contains(system)) {

            hs.add(system);

            String protocol = url.getProtocol();
            Boolean isSSL = (protocol.equals("https"));

            for (String SWAGGER_PATH : SWAGGER_APIS) {

                try {

                    URL urlToTest = new URL(protocol, url.getHost(), url.getPort(), SWAGGER_PATH);
                    byte[] swaggerRootRequest = helpers.buildHttpRequest(urlToTest);

                    byte[] response = callbacks.makeHttpRequest(url.getHost(),
                            url.getPort(), isSSL, swaggerRootRequest);

                    IResponseInfo swaggerInfo = helpers.analyzeResponse(response);

                    // look for matches of our active check grep string
                    List<int[]> matches = getMatches(response, GREP_STRING, helpers);
                    if ((matches.size() > 0) && (swaggerInfo.getStatusCode() == 200)) {

                        // Retrieve servlet classes                                
                        issues.add(new CustomScanIssue(
                                baseRequestResponse.getHttpService(),
                                new URL(protocol, url.getHost(), url.getPort(), SWAGGER_PATH),
                                new CustomHttpRequestResponse(swaggerRootRequest, response, baseRequestResponse.getHttpService()),
                                TITLE,
                                DESCRIPTION,
                                REMEDY,
                                Risk.Low,
                                Confidence.Firm
                        ));

                       
                        return issues;

                    }

                } catch (MalformedURLException ex) {
                    stderr.println("Malformed URL Exception " + ex);
                }
            }
        }

        
        /**
         * Attempt on the application context
         *
         * Ex: http://www.example.com/myapp/Login
         *
         * Retrieve the myapp context and test it
         *
         * Ex: http://www.example.com/myapp/swagger-ui.html
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

            for (String SWAGGER_PATH : SWAGGER_APIS) {

                try {

                    URL urlToTest = new URL(protocol, url.getHost(), url.getPort(), context + SWAGGER_PATH);
                    byte[] swaggerCtxRequest = helpers.buildHttpRequest(urlToTest);

                    byte[] response = callbacks.makeHttpRequest(url.getHost(),
                            url.getPort(), isSSL, swaggerCtxRequest);

                    IResponseInfo swaggerInfo = helpers.analyzeResponse(response);

                    // look for matches of our active check grep string
                    List<int[]> matches = getMatches(response, GREP_STRING, helpers);
                    if ((matches.size() > 0) && (swaggerInfo.getStatusCode() == 200)) {

                        issues.add(new CustomScanIssue(
                                baseRequestResponse.getHttpService(),
                                new URL(protocol, url.getHost(), url.getPort(), SWAGGER_PATH),
                                new CustomHttpRequestResponse(swaggerCtxRequest, response, baseRequestResponse.getHttpService()),
                                TITLE,
                                DESCRIPTION,
                                REMEDY,
                                Risk.High,
                                Confidence.Certain
                        ));


                        return issues;

                    }

                } catch (MalformedURLException ex) {
                    stderr.println("Malformed URL Exception " + ex);
                }
            }
        }

        return issues;
    }

}

