package burp.j2ee.issues.impl;

import static burp.HTTPMatcher.getApplicationContext;
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
import burp.j2ee.issues.IModule;

import java.io.PrintWriter;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.List;



public class SpringBootActuator implements IModule {

    private static final String TITLE = "Spring Boot Actuator";
    private static final String DESCRIPTION = "J2EEscan identified the Spring Boot Actuator endpoint. <br />"
            + "This development console allows to access remote sensitive information (ex: enviroment variables, http sessions)<br /><br/>."
            + "The endpoints could be:<br >"
            + "<ul>"
            + "<li>autoconfig</li>"
            + "<li>beans</li>"
            + "<li>configprops</li>"
            + "<li>dump</li>"
            + "<li>env</li>"
            + "<li>health</li>"
            + "<li>info</li>"            
            + "<li>metrics</li>"   
            + "<li>mappings</li>"   
            + "<li>shutdown</li>"               
            + "<li>trace</li>"                           
            + "</ul>"
            + "<br /><b>References</b><br />"
            + "http://docs.spring.io/spring-boot/docs/current/reference/htmlsingle/#production-ready-endpoints";
    private static final String REMEDY = "Disable access to this endpointon on the production server";

    private static final byte[] GREP_STRING = "{\"status\":\"UP\"}".getBytes();
    private static final List<String> SPRINGBOOT_ACTUATOR_PATHS = Arrays.asList(
            "/health",
            "/manager/health"
    );

    // List of host and port system already tested
    private static LinkedHashSet hs = new LinkedHashSet();
    // List of host port and context already tested
    private static LinkedHashSet hsc = new LinkedHashSet();

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

            for (String springboot_path : SPRINGBOOT_ACTUATOR_PATHS) {

                try {
                    URL urlToTest = new URL(protocol, url.getHost(), url.getPort(), springboot_path);
                    byte[] webconsoleRequest = helpers.buildHttpRequest(urlToTest);

                    // make a request containing our injection test in the insertion point
                    IHttpRequestResponse checkRequestResponse = callbacks.makeHttpRequest(
                            baseRequestResponse.getHttpService(), webconsoleRequest);

                    // look for matches of our active check grep string
                    List<int[]> matches = getMatches(checkRequestResponse.getResponse(), GREP_STRING, helpers);
                    if (matches.size() > 0) {

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
                } catch (MalformedURLException ex) {
                    stderr.println("Error creating URL " + ex.getMessage());
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

            for (String webconsole_path : SPRINGBOOT_ACTUATOR_PATHS) {

                try {
                    URL urlToTest = new URL(protocol, url.getHost(), url.getPort(), context + webconsole_path);
                    byte[] webconsoleRequest = helpers.buildHttpRequest(urlToTest);

                    // make a request containing our injection test in the insertion point
                    IHttpRequestResponse checkRequestResponse = callbacks.makeHttpRequest(
                            baseRequestResponse.getHttpService(), webconsoleRequest);

                    // look for matches of our active check grep string
                    List<int[]> matches = getMatches(checkRequestResponse.getResponse(), GREP_STRING, helpers);
                    if (matches.size() > 0) {

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
                } catch (MalformedURLException ex) {
                    stderr.println("Error creating URL " + ex.getMessage());
                }
            }

        }

        return issues;
    }
}
