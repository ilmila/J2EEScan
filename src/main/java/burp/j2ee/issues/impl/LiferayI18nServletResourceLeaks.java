package burp.j2ee.issues.impl;

import java.io.PrintWriter;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;

import static burp.HTTPMatcher.getMatches;
import static burp.HTTPMatcher.getApplicationContext;

import burp.CustomHttpRequestResponse;
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

/**
 * Tested on:
 * - Liferay Portal 7.3.0 GA1
 * - Liferay Portal 7.0.2 GA3
 * 
 * This scan check if the I18n Servlet leaks information by sending an HTTP request 
 * to /[language]/[resource];.js (also .jsp works). The test is taken from the 
 * source code that can be found on this link: 
 * https://github.com/liferay/liferay-portal/blob/master/modules/apps/portal/portal-util-test/src/testIntegration/java/com/liferay/portal/util/test/PortalImplLocaleTest.java#L116
 *
 */
public class LiferayI18nServletResourceLeaks implements IModule{

    private final static String PATH = "/en/WEB-INF/web.xml;.js";
    private static final byte[] REGEX = "<web-app id".getBytes();

    // List of host and port system already tested
    private static LinkedHashSet<String> hs = new LinkedHashSet<String>();
    // List of host port and context already tested
    private static LinkedHashSet<String> hsc = new LinkedHashSet<String>();

    private static final String TITLE = "Liferay - Resource leakage through I18nServlet";
    private static final String REMEDY = "Update Liferay to the latest version";

    IExtensionHelpers helpers;
    PrintWriter stderr;

    public List<IScanIssue> scan(IBurpExtenderCallbacks callbacks, IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
        List<IScanIssue> issues = new ArrayList<>();
        helpers = callbacks.getHelpers();
        stderr = new PrintWriter(callbacks.getStderr(), true);
        IRequestInfo reqInfo = helpers.analyzeRequest(baseRequestResponse);

        URL url = reqInfo.getUrl();
        String host = url.getHost(), protocol = url.getProtocol();
        int port = url.getPort();
        Boolean useHttps = protocol.equals("https");
        
        // Check if Liferay has been found
        if (!IssuesHandler.isvulnerabilityFound(callbacks,
                    "J2EEScan - Liferay detected",
                    protocol,
                    host)) {
                return issues;
        }

        // Check if the vulnerability has already been issued
        if (IssuesHandler.isvulnerabilityFound(callbacks,
                    "J2EEScan - Liferay - Resource leakage through I18nServlet",
                    protocol,
                    host)) {
                return issues;
        }


        String system = host.concat(Integer.toString(port));
        if(hs.add(system)) {
            try {
                URL urlMod = new URL(protocol, host, port, PATH);
                byte[] request = helpers.buildHttpRequest(urlMod);
                byte[] response = callbacks.makeHttpRequest(host, port, useHttps, request);

                IResponseInfo respInfo = helpers.analyzeResponse(response);
                if(respInfo.getStatusCode() == 200){
                    List<int[]> matches = getMatches(response, REGEX, helpers);


                    if(matches.size() > 0){
                        issues.add(new CustomScanIssue(
                                    baseRequestResponse.getHttpService(), 
                                    urlMod, 
                                    new CustomHttpRequestResponse(request, response, baseRequestResponse.getHttpService()),
                                    TITLE, 
                                    "The I18nServlet is used to display different languages in Liferay. By visiting "
                                    + protocol + "://" + host + ":" + port + "/en/[resource].jsp you can access [resource] file.<br />" 
                                    + "For example, by visiting " + urlMod.toString() + "is possible to read web.xml<br /><br />"
                                    + "<b>References</b>:<br /><br />"
                                    + "https://github.com/liferay/liferay-portal/blob/master/modules/apps/portal/portal-util-test/src/testIntegration/java/com/liferay/portal/util/test/PortalImplLocaleTest.java#L116<br />"
                                    + "https://github.com/liferay/liferay-portal/blob/master/portal-impl/src/com/liferay/portal/servlet/I18nServlet.java#L104",  
                                    REMEDY,
                                    Risk.Medium, 
                                    Confidence.Certain
                                ));
                    }
                }
            } catch (MalformedURLException ex) {
                stderr.println("Malformed URL Exception: " + ex);
            }
        }

        /**
         * Test on the application context
         */
        String context = getApplicationContext(url);

        if (context.isEmpty()) {
            return issues;
        }

        String contextURI = system + context;

        if(hsc.add(contextURI)){
            try {
                URL urlMod = new URL(protocol, host, port, context + PATH);
                byte[] request = helpers.buildHttpRequest(urlMod);
                byte[] response = callbacks.makeHttpRequest(host, port, useHttps, request);

                IResponseInfo respInfo = helpers.analyzeResponse(response);
                if(respInfo.getStatusCode() == 200){
                    List<int[]> matches = getMatches(response, REGEX, helpers);


                    if(matches.size() > 0){
                        issues.add(new CustomScanIssue(
                                    baseRequestResponse.getHttpService(), 
                                    urlMod, 
                                    new CustomHttpRequestResponse(request, response, baseRequestResponse.getHttpService()),
                                    TITLE, 
                                    "The I18nServlet is used to display different languages in Liferay. By visiting "
                                    + protocol + "://" + host + ":" + port + "/en/[resource].jsp you can access [resource] file.<br />" 
                                    + "For example, by visiting " + urlMod.toString() + "is possible to read web.xml<br /><br />"
                                    + "<b>References</b>:<br /><br />"
                                    + "https://github.com/liferay/liferay-portal/blob/master/modules/apps/portal/portal-util-test/src/testIntegration/java/com/liferay/portal/util/test/PortalImplLocaleTest.java#L116<br />"
                                    + "https://github.com/liferay/liferay-portal/blob/master/portal-impl/src/com/liferay/portal/servlet/I18nServlet.java#L104", 
                                    REMEDY,
                                    Risk.Medium, 
                                    Confidence.Certain
                                ));
                    }
                }
            } catch (MalformedURLException ex) {
                stderr.println("Malformed URL Exception: " + ex);
            }        
        }

        return issues;
    }
    
}
