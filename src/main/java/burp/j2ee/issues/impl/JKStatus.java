package burp.j2ee.issues.impl;

import burp.j2ee.CustomScanIssue;
import burp.CustomHttpRequestResponse;
import static burp.HTTPMatcher.URIMutator;
import static burp.HTTPMatcher.getMatches;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IRequestInfo;
import burp.IResponseInfo;
import burp.IScanIssue;
import burp.IScannerInsertionPoint;
import burp.WeakPasswordBruteforcer;
import burp.j2ee.Confidence;
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
 * Test for JK Management Endpoints
 * 
 * 
 * http://tomcat.apache.org/connectors-doc/miscellaneous/jkstatustasks.html
 * https://tomcat.apache.org/connectors-doc/common_howto/loadbalancers.html
 * 
 */
public class JKStatus implements IModule{

    // List of host and port system already tested
    private static LinkedHashSet hs = new LinkedHashSet();

    private static final String JK_MANAGEMENT_TITLE = "JK Management Enpoints";
    private static final String DESCRIPTION_JK_MANAGEMENT = "J2EEscan identified the JK managements endpoints accessible "
            + " to unauthenticated remote users.<br /><br />"
            + "<b>References:</b><br /><br />"
            + "http://tomcat.apache.org/connectors-doc/miscellaneous/jkstatustasks.html<br />"
            + "https://tomcat.apache.org/connectors-doc/common_howto/loadbalancers.html<br />";            

    private static final String REMEDY = "Disable or restrict access to the JK management endpoints";

    private static final List<String> JK_ENDPOINTS = Arrays.asList(
            "/jk-status",
            "/jkstatus-auth",
            "/jkstatus",
            "/jkmanager",
            "/jkmanager-auth",
            "/jdkstatus"
    );   

    private static final byte[] GREP_STRING = "JK Status Manager".getBytes();
    private PrintWriter stderr;

    
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

            List<String> JK_ENDPOINTS_MUTATED = URIMutator(JK_ENDPOINTS);
            for (String JK_ENDPOINT : JK_ENDPOINTS_MUTATED) {

                try {

                    URL urlToTest = new URL(protocol, url.getHost(), url.getPort(), JK_ENDPOINT);
                    byte[] jbosstest = helpers.buildHttpRequest(urlToTest);

                    byte[] response = callbacks.makeHttpRequest(url.getHost(),
                            url.getPort(), isSSL, jbosstest);

                    IResponseInfo jkMgmInfo = helpers.analyzeResponse(response);

                    if (jkMgmInfo.getStatusCode() == 200) {

                        // look for matches of our active check grep string
                        List<int[]> matcheInvoker = getMatches(response, GREP_STRING, helpers);
    
                        if (matcheInvoker.size() > 0){

                            issues.add(new CustomScanIssue(
                                    baseRequestResponse.getHttpService(),
                                    new URL(protocol, url.getHost(), url.getPort(), JK_ENDPOINT),
                                    new CustomHttpRequestResponse(jbosstest, response, baseRequestResponse.getHttpService()),
                                    JK_MANAGEMENT_TITLE,
                                    DESCRIPTION_JK_MANAGEMENT,
                                    REMEDY,
                                    Risk.High,
                                    Confidence.Certain
                            ));
                            
                            return issues;
                        }

                    }
 
                    
                    if (jkMgmInfo.getStatusCode() == 401) {
                        // Test Weak Passwords
                        CustomHttpRequestResponse httpWeakPasswordResult;
                        WeakPasswordBruteforcer br = new WeakPasswordBruteforcer();
                        httpWeakPasswordResult = br.HTTPBasicBruteforce(callbacks, urlToTest);

                        if (httpWeakPasswordResult != null) {
                            issues.add(new CustomScanIssue(
                                    baseRequestResponse.getHttpService(),
                                    new URL(protocol, url.getHost(), url.getPort(), urlToTest.getPath()),
                                    httpWeakPasswordResult,
                                    JK_MANAGEMENT_TITLE,
                                    DESCRIPTION_JK_MANAGEMENT,
                                    REMEDY,
                                    Risk.High,
                                    Confidence.Certain
                            ));

                            return issues;
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
