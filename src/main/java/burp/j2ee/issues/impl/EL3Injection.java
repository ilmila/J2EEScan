package burp.j2ee.issues.impl;

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
import java.util.Arrays;
import java.util.List;


/**
 * 
 * This module tries to detect common EL3 Injection
 * 
 * Snippet of vulnerable code:
 * 
 * input1 = "System.getProperties()"
 * 
 * <%@page import="javax.el.ELProcessor"%>
 * <%@page import="javax.el.ELManager"%>
 * …
 * <%
 * String input1 = request.getParameter("input1");
 * ELProcessor elp = new ELProcessor();
 * Object sys = elp.eval(input1);
 * out.println(sys);
 * %>
 * 
 * Reference:
 * @sectooladdict
 * http://sectooladdict.blogspot.co.il/2014/12/el-30-injection-java-is-getting-hacker.html
 * 
 */

public class EL3Injection  implements IModule {

    private static final String TITLE = "EL 3.0/Lambda Injection";
    private static final String DESCRIPTION = "J2EEscan identified an EL 3.0 (Expression Language) "
            + "Injection vulnerability; an expression language makes it possible to easily "
            + "access application data stored in JavaBeans components and execute code on the server."  
            + "<br /><br />"
            + "<b>References</b>:<br /><br />"
            + "http://sectooladdict.blogspot.co.il/2014/12/el-30-injection-java-is-getting-hacker.html<br />"
            + "http://www.mindedsecurity.com/fileshare/ExpressionLanguageInjection.pdf<br />"
            + "https://jcp.org/en/jsr/detail?id=341<br />"; 
            
    private static final String REMEDY = "Do not use untrusted user input directly in lambda EL3 statements";

    private static final byte[] GREP_STRING = "java.vendor".getBytes();  
    private static final List<byte[]> EL_INJECTION_TESTS = Arrays.asList(
            "System.getProperties()".getBytes()
    );            
     
    @Override
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
            List<int[]> matches = getMatches(checkRequestResponse.getResponse(), GREP_STRING, helpers);
            if (matches.size() > 0) {

                issues.add(new CustomScanIssue(
                        baseRequestResponse.getHttpService(),
                        helpers.analyzeRequest(baseRequestResponse).getUrl(),
                        checkRequestResponse,
                        TITLE,
                        DESCRIPTION,
                        REMEDY,
                        Risk.High,
                        Confidence.Tentative
                ));
            }
            
        }    
          
        return issues;
    }
}
