package burp.j2ee.issues.impl;

import static burp.HTTPMatcher.getMatches;
import static burp.HTTPMatcher.isJavaApplicationByURL;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IParameter;
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
 * Apache Struts Debug mode OGNL Console - OGNL Injection
 *
 * https://struts.apache.org/docs/debugging.html
 * https://struts.apache.org/docs/devmode.html
 * http://www.pwntester.com/blog/2014/01/21/struts-2-devmode-an-ognl-backdoor/
 *
 *
 */
public class ApacheStrutsDebugMode implements IModule {

    private static final String TITLE = "Apache Struts - Debug Mode - OGNL Console - OGNL Injection";
    private static final String DESCRIPTION = "J2EEscan identified the Development Mode (aka \"devMode\") "
            + "on the remote Apache Struts application."
            + "Web Console through . <br />"
            + "The <i>Debugging Interceptor</i> provides three debugging modes to provide "
            + "insight into the data behind the page. <br />"
            + "The <i>xml mode</i> formats relevant framework objects as an XML document. <br />"
            + "The <b>console mode</b> provides a OGNL command line that accepts entry of runtime expressions. "
            + "<b>This could lead to RCE</b><br /> "
            + "The <i>browser mode</i> adds an interactive page that display objects from the Value Stack. <br /><br />"
            + "<b>References</b>:<br />"
            + "https://struts.apache.org/docs/debugging.html<br />"
            + "https://struts.apache.org/docs/devmode.html<br />"
            + "http://www.pwntester.com/blog/2014/01/21/struts-2-devmode-an-ognl-backdoor/";

    private static final String REMEDY = "Modify the <i>struts.devMode</i> property on the production server";

    /**
     * Example of response with ?debug=console parameter in the request
        <head>
            <script type="text/javascript">
            var baseUrl = "/struts";
            window.open(baseUrl+"/webconsole.html", 'OGNL Console','width=500,height=450,status=no,toolbar=no,menubar=no');
            </script>
        </head>
        <body>
        <pre>
    */
    private static final byte[] GREP_STRING = "'OGNL Console'".getBytes();


    private PrintWriter stderr;

    @Override
    public List<IScanIssue> scan(IBurpExtenderCallbacks callbacks, IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {

        IExtensionHelpers helpers = callbacks.getHelpers();
        stderr = new PrintWriter(callbacks.getStderr(), true);

        List<IScanIssue> issues = new ArrayList<>();

        IRequestInfo reqInfo = callbacks.getHelpers().analyzeRequest(baseRequestResponse);
        URL url = reqInfo.getUrl();

        if (!isJavaApplicationByURL(url)) {
            return issues;
        }
 
        byte[] rawrequest = baseRequestResponse.getRequest();
        List<IParameter> parameters = reqInfo.getParameters();

        //Remove URI parameters
        for (IParameter param : parameters) {
            rawrequest = callbacks.getHelpers().removeParameter(rawrequest, param);
        }

        rawrequest = callbacks.getHelpers().addParameter(rawrequest,
                callbacks.getHelpers().buildParameter("debug", "console", IParameter.PARAM_URL)
        );

        // make a request containing our injection test in the insertion point
        IHttpRequestResponse checkRequestResponse = callbacks.makeHttpRequest(
                baseRequestResponse.getHttpService(), rawrequest);

        byte[] response = checkRequestResponse.getResponse();
        List<int[]> matches = getMatches(response, GREP_STRING, helpers);

        if (matches.size() > 0) {

            issues.add(new CustomScanIssue(
                    baseRequestResponse.getHttpService(),
                    reqInfo.getUrl(),
                    checkRequestResponse,
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

/**
 * *
 * Proof of concept:
 *
 * GET /test.do?debug=console HTTP/1.1 
 * Host: www.example.com 
 * User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko

 *
 * HTTP/1.1 200 OK 
 * Connection: close 
 * Date: Sat, 30 Jan 2016 18:54:24 GMT
 * Content-Type: text/html; 
 *
 * <!DOCTYPE html>
 * <html>
 * <head>
 * <script type="text/javascript">
 * var baseUrl = "/struts"; window.open(baseUrl+"/webconsole.html", 'OGNL
 * Console','width=500,height=450,status=no,toolbar=no,menubar=no');
 * </script>
 * </head>
 * <body>
 *
 *
 *
 * POST /index.do HTTP/1.1 
 * Host: www.example.com 
 * Connection: keep-alive
 * X-Requested-With: XMLHttpRequest 
 * Content-Type: application/x-www-form-urlencoded; charset=UTF-8 
 * Accept-Encoding: gzip,
 *
 * debug=command&expression=1%2B1
 *
 *
 *
 * GET /test.do?debug=browser HTTP/1.1 
 * Host: www.example.com
 * User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko
 *
 *
 * HTTP/1.1 200 OK 
 * Date: Sat, 30 Jan 2016 18:40:04 GMT 
 * Content-Length: 1
 * Content-Type: text/plain; charset=GB2312 
 * X-Powered-By: Servlet/2.5 JSP/2.1
 *
 * 2
 *
 */
