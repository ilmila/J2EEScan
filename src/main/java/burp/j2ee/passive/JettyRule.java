package burp.j2ee.passive;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IRequestInfo;
import burp.IResponseInfo;
import burp.j2ee.Confidence;
import burp.j2ee.CustomScanIssue;
import burp.j2ee.Risk;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class JettyRule implements PassiveRule {

    private static final Pattern JETTY_PATTERN = Pattern.compile("><small>Powered by Jetty", Pattern.DOTALL | Pattern.MULTILINE);
    
    @Override
    public void scan(IBurpExtenderCallbacks callbacks, IHttpRequestResponse baseRequestResponse,
                     String reqBody, String respBody, IRequestInfo reqInfo, IResponseInfo respInfo,
                     String httpServerHeader, String contentTypeResponse, String xPoweredByHeader) {
        IExtensionHelpers helpers = callbacks.getHelpers();

        /**
         * Detect Jetty
         */
        if (respBody != null && contentTypeResponse != null
                && (contentTypeResponse.contains("text/html") || (contentTypeResponse.contains("text/plain")))) {

            
            Matcher matcher = JETTY_PATTERN.matcher(respBody);

            if (matcher.find()) {
              
                callbacks.addScanIssue(new CustomScanIssue(
                        baseRequestResponse.getHttpService(),
                        reqInfo.getUrl(),
                        baseRequestResponse,
                        "Information Disclosure - Jetty",
                        "J2EEscan identified the remote Servlet Container",
                        "",
                        Risk.Information,
                        Confidence.Certain
                ));
            }

        }
  
    }
}
