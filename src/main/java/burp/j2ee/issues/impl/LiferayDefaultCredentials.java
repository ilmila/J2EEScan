package burp.j2ee.issues.impl;

import java.io.PrintWriter;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static burp.HTTPMatcher.getApplicationContext;

import burp.CustomHttpRequestResponse;
import burp.IBurpExtenderCallbacks;
import burp.ICookie;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IRequestInfo;
import burp.IResponseInfo;
import burp.IScanIssue;
import burp.IScannerInsertionPoint;
import burp.j2ee.Confidence;
import burp.j2ee.CustomScanIssue;
import burp.j2ee.IssuesHandler;
import burp.j2ee.Risk;
import burp.j2ee.issues.IModule;


/**
 * This scanner try to identify if the login and registration page are accessible. If the login 
 * page can be accessed then the default admin credentials is checked. To send a request to do
 * the login is necessary to write in the request the JSESSIONID and the p_auth token.
 * These are related in some way by Liferay, so it is important that they are retrieved correctly.
 * 
 * TODO: Get a correct p_auth from http://[host]:[port]/LOGIN_PATH: 
 * To obtain a correct p_auth we need to send an HTTP request to http://[host]:[port]/LOGIN_PATH_REQ
 * and then read the response. 
 * If instead we try to retrieve the p_auth from the previous request used to check the presence of 
 * the login page (http://[host]:[port]/LOGIN_PATH), the p_auth is wrong.
 * 
 */
public class LiferayDefaultCredentials implements IModule {
 
    private static final String DEFAULT_EMAIL = "test%40liferay.com", 
                                DEFAULT_PASSWORD = "test", 
                                LOGIN_PATH = "/web/guest/home?p_p_id=com_liferay_login_web_portlet_LoginPortlet" +
                                             "&p_p_lifecycle=0&p_p_state=maximized&p_p_mode=view&saveLastPath=false" + 
                                             "&_com_liferay_login_web_portlet_LoginPortlet_mvcRenderCommandName=%2Flogin%2Flogin", 
                                LOGIN_PATH_REQ = "/web/guest/home?p_p_id=com_liferay_login_web_portlet_LoginPortlet" +
                                             "&p_p_lifecycle=1&p_p_state=maximized&p_p_mode=view" +
                                             "&_com_liferay_login_web_portlet_LoginPortlet_javax.portlet.action=%2Flogin%2Flogin" + 
                                             "&_com_liferay_login_web_portlet_LoginPortlet_mvcRenderCommandName=%2Flogin%2Flogin",
                                REGISTER_PATH = "/web/guest/home?p_p_id=com_liferay_login_web_portlet_LoginPortlet" + 
                                                "&p_p_lifecycle=0&p_p_state=maximized&p_p_mode=view&saveLastPath=false" +
                                                "&_com_liferay_login_web_portlet_LoginPortlet_mvcRenderCommandName=%2Flogin%2Fcreate_account";

    private static final String[] LOGIN_PATTERN = { ".*_com_liferay_login_web_portlet_LoginPortlet_login.*",
                                                    ".*_com_liferay_login_web_portlet_LoginPortlet_password.*" },
                                REGISTER_PATTERN = { ".*_com_liferay_login_web_portlet_LoginPortlet_emailAddress.*",
                                                     ".*_com_liferay_login_web_portlet_LoginPortlet_screenName.*" };
    
    private IExtensionHelpers helpers;
    private PrintWriter stderr;

    // List of host and port system already tested
    private static LinkedHashSet<String> hs = new LinkedHashSet<String>();

    public List<IScanIssue> scan(IBurpExtenderCallbacks callbacks, IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
        List<IScanIssue> issues = new ArrayList<>();

        helpers = callbacks.getHelpers();
        stderr = new PrintWriter(callbacks.getStderr(), true);
        IRequestInfo reqInfo = helpers.analyzeRequest(baseRequestResponse);

        URL url = reqInfo.getUrl(), urlMod;
        String host = url.getHost(), protocol = url.getProtocol();
        int port = url.getPort();
        Boolean useHttps = protocol.equals("https");

        // Check if Liferay has been found
        if (!IssuesHandler.isvulnerabilityFound(callbacks,
                "J2EEScan - Liferay detected",
                protocol,
                host)) {
            return issues;
        }

        // Check if the vulnerability has already been issued
        if (IssuesHandler.isvulnerabilityFound(callbacks,
                    "J2EEScan - Liferay Hardening - Login page found",
                    protocol,
                    host)) {
                return issues;
        }

        String contextList[] = { "",  getApplicationContext(url) };

        for(String context : contextList){

            String system = host + Integer.toString(port) + context;
            if(!hs.add(system))
                continue;

            try{

                // Check for login page
                urlMod = new URL(protocol, host, port, context + LOGIN_PATH);
        
                byte[] request = helpers.buildHttpRequest(urlMod);
                byte[] response = callbacks.makeHttpRequest(host, port, useHttps, request);

                IResponseInfo respInfo = helpers.analyzeResponse(response);

                if(respInfo.getStatusCode() == 200){
                    Pattern p1 = Pattern.compile(LOGIN_PATTERN[0], Pattern.DOTALL),
                            p2 = Pattern.compile(LOGIN_PATTERN[1], Pattern.DOTALL);
                    if(p1.matcher(helpers.bytesToString(response)).matches() && p2.matcher(helpers.bytesToString(response)).matches()){
                        issues.add(new CustomScanIssue(
                                baseRequestResponse.getHttpService(), 
                                urlMod, 
                                new CustomHttpRequestResponse(request, response, baseRequestResponse.getHttpService()),
                                "Liferay Hardening - Login page found", 
                                "The Liferay login page can be accessed from \"" + urlMod.toString() + "\"."
                                + "<br /><br /><b>References</b>:<br /><br />"
                                + "https://help.liferay.com/hc/es/articles/360028711192-Introduction-to-Securing-Liferay-DXP<br/>"
                                + "https://liferay.dev/blogs/-/blogs/quick-tips-for-liferay-hardening<br/>", 
                                "Disable access to the login page",
                                Risk.Information, 
                                Confidence.Certain
                            ));

                        // Check for default credentials
                        String p_auth="", JSESSIONID="";
                        List<ICookie> cookie = callbacks.getCookieJarContents();
                        for(ICookie c : cookie){
                            if(c.getName().equals("JSESSIONID") && baseRequestResponse.getHttpService().getHost().equals(c.getDomain())){
                                JSESSIONID=c.getValue();
                                break;
                            }
                        }

                        request = helpers.toggleRequestMethod(baseRequestResponse.getRequest());
                        reqInfo = helpers.analyzeRequest(request);

                        List<String> headers = reqInfo.getHeaders();
                        headers.set(0, "POST " + context + LOGIN_PATH_REQ + " HTTP/1.1");
                        headers.add("Cookie: COOKIE_SUPPORT=true; GUEST_LANGUAGE_ID=en_US; JSESSIONID=" + JSESSIONID 
                                    + "; LFR_SESSION_STATE_20102=" + String.valueOf(System.currentTimeMillis()));
                    
                        request = helpers.buildHttpMessage(headers, helpers.stringToBytes(""));  
                        response = callbacks.makeHttpRequest(host, port, useHttps, request);    //Used to retrieve p_auth

                        Pattern p = Pattern.compile(".*(Liferay\\.authToken)(\\s)?=(\\s)?('|\")(\\w*)('|\");.*");
                        Matcher m = p.matcher(helpers.bytesToString(response));

                        if(m.find()){          
                            p_auth = m.group(5);

                            request = helpers.buildHttpMessage(headers, helpers.stringToBytes(
                                                                        "_com_liferay_login_web_portlet_LoginPortlet_formDate=" + String.valueOf(System.currentTimeMillis()) +
                                                                        "&_com_liferay_login_web_portlet_LoginPortlet_saveLastPath=false" +
                                                                        "&_com_liferay_login_web_portlet_LoginPortlet_redirect=" +
                                                                        "&_com_liferay_login_web_portlet_LoginPortlet_doActionAfterLogin=false" +
                                                                        "&_com_liferay_login_web_portlet_LoginPortlet_login=" + DEFAULT_EMAIL + 
                                                                        "&_com_liferay_login_web_portlet_LoginPortlet_password=" + DEFAULT_PASSWORD + 
                                                                        "&_com_liferay_login_web_portlet_LoginPortlet_checkboxNames=rememberMe" + 
                                                                        "&p_auth=" + p_auth));

                    
                            response = callbacks.makeHttpRequest(host, port, useHttps, request);                     
                            respInfo = helpers.analyzeResponse(response);

                            if(respInfo.getStatusCode() == 302 || respInfo.getStatusCode() == 200){
                                p = Pattern.compile(".*((Set-Cookie: COMPANY_ID=\\d*;.*)(Set-Cookie: ID=\\w*;.*))"
                                                    + "|((Set-Cookie: ID=\\w*;.*)(Set-Cookie: COMPANY_ID=\\d*;.*)).*", Pattern.DOTALL);
                                m = p.matcher(helpers.bytesToString(response));

                                if(m.matches()){
                                    issues.add(new CustomScanIssue(
                                        baseRequestResponse.getHttpService(), 
                                        urlMod, 
                                        new CustomHttpRequestResponse(request, response, baseRequestResponse.getHttpService()),
                                        "Liferay Hardening - Default admin credentials found", 
                                        "The default admin credentials have been found.<br/> Email: " + DEFAULT_EMAIL.replace("%40", "@")
                                        + "<br/>Password: " + DEFAULT_PASSWORD, 
                                        "Disable the default admin user",
                                        Risk.High, 
                                        Confidence.Certain
                                    ));
                                }
                            }
                        }
                    }
                }

                // Check for registration page
                urlMod = new URL(protocol, host, port, context + REGISTER_PATH);
        
                request = helpers.buildHttpRequest(urlMod);
                response = callbacks.makeHttpRequest(host, port, useHttps, request);
                
                respInfo = helpers.analyzeResponse(response);

                if(respInfo.getStatusCode() == 200){
                    Pattern p1 = Pattern.compile(REGISTER_PATTERN[0], Pattern.DOTALL),
                            p2 = Pattern.compile(REGISTER_PATTERN[1], Pattern.DOTALL);
                
                    if(p1.matcher(helpers.bytesToString(response)).matches() && p2.matcher(helpers.bytesToString(response)).matches()){
                            issues.add(new CustomScanIssue(
                                baseRequestResponse.getHttpService(), 
                                urlMod, 
                                new CustomHttpRequestResponse(request, response, baseRequestResponse.getHttpService()),
                                "Liferay Hardening - Registration page found", 
                                "The Liferay registration page can be accessed from \"" + urlMod.toString() + "\"."
                                + "<br /><br /><b>References</b>:<br /><br />"
                                + "https://help.liferay.com/hc/es/articles/360028711192-Introduction-to-Securing-Liferay-DXP<br/>"
                                + "https://liferay.dev/blogs/-/blogs/quick-tips-for-liferay-hardening<br/>", 
                                "Disable access to the registration page",
                                Risk.Information, 
                                Confidence.Certain
                            ));
                    }
                }

            }catch(MalformedURLException ex){
                stderr.println("Malformed URL Exception: " + ex);
            }

        }

        return issues;
    }

}