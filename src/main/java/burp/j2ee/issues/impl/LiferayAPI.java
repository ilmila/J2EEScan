package burp.j2ee.issues.impl;

import java.net.MalformedURLException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.io.PrintWriter;
import java.net.URL;

import static burp.HTTPMatcher.getApplicationContext;

import burp.CustomHttpRequestResponse;
import burp.IBurpExtenderCallbacks;
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

public class LiferayAPI implements IModule{
    

    private final static List<String> PATHS = Arrays.asList(
        "/api/jsonws",  //JSON
        "/api/axis",    //SOAP
        "/api/liferay", //Liferay tunnel servlet
        "/webdav"       //WebDAV servlet
    );

    private final static List<Pattern> PATTERNS = Arrays.asList(
        Pattern.compile(".*<title>json-web-services-api<\\/title>.*", Pattern.DOTALL),
        Pattern.compile(".*<h2>And now\\.\\.\\. Some Services<\\/h2>.*", Pattern.DOTALL),
        Pattern.compile(".*Internal Server Error.*An error occurred while accessing the requested resource\\..*", Pattern.DOTALL)
    );

    private final static List<String[]> API = Arrays.asList(
        new String[]{ "JSON", "Liferay\'s default JSON web service", "https://help.liferay.com/hc/en-us/articles/360018151631-JSON-Web-Services <br />" +
                                                                     "https://help.liferay.com/hc/en-us/articles/360017872472-Service-Security-Layers" },
        new String[]{ "AXIS", "Liferay\'s default SOAP web service", "https://help.liferay.com/hc/en-us/articles/360017872492-SOAP-Web-Services <br />" +
                                                                     "https://help.liferay.com/hc/en-us/articles/360017872472-Service-Security-Layers" },
        new String[]{ "Liferay Tunnel", "Liferay tunnel servlet", "https://help.liferay.com/hc/en-us/articles/360017872472-Service-Security-Layers" },
        new String[]{ "WebDAV", "WebDAV allows access to files in a document library on a remote server", 
                                                                     "https://help.liferay.com/hc/en-us/articles/360018172711-Desktop-Access-to-Documents-and-Media <br />" +
                                                                     "https://help.liferay.com/hc/en-us/articles/360017872472-Service-Security-Layers" }
    );

    // List of host and port system already tested
    private static LinkedHashSet<String> hs = new LinkedHashSet<String>();
    
    IExtensionHelpers helpers;
    PrintWriter stderr;

    public List<IScanIssue> scan(IBurpExtenderCallbacks callbacks, IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
        List<IScanIssue> issues = new ArrayList<>();
        helpers = callbacks.getHelpers();
        stderr = new PrintWriter(callbacks.getStderr(), true);
        IRequestInfo reqInfo = helpers.analyzeRequest(baseRequestResponse);

        URL url = reqInfo.getUrl();
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

        // Check if the APIs have already been found
        for(String[] APIName : API)
            if(IssuesHandler.isvulnerabilityFound(callbacks, 
                        "J2EEScan - Liferay Hardening - API Exposed: " + APIName[0], 
                        protocol, 
                        host)){
                return issues;
            }

        Iterator<Pattern> patternIterator = PATTERNS.iterator();
        Iterator<String[]> APIIterator = API.iterator();


        String contextList[] = { "", getApplicationContext(url) };
        
        for(String context : contextList){

            String system = host + Integer.toString(port) + context;
            if(!hs.add(system))
                continue;

            for(String path : PATHS){
                String[] nameDetails = APIIterator.next();
            
                try{
                    URL urlMod = new URL(protocol, host, port, context + path);

                    if(nameDetails[0].contains("JSON") || nameDetails[0].contains("AXIS")){
                        Pattern p = patternIterator.next();

                        byte[] request = helpers.buildHttpRequest(urlMod);
                        byte[] response = callbacks.makeHttpRequest(host, port, useHttps, request);
                
                        IResponseInfo respInfo = helpers.analyzeResponse(response);

                        if(respInfo.getStatusCode() == 200){
                            Matcher m = p.matcher(helpers.bytesToString(response));

                            if(m.matches()){
                                issues.add(new CustomScanIssue(
                                    baseRequestResponse.getHttpService(), 
                                    urlMod, 
                                    new CustomHttpRequestResponse(request, response, baseRequestResponse.getHttpService()),
                                    "Liferay Hardening - API Exposed: " + nameDetails[0], 
                                    "The " + nameDetails[0] + " API has been found and can be accessed from \"" + urlMod.toString() 
                                    + "\": " + nameDetails[1] + ".<br /><br />"
                                    + "<b>References</b>:<br /><br />" + nameDetails[2], 
                                    "Restrict API access to local only",
                                    Risk.Medium, 
                                    Confidence.Certain
                                ));
                            }
                        }
                    }else if(nameDetails[0].contains("Tunnel")){
                        Pattern p = patternIterator.next();

                        byte[] request = helpers.buildHttpRequest(urlMod);
                        byte[] response = callbacks.makeHttpRequest(host, port, useHttps, request);
                    
                        IResponseInfo respInfo = helpers.analyzeResponse(response);

                        if(respInfo.getStatusCode() == 404){
                            Matcher m = p.matcher(helpers.bytesToString(response));

                            if(m.matches()){
                                issues.add(new CustomScanIssue(
                                    baseRequestResponse.getHttpService(), 
                                    urlMod, 
                                    new CustomHttpRequestResponse(request, response, baseRequestResponse.getHttpService()),
                                    "Liferay Hardening - API Exposed: " + nameDetails[0], 
                                    "The " + nameDetails[0] + " servlet has been found at \"" + urlMod.toString() 
                                    + "\".<br /><br />"
                                    + "<b>References</b>:<br /><br />" + nameDetails[2], 
                                    "Restrict servlet access to local only",
                                    Risk.Medium, 
                                    Confidence.Firm
                                ));
                            }
                        }
                    }else if(nameDetails[0].contains("WebDAV")){
                        byte[] request = helpers.buildHttpRequest(urlMod);
                        reqInfo = helpers.analyzeRequest(request);

                        List<String> headers = reqInfo.getHeaders();
                        headers.set(0, "PROPFIND " + path + " HTTP/1.1");
                        request = helpers.buildHttpMessage(headers, helpers.stringToBytes(""));  

                        byte[] response = callbacks.makeHttpRequest(host, port, useHttps, request);
                        IResponseInfo respInfo = helpers.analyzeResponse(response);

                        if(respInfo.getStatusCode() == 401){
                            issues.add(new CustomScanIssue(
                                    baseRequestResponse.getHttpService(), 
                                    urlMod, 
                                    new CustomHttpRequestResponse(request, response, baseRequestResponse.getHttpService()),
                                    "Liferay Hardening - API Exposed: " + nameDetails[0], 
                                    "The " + nameDetails[0] + " servlet has been found at \"" + urlMod.toString() 
                                    + "\": " + nameDetails[1] + ".<br /><br />"
                                    + "<b>References</b>:<br /><br />" + nameDetails[2], 
                                    "Restrict servlet access to local only",
                                    Risk.Medium, 
                                    Confidence.Firm
                                ));
                        }
                   
                    }

                }catch(MalformedURLException ex){
                    stderr.println("Malformed URL Exception: " + ex);
                }
            }
        }

        return issues;
    }


}
