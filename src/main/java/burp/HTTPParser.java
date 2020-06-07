package burp;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.Iterator;
import java.util.List;

public class HTTPParser {

    public static String getRequestHeaderValue(IRequestInfo requestInfo, String headerName) {
        headerName = headerName.toLowerCase().replace(":", "");
        for (String header : requestInfo.getHeaders()) {
            if (header.toLowerCase().startsWith(headerName)) {
                return header.split(":", 0)[1];
            }
        }
        return null;
    }

    public static String getResponseHeaderValue(IResponseInfo responseInfo, String headerName) {
        headerName = headerName.toLowerCase().replace(":", "");
        for (String header : responseInfo.getHeaders()) {
            if (header.toLowerCase().startsWith(headerName)) {
                return header.split(":", 2)[1];
            }
        }
        return null;
    }

    public static List<String> addOrUpdateHeader(List<String> headers, String newHeader, String newHeaderValue) {

        Iterator<String> iter = headers.iterator();
        while (iter.hasNext()) {
            if (iter.next().toLowerCase().contains(newHeader.toLowerCase())) {
                iter.remove();
            }
        }
        headers.add(String.format("%s: %s", newHeader, newHeaderValue));
        return headers;
    }

    public static String getHTTPBasicCredentials(IRequestInfo requestInfo) throws Exception {
        String authHeader = getRequestHeaderValue(requestInfo, "Authorization").trim();
        String[] parts = authHeader.split("\\s");

        if (parts.length != 2) {
            throw new Exception("Wrong number of HTTP Authorization header parts");
        }

        if (!parts[0].equalsIgnoreCase("Basic")) {
            throw new Exception("HTTP authentication must be Basic");
        }

        return parts[1];
    }

    public static URL concatenate(URL baseUrl, String extraPath) throws URISyntaxException, MalformedURLException {
        URI uri = baseUrl.toURI();

        String newPath = uri.getPath() + "/" + extraPath;
        URI newUri = uri.resolve(newPath);

        return newUri.toURL();
    }

    public static Boolean isJSONRequest(String contentTypeHeader) {
        
        return (contentTypeHeader.contains("json")) ||
               contentTypeHeader.contains("application/x-javascript") ||
               contentTypeHeader.contains("application/javascript");
        
    }

}
