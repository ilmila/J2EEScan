package burp.j2ee;

import burp.IBurpExtenderCallbacks;
import burp.IScanIssue;


public class IssuesHandler {
    
        
        /**
         * 
         * Verify for a specific protocol - host a specific
         * issue has been already detected
         * 
         * @param callbacks IBurpExtenderCallbacks
         * @param vulnerabilityName vulnerability to check if it's present into the issues
         * @param protocol (http/https)
         * @param host the hostname 
         * 
         */
        public static boolean isvulnerabilityFound(IBurpExtenderCallbacks callbacks, 
                String vulnerabilityName,
                String protocol,
                String host) {

        IScanIssue[] allIssues;

        allIssues = callbacks.getScanIssues(protocol + "://" + host);
        
        for (IScanIssue a : allIssues) {

            if (a.getIssueName().contains(vulnerabilityName)) {
                return true;
            }
        }
        
        return false;
    }
}
