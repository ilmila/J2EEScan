package burp.j2ee.passive;


import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IRequestInfo;
import burp.IResponseInfo;
import burp.j2ee.Confidence;
import burp.j2ee.CustomScanIssue;
import burp.j2ee.Risk;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class SqlQueryRule implements PassiveRule {


    @Override
    public void scan(IBurpExtenderCallbacks callbacks, IHttpRequestResponse baseRequestResponse,
                     String reqBody, String respBody, IRequestInfo reqInfo, IResponseInfo respInfo,
                     String httpServerHeader, String contentTypeResponse) {

        IExtensionHelpers helpers = callbacks.getHelpers();

        /**
         * SQL statements in URL
         *
         * Improved detection for SQL statements in HTTP POST requests.
         */
        if (reqBody != null) {

            List<Pattern> sqlQueriesRe = new ArrayList();
            sqlQueriesRe.add(Pattern.compile("select ", Pattern.CASE_INSENSITIVE | Pattern.DOTALL | Pattern.MULTILINE));
            sqlQueriesRe.add(Pattern.compile("IS NOT NULL", Pattern.CASE_INSENSITIVE | Pattern.DOTALL | Pattern.MULTILINE));

            // check the pattern on response reqBody
            for (Pattern sqlQueryRule : sqlQueriesRe) {

                Matcher matcher = sqlQueryRule.matcher(helpers.urlDecode(reqBody));

                if (matcher.find()) {
                    callbacks.addScanIssue(new CustomScanIssue(
                            baseRequestResponse.getHttpService(),
                            helpers.analyzeRequest(baseRequestResponse).getUrl(),
                            baseRequestResponse,
                            "SQL Statements in HTTP Request",
                            "J2EEScan potentially identified SQL statements in HTTP POST requests.<br />"
                                    + "If SQL queries are passed from client to server in HTTP requests, a malicious user "
                                    + "could be able to alter the SQL statement executed on the remote database.",
                            "Analyse the issue and modify the application behaviour, removing the SQL queries from the HTTP requests.",
                            Risk.Medium,
                            Confidence.Tentative
                    ));
                }
            }
        }
    }
}
