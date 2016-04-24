package burp.j2ee.passive;

import burp.IBurpExtenderCallbacks;
import burp.IHttpRequestResponse;
import burp.IRequestInfo;
import burp.IResponseInfo;
import burp.IScanIssue;
import org.junit.Test;
import org.mockito.Matchers;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

public class ApacheStrutsS2023RuleTest {


    @Test
    public void testVulnerableToken() {
        testInputField("<input type=\"hidden\" name=\"token\" value=\"P6DFW9HJWBL6OZ5IMHGB21PC0OLAZCFO\" />", true);
        testInputField("<input type=\"hidden\" name=\"token\" value=\"M392002D7K0RPB528MIEMS6M8JO6W8SK\" />", true);
        testInputField("<input type=\"hidden\" name=\"token\" value=\"37XAHNZS547RUW59N2IFIL7ZYPW37VSQ\" />", true);
    }

    @Test
    public void testFalsePositive() {
        //False positive
        testInputField("<input type=\"hidden\" name=\"token\" value=\"HJ6MHGBBOLAZ5DFW9WI21PC0PZCFOL6O\" />", false);
        //Potential seed.. but the following sequence is not confirm
        testInputField("<input type=\"hidden\" name=\"token\" value=\"P6DFW9HJWBL6OZ5IMHGB21PC0OL6W8SK\" />", false);
    }

    private static void testInputField(String stubResponse, boolean expectedVulnerableToken) {
        IBurpExtenderCallbacks cb = mock(IBurpExtenderCallbacks.class);
        IHttpRequestResponse reqResp = mock(IHttpRequestResponse.class);
        IRequestInfo reqInfo = mock(IRequestInfo.class);
        IResponseInfo respInfo = mock(IResponseInfo.class);

        ApacheStrutsS2023Rule rule = new ApacheStrutsS2023Rule();
        rule.scan(cb,reqResp,"",stubResponse,reqInfo,respInfo,"","", "");

        if(expectedVulnerableToken) {
            verify(cb).addScanIssue(Matchers.<IScanIssue>any());
        }
        else {
            verify(cb,never()).addScanIssue(Matchers.<IScanIssue>any());
        }

    }

}
