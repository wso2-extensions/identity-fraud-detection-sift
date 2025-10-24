package org.wso2.carbon.identity.fraud.detection.sift.util;

import com.siftscience.exception.InvalidFieldException;
import com.siftscience.model.AbuseScore;
import com.siftscience.model.Browser;
import com.siftscience.model.EventResponseBody;
import com.siftscience.model.LoginFieldSet;
import com.siftscience.model.ScoreResponse;
import com.siftscience.model.WorkflowStatus;
import com.siftscience.model.WorkflowStatusHistoryConfig;
import com.siftscience.model.WorkflowStatusHistoryItem;
import java.util.Map;
import org.wso2.carbon.identity.application.authentication.framework.config.model.graph.js.JsAuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;
import org.wso2.carbon.identity.fraud.detection.sift.Constants;
import org.wso2.carbon.identity.fraud.detection.sift.models.SiftFraudDetectorRequestDTO;
import org.wso2.carbon.identity.fraud.detection.sift.models.SiftFraudDetectorResponseDTO;
import org.wso2.carbon.identity.fraud.detectors.core.constant.FraudDetectorConstants;
import org.wso2.carbon.identity.fraud.detectors.core.exception.IdentityFraudDetectorRequestException;
import org.wso2.carbon.identity.fraud.detectors.core.exception.IdentityFraudDetectorResponseException;
import org.wso2.carbon.identity.fraud.detectors.core.model.FraudDetectorResponseDTO;
import static org.wso2.carbon.identity.fraud.detection.sift.Constants.AUTHENTICATION_CONTEXT;
import static org.wso2.carbon.identity.fraud.detection.sift.Constants.CUSTOM_PARAMS;
import static org.wso2.carbon.identity.fraud.detection.sift.Constants.SIFT_ACCOUNT_TAKEOVER;
import static org.wso2.carbon.identity.fraud.detection.sift.Constants.SIFT_DECISION;
import static org.wso2.carbon.identity.fraud.detection.sift.Constants.SIFT_SESSION;
import static org.wso2.carbon.identity.fraud.detection.sift.util.Util.getLoginStatus;
import static org.wso2.carbon.identity.fraud.detection.sift.util.Util.processCustomParameters;
import static org.wso2.carbon.identity.fraud.detection.sift.util.Util.processDefaultParameters;
import static org.wso2.carbon.identity.fraud.detection.sift.util.Util.resolvePayloadData;
import static org.wso2.carbon.identity.fraud.detection.sift.util.Util.setAPIKey;

public class SiftLoginEventUtil {

    public static String handleLoginEventPayload(SiftFraudDetectorRequestDTO requestDTO)
            throws IdentityFraudDetectorRequestException {

        Map<String, Object> properties = requestDTO.getProperties();
        JsAuthenticationContext context = properties.get(AUTHENTICATION_CONTEXT) != null ?
                (JsAuthenticationContext) properties.get(AUTHENTICATION_CONTEXT) : null;
        if (context == null) {
            throw new IdentityFraudDetectorRequestException("Authentication context is null in the request.");
        }

        try {
            String loginStatus = getLoginStatus((String)properties.get(Constants.LOGIN_STATUS)).getSiftValue();
            LoginFieldSet loginFieldSet = new LoginFieldSet()
                    .setLoginStatus(loginStatus)
                    .setUserId(resolvePayloadData(Constants.USER_ID_KEY, context))
                    .setBrowser(new Browser().setUserAgent(resolvePayloadData(Constants.USER_AGENT_KEY, context)))
                    .setIp(resolvePayloadData(Constants.IP_KEY, context))
                    .setSessionId(resolvePayloadData(Constants.SESSION_ID_KEY, context));
            Map<String, Object> passedCustomParams = properties.get(CUSTOM_PARAMS) != null ?
                    (Map<String, Object>) properties.get(CUSTOM_PARAMS) : null;
            processDefaultParameters(loginFieldSet, passedCustomParams);
            processCustomParameters(loginFieldSet, passedCustomParams);
            loginFieldSet.validate();
            return setAPIKey(loginFieldSet, context.getWrapped().getTenantDomain());
        } catch (InvalidFieldException e) {
            throw new IdentityFraudDetectorRequestException("Error while building login event payload: "
                    + e.getMessage(), e);
        } catch (FrameworkException e) {
            throw new IdentityFraudDetectorRequestException("Error while resolving payload data: "
                    + e.getMessage(), e);
        }
    }

    public static FraudDetectorResponseDTO handleLoginResponse(String responseContent,
                                                               SiftFraudDetectorRequestDTO requestDTO)
            throws IdentityFraudDetectorResponseException {

        EventResponseBody responseBody = EventResponseBody.fromJson(responseContent);
        double riskScore = 0;
        String workflowDecision = null;

        if (responseBody.getStatus() != 0) {
            throw new IdentityFraudDetectorResponseException("Error occurred while publishing event to Sift. Returned" +
                    "Sift status code: " + responseBody.getStatus());
        }

        if (requestDTO.isReturnRiskScore()) {

            ScoreResponse scoreResponse = responseBody.getScoreResponse();
            AbuseScore abuseScore = scoreResponse != null && scoreResponse.getScores() != null ?
                    scoreResponse.getScores().get(SIFT_ACCOUNT_TAKEOVER) : null;
            if (abuseScore != null) {
                riskScore = abuseScore.getScore();
            }

        } else if (requestDTO.isReturnWorkflowDecision()) {

            ScoreResponse scoreResponse = responseBody.getScoreResponse();
            for (WorkflowStatus workflowStatus : scoreResponse.getWorkflowStatuses()) {
                if (workflowStatus != null && isATOAbuseType(workflowStatus) && isSessionType(workflowStatus)) {
                    workflowDecision = getDecision(workflowStatus);
                }
            }
        }

        SiftFraudDetectorResponseDTO responseDTO = new SiftFraudDetectorResponseDTO(
                FraudDetectorConstants.ExecutionStatus.SUCCESS, requestDTO.getEventName());
        responseDTO.setRiskScore(riskScore);
        responseDTO.setWorkflowDecision(workflowDecision);
        return responseDTO;
    }

    private static boolean isATOAbuseType(WorkflowStatus workflowStatus) {

        for (String abuseType : workflowStatus.getAbuseTypes()) {
            if (SIFT_ACCOUNT_TAKEOVER.equals(abuseType)) {
                return true;
            }
        }
        return false;
    }

    private static boolean isSessionType(WorkflowStatus workflowStatus) {

        if (workflowStatus.getEntity() == null) {
            return false;
        }
        return SIFT_SESSION.equals(workflowStatus.getEntity().getType());
    }

    private static String getDecision(WorkflowStatus workflowStatus) {

        if (workflowStatus.getHistory() == null) {
            return null;
        }
        for (WorkflowStatusHistoryItem historyItem : workflowStatus.getHistory()) {
            if (SIFT_DECISION.equals(historyItem.getApp())) {
                WorkflowStatusHistoryConfig config = historyItem.getConfig();
                if (config != null) {
                    return config.getDecisionId();
                }
            }
        }
        return null;
    }

}
