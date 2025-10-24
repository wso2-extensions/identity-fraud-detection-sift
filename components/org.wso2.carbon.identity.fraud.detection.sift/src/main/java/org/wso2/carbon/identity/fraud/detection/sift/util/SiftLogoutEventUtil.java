package org.wso2.carbon.identity.fraud.detection.sift.util;

import com.siftscience.exception.InvalidFieldException;
import com.siftscience.model.Browser;
import com.siftscience.model.EventResponseBody;
import com.siftscience.model.LogoutFieldSet;
import org.apache.commons.codec.digest.DigestUtils;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.context.SessionContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;
import org.wso2.carbon.identity.fraud.detection.sift.models.SiftFraudDetectorRequestDTO;
import org.wso2.carbon.identity.fraud.detection.sift.models.SiftFraudDetectorResponseDTO;
import org.wso2.carbon.identity.fraud.detectors.core.constant.FraudDetectorConstants;
import org.wso2.carbon.identity.fraud.detectors.core.exception.IdentityFraudDetectorRequestException;
import org.wso2.carbon.identity.fraud.detectors.core.exception.IdentityFraudDetectorResponseException;
import org.wso2.carbon.identity.fraud.detectors.core.model.FraudDetectorResponseDTO;

import java.util.Map;

import static org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants.AUTHENTICATED_USER;
import static org.wso2.carbon.identity.event.IdentityEventConstants.EventProperty.CONTEXT;
import static org.wso2.carbon.identity.event.IdentityEventConstants.EventProperty.SESSION_CONTEXT;
import static org.wso2.carbon.identity.event.IdentityEventConstants.EventProperty.TENANT_DOMAIN;
import static org.wso2.carbon.identity.fraud.detection.sift.util.Util.setAPIKey;

public class SiftLogoutEventUtil {

    public static String handleLogoutEventPayload(SiftFraudDetectorRequestDTO requestDTO)
            throws IdentityFraudDetectorRequestException {

        Map<String, Object> properties = requestDTO.getProperties();
        String tenantDomain = (String) properties.get(TENANT_DOMAIN);
        AuthenticationContext authenticationContext = (AuthenticationContext) properties.get(CONTEXT);
        SessionContext sessionContext = (SessionContext) properties.get(SESSION_CONTEXT);
        boolean isLogoutTriggeredFromApplication = authenticationContext != null;
        try {
            LogoutFieldSet logoutFieldSet = new LogoutFieldSet()
                    .setUserId(resolveUserId(sessionContext))
                    .setBrowser(new Browser().setUserAgent(SiftEventUtil.resolveUserAgent()))
                    .setIp(SiftEventUtil.resolveRemoteAddress())
                    .setCustomField("is_logout_triggered_from_application", isLogoutTriggeredFromApplication);
            logoutFieldSet.validate();
            return setAPIKey(logoutFieldSet, tenantDomain);
        } catch (InvalidFieldException e) {
            throw new IdentityFraudDetectorRequestException("Error while building logout event payload: "
                    + e.getMessage(), e);
        } catch (FrameworkException e) {
            throw new IdentityFraudDetectorRequestException("Error while resolving payload data: "
                    + e.getMessage(), e);
        }
    }

    public static FraudDetectorResponseDTO handleLogoutResponse(String responseContent,
                                                                SiftFraudDetectorRequestDTO requestDTO)
            throws IdentityFraudDetectorResponseException {

        EventResponseBody responseBody = EventResponseBody.fromJson(responseContent);
        FraudDetectorConstants.FraudDetectionEvents eventName = requestDTO.getEventName();
        if (responseBody.getStatus() != 0) {
            throw new IdentityFraudDetectorResponseException("Error occurred while publishing event to Sift. Returned" +
                    "Sift status code: " + responseBody.getStatus() + " for event: " + eventName.name());
        }
        return new SiftFraudDetectorResponseDTO(FraudDetectorConstants.ExecutionStatus.SUCCESS, eventName);
    }

    private static String resolveUserId(SessionContext sessionContext)
            throws FrameworkException, IdentityFraudDetectorRequestException {

        if (sessionContext == null) {
            throw new IdentityFraudDetectorRequestException("Cannot resolve payload data. Both authentication " +
                    "context and session context are null.");
        }
        if (sessionContext.getProperties().containsKey(AUTHENTICATED_USER)) {
            return DigestUtils.sha256Hex(sessionContext.getProperties().get(AUTHENTICATED_USER).toString());
        } else {
            throw new IdentityFraudDetectorRequestException("Cannot resolve payload data. Authenticated user is not " +
                    "available in the session context.");
        }
    }
}
