package org.wso2.carbon.identity.fraud.detection.sift.util;

import com.siftscience.exception.InvalidFieldException;
import com.siftscience.model.Browser;
import com.siftscience.model.CreateAccountFieldSet;
import com.siftscience.model.EventResponseBody;
import org.wso2.carbon.identity.fraud.detection.sift.models.SiftFraudDetectorRequestDTO;
import org.wso2.carbon.identity.fraud.detection.sift.models.SiftFraudDetectorResponseDTO;
import org.wso2.carbon.identity.fraud.detectors.core.constant.FraudDetectorConstants;
import org.wso2.carbon.identity.fraud.detectors.core.exception.IdentityFraudDetectorRequestException;
import org.wso2.carbon.identity.fraud.detectors.core.exception.IdentityFraudDetectorResponseException;
import org.wso2.carbon.identity.fraud.detectors.core.model.FraudDetectorRequestDTO;
import org.wso2.carbon.identity.fraud.detectors.core.model.FraudDetectorResponseDTO;

import java.util.Map;
import org.wso2.carbon.user.core.UserCoreConstants;

import static org.wso2.carbon.identity.event.IdentityEventConstants.EventProperty.TENANT_DOMAIN;
import static org.wso2.carbon.identity.fraud.detection.sift.util.SiftEventUtil.resolveFullName;
import static org.wso2.carbon.identity.fraud.detection.sift.util.SiftEventUtil.resolveRemoteAddress;
import static org.wso2.carbon.identity.fraud.detection.sift.util.SiftEventUtil.resolveSessionId;
import static org.wso2.carbon.identity.fraud.detection.sift.util.SiftEventUtil.resolveUserAgent;
import static org.wso2.carbon.identity.fraud.detection.sift.util.SiftEventUtil.resolveUserClaim;
import static org.wso2.carbon.identity.fraud.detection.sift.util.SiftEventUtil.resolveUserId;
import static org.wso2.carbon.identity.fraud.detection.sift.util.SiftEventUtil.validateMobileNumberFormat;
import static org.wso2.carbon.identity.fraud.detection.sift.util.Util.setAPIKey;

public class SiftUserRegistrationEventUtil {

    public static String handlePostUserRegistrationEventPayload(FraudDetectorRequestDTO requestDTO)
            throws IdentityFraudDetectorRequestException {

        Map<String, Object> properties = requestDTO.getProperties();
        String tenantDomain = (String) properties.get(TENANT_DOMAIN);

        try {
            String validatedMobileNumber = validateMobileNumberFormat(
                    resolveUserClaim(properties, UserCoreConstants.ClaimTypeURIs.MOBILE));
            CreateAccountFieldSet fieldSet = new CreateAccountFieldSet()
                    .setUserId(resolveUserId(properties))
                    .setBrowser(new Browser().setUserAgent(resolveUserAgent()))
                    .setIp(resolveRemoteAddress())
                    .setSocialSignOnType("$other")
                    .setSessionId(resolveSessionId(properties))
                    .setUserEmail(resolveUserClaim(properties, UserCoreConstants.ClaimTypeURIs.EMAIL_ADDRESS))
                    .setPhone(validatedMobileNumber)
                    .setVerificationPhoneNumber(validatedMobileNumber)
                    .setName(resolveFullName(properties));
            fieldSet.validate();
            return setAPIKey(fieldSet, tenantDomain);
        } catch (InvalidFieldException e) {
            throw new IdentityFraudDetectorRequestException("Error while building user registration event payload: "
                    + e.getMessage(), e);
        }
    }

    public static FraudDetectorResponseDTO handlePostUserRegistrationResponse(String responseContent,
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
}
