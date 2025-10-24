package org.wso2.carbon.identity.fraud.detection.sift.util;

import com.siftscience.exception.InvalidFieldException;
import com.siftscience.model.Browser;
import com.siftscience.model.EventResponseBody;
import com.siftscience.model.VerificationFieldSet;
import java.util.Map;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.lang.StringUtils;
import org.wso2.carbon.identity.fraud.detection.sift.models.SiftFraudDetectorRequestDTO;
import org.wso2.carbon.identity.fraud.detection.sift.models.SiftFraudDetectorResponseDTO;
import org.wso2.carbon.identity.fraud.detectors.core.constant.FraudDetectorConstants;
import org.wso2.carbon.identity.fraud.detectors.core.exception.IdentityFraudDetectorRequestException;
import org.wso2.carbon.identity.fraud.detectors.core.exception.IdentityFraudDetectorResponseException;
import org.wso2.carbon.identity.fraud.detectors.core.model.FraudDetectorResponseDTO;
import org.wso2.carbon.identity.governance.service.notification.NotificationChannels;
import org.wso2.carbon.user.core.UserCoreConstants;
import static org.wso2.carbon.identity.event.IdentityEventConstants.Event.POST_USER_ACCOUNT_CONFIRMATION;
import static org.wso2.carbon.identity.event.IdentityEventConstants.EventProperty.CONFIRMATION_CODE;
import static org.wso2.carbon.identity.event.IdentityEventConstants.EventProperty.TENANT_DOMAIN;
import static org.wso2.carbon.identity.event.IdentityEventConstants.Event.TRIGGER_NOTIFICATION;
import static org.wso2.carbon.identity.event.IdentityEventConstants.EventProperty.VERIFIED_CHANNEL;
import static org.wso2.carbon.identity.fraud.detection.sift.util.SiftEventUtil.resolveRemoteAddress;
import static org.wso2.carbon.identity.fraud.detection.sift.util.SiftEventUtil.resolveUserAgent;
import static org.wso2.carbon.identity.fraud.detection.sift.util.SiftEventUtil.resolveUserClaim;
import static org.wso2.carbon.identity.fraud.detection.sift.util.SiftEventUtil.resolveUserId;
import static org.wso2.carbon.identity.fraud.detection.sift.util.SiftEventUtil.validateMobileNumberFormat;
import static org.wso2.carbon.identity.fraud.detection.sift.util.Util.setAPIKey;
import static org.wso2.carbon.identity.fraud.detectors.core.constant.FraudDetectorConstants.INTERNAL_EVENT_NAME;
import static org.wso2.carbon.identity.recovery.IdentityRecoveryConstants.EMAIL_VERIFIED_CLAIM;
import static org.wso2.carbon.identity.recovery.IdentityRecoveryConstants.NOTIFICATION_TYPE_ACCOUNT_CONFIRM;
import static org.wso2.carbon.identity.recovery.IdentityRecoveryConstants.TEMPLATE_TYPE;

public class SiftVerificationEventUtil {

    public static String handleVerificationEventPayload(SiftFraudDetectorRequestDTO requestDTO)
            throws IdentityFraudDetectorRequestException {

        Map<String, Object> properties = requestDTO.getProperties();
        String tenantDomain = (String) properties.get(TENANT_DOMAIN);

        try {
            String verifiedEvent = resolveVerifiedEvent(properties);
            String sessionId = resolveSessionId(properties);
            String verificationType = resolveVerificationType(properties);
            VerificationFieldSet fieldSet = new VerificationFieldSet()
                    .setUserId(resolveUserId(properties))
                    .setSessionId(sessionId)
                    .setStatus(resolveStatus(properties))
                    .setBrowser(new Browser().setUserAgent(resolveUserAgent()))
                    .setIp(resolveRemoteAddress())
                    .setReason(resolveReason(properties))
                    .setVerifiedEvent(verifiedEvent)
                    .setVerifiedEntityId(resolveEntityId(verifiedEvent, sessionId))
                    .setVerificationType(verificationType)
                    .setVerifiedValue(resolveVerifiedValue(verificationType, properties));;
            fieldSet.validate();
            return setAPIKey(fieldSet, tenantDomain);
        } catch (InvalidFieldException e) {
            throw new IdentityFraudDetectorRequestException("Error while building verification event payload: "
                    + e.getMessage(), e);
        }
    }

    public static FraudDetectorResponseDTO handleVerificationResponse(String responseContent,
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

    private static String resolveSessionId(Map<String, Object> properties) throws IdentityFraudDetectorRequestException {

        String internalEventName = (String) properties.get(INTERNAL_EVENT_NAME);
        if (TRIGGER_NOTIFICATION.equals(internalEventName)
                || POST_USER_ACCOUNT_CONFIRMATION.equals(internalEventName)) {

            String confirmationCode = (String) properties.get(CONFIRMATION_CODE);
            return DigestUtils.sha256Hex(confirmationCode);
        }

        throw new IdentityFraudDetectorRequestException("Cannot resolve session id for the verification event.");
    }

    private static String resolveStatus(Map<String, Object> properties) throws IdentityFraudDetectorRequestException {

        String internalEventName = (String) properties.get(INTERNAL_EVENT_NAME);
        if (TRIGGER_NOTIFICATION.equals(internalEventName)) {
            return "$pending";
        } else if (POST_USER_ACCOUNT_CONFIRMATION.equals(internalEventName)) {
            return "$success";
        }

        throw new IdentityFraudDetectorRequestException("Cannot resolve status for the verification event.");
    }

    private static String resolveVerifiedEvent(Map<String, Object> properties) {

        String internalEventName = (String) properties.get(INTERNAL_EVENT_NAME);
        if (TRIGGER_NOTIFICATION.equals(internalEventName)) {
            String templateType = (String) properties.get(TEMPLATE_TYPE);
            if (templateType.equals(NOTIFICATION_TYPE_ACCOUNT_CONFIRM)) {
                return "$create_account";
            }
        } else if (POST_USER_ACCOUNT_CONFIRMATION.equals(internalEventName)){
            return "$create_account";
        }

        return null;
    }

    private static String resolveEntityId(String verifiedEvent, String sessionId) {

        if ("$login".equals(verifiedEvent)) {
            return sessionId;
        }
        return null;
    }

    private static String resolveVerificationType(Map<String, Object> properties) {

        String internalEventName = (String) properties.get(INTERNAL_EVENT_NAME);
        if (TRIGGER_NOTIFICATION.equals(internalEventName)) {
            // This event is only triggered for email related notifications.
            return "$email";
        } else if (POST_USER_ACCOUNT_CONFIRMATION.equals(internalEventName)){
            String verifiedChannelClaim = (String) properties.get(VERIFIED_CHANNEL);
            if (EMAIL_VERIFIED_CLAIM.equals(verifiedChannelClaim)) {
                return "$email";
            } else if (NotificationChannels.SMS_CHANNEL.getVerifiedClaimUrl().equals(verifiedChannelClaim)) {
                return "$sms";
            }
        }
        return null;
    }

    private static String resolveVerifiedValue(String verificationType, Map<String, Object> properties)
            throws IdentityFraudDetectorRequestException {

        if (StringUtils.isNotEmpty(verificationType)) {
            if ("$email".equals(verificationType)) {
                return resolveUserClaim(properties, UserCoreConstants.ClaimTypeURIs.EMAIL_ADDRESS);
            } else if ("$sms".equals(verificationType)) {
                return validateMobileNumberFormat(resolveUserClaim(properties, UserCoreConstants.ClaimTypeURIs.MOBILE));
            }
        }
        return null;
    }

    private static String resolveReason(Map<String, Object> properties) {

        String internalEventName = (String) properties.get(INTERNAL_EVENT_NAME);
        if (TRIGGER_NOTIFICATION.equals(internalEventName)
                || POST_USER_ACCOUNT_CONFIRMATION.equals(internalEventName)) {
            return "$manual_review";
        }
        return null;
    }

}
