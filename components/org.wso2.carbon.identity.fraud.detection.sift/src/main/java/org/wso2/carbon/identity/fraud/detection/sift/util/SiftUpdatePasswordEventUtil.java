package org.wso2.carbon.identity.fraud.detection.sift.util;

import com.siftscience.exception.InvalidFieldException;
import com.siftscience.model.Browser;
import com.siftscience.model.EventResponseBody;
import com.siftscience.model.UpdatePasswordFieldSet;
import org.wso2.carbon.identity.fraud.detection.sift.models.SiftFraudDetectorRequestDTO;
import org.wso2.carbon.identity.fraud.detection.sift.models.SiftFraudDetectorResponseDTO;
import org.wso2.carbon.identity.fraud.detectors.core.constant.FraudDetectorConstants;
import org.wso2.carbon.identity.fraud.detectors.core.exception.IdentityFraudDetectorRequestException;
import org.wso2.carbon.identity.fraud.detectors.core.exception.IdentityFraudDetectorResponseException;
import org.wso2.carbon.identity.fraud.detectors.core.model.FraudDetectorResponseDTO;

import java.util.Map;
import org.wso2.carbon.user.core.UserCoreConstants;

import static org.wso2.carbon.identity.event.IdentityEventConstants.Event.POST_ADD_USER_WITH_ASK_PASSWORD;
import static org.wso2.carbon.identity.event.IdentityEventConstants.Event.POST_FORCE_PASSWORD_RESET_BY_ADMIN;
import static org.wso2.carbon.identity.event.IdentityEventConstants.Event.POST_SEND_RECOVERY_NOTIFICATION;
import static org.wso2.carbon.identity.event.IdentityEventConstants.EventProperty.RECOVERY_SCENARIO;
import static org.wso2.carbon.identity.event.IdentityEventConstants.EventProperty.SCENARIO;
import static org.wso2.carbon.identity.event.IdentityEventConstants.EventProperty.Scenario.ScenarioTypes.POST_CREDENTIAL_UPDATE_BY_ADMIN;
import static org.wso2.carbon.identity.event.IdentityEventConstants.EventProperty.Scenario.ScenarioTypes.POST_CREDENTIAL_UPDATE_BY_USER;
import static org.wso2.carbon.identity.event.IdentityEventConstants.EventProperty.TENANT_DOMAIN;
import static org.wso2.carbon.identity.fraud.detection.sift.util.SiftEventUtil.resolveRemoteAddress;
import static org.wso2.carbon.identity.fraud.detection.sift.util.SiftEventUtil.resolveUserAgent;
import static org.wso2.carbon.identity.fraud.detection.sift.util.SiftEventUtil.resolveUserClaim;
import static org.wso2.carbon.identity.fraud.detection.sift.util.SiftEventUtil.resolveUserId;
import static org.wso2.carbon.identity.fraud.detection.sift.util.SiftEventUtil.validateMobileNumberFormat;
import static org.wso2.carbon.identity.fraud.detection.sift.util.Util.setAPIKey;
import static org.wso2.carbon.identity.fraud.detectors.core.constant.FraudDetectorConstants.INTERNAL_EVENT_NAME;
import static org.wso2.carbon.identity.fraud.detectors.core.constant.FraudDetectorConstants.FraudDetectionEvents.POST_UPDATE_PASSWORD;
import static org.wso2.carbon.identity.recovery.RecoveryScenarios.ADMIN_FORCED_PASSWORD_RESET_VIA_EMAIL_LINK;
import static org.wso2.carbon.identity.recovery.RecoveryScenarios.ASK_PASSWORD;
import static org.wso2.carbon.identity.recovery.RecoveryScenarios.NOTIFICATION_BASED_PW_RECOVERY;
import static org.wso2.carbon.identity.recovery.RecoveryScenarios.NOTIFICATION_BASED_PW_RECOVERY_OFFLINE_INVITE;

public class SiftUpdatePasswordEventUtil {

    public static String handleUpdatePasswordEventPayload(SiftFraudDetectorRequestDTO requestDTO)
            throws IdentityFraudDetectorRequestException {

        Map<String, Object> properties = requestDTO.getProperties();
        String tenantDomain = (String) properties.get(TENANT_DOMAIN);

        try {
            UpdatePasswordFieldSet fieldSet = new UpdatePasswordFieldSet()
                    .setUserId(resolveUserId(properties))
                    .setReason(resolveReason(requestDTO))
                    .setStatus(resolveStatus(requestDTO))
                    .setBrowser(new Browser().setUserAgent(resolveUserAgent()))
                    .setIp(resolveRemoteAddress())
                    .setUserEmail(resolveUserClaim(properties, UserCoreConstants.ClaimTypeURIs.EMAIL_ADDRESS))
                    .setVerificationPhoneNumber(validateMobileNumberFormat(
                            resolveUserClaim(properties, UserCoreConstants.ClaimTypeURIs.MOBILE)));
            fieldSet.validate();
            return setAPIKey(fieldSet, tenantDomain);
        } catch (InvalidFieldException e) {
            throw new IdentityFraudDetectorRequestException("Error while building update credential event payload: "
                    + e.getMessage(), e);
        }
    }

    public static FraudDetectorResponseDTO handleUpdatePasswordResponse(String responseContent,
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

    private static String resolveReason(SiftFraudDetectorRequestDTO requestDTO)
            throws IdentityFraudDetectorRequestException {

        if (POST_UPDATE_PASSWORD.equals(requestDTO.getEventName())) {

            // This section covers the post password update scenarios came through POST_ADD_NEW_PASSWORD internal event.
            String recoveryScenario = (String) requestDTO.getProperties().get(RECOVERY_SCENARIO);
            if (ASK_PASSWORD.name().equals(recoveryScenario)) {
                // Ask password flow where admin created the user and user set the password successfully.
                return "$forced_reset";
            } else if (NOTIFICATION_BASED_PW_RECOVERY_OFFLINE_INVITE.name().equals(recoveryScenario)) {
                // Offline invite link scenario where admin created the user and user set the password successfully.
                return "$forced_reset";
            } else if (ADMIN_FORCED_PASSWORD_RESET_VIA_EMAIL_LINK.name().equals(recoveryScenario)) {
                // TODO: Check for OTP based flow too.
                // Admin forced password reset via email link scenario and user set the password successfully.
                return "$forced_reset";
            } else if (NOTIFICATION_BASED_PW_RECOVERY.name().equals(recoveryScenario)) {
                // This is a forgot password scenario where user initiates the password reset flow.
                return "$forgot_password";
            }

            // This section covers the post password update scenarios came through POST_UPDATE_CREDENTIAL_BY_SCIM
            // internal event.
            String scenario = (String) requestDTO.getProperties().get(SCENARIO);
            if (POST_CREDENTIAL_UPDATE_BY_ADMIN.equals(scenario)) {
                // Admin forcefully updates the password of the user.
                return "$forced_reset";
            } else if (POST_CREDENTIAL_UPDATE_BY_USER.equals(scenario)) {
                // User updates their own password.
                return "$user_update";
            }
        }

        // This section covers the password update notification scenarios.
        String internalEventName = (String) requestDTO.getProperties().get(INTERNAL_EVENT_NAME);
        if (POST_ADD_USER_WITH_ASK_PASSWORD.equals(internalEventName)
                || POST_FORCE_PASSWORD_RESET_BY_ADMIN.equals(internalEventName)) {
            return "$forced_reset";
        } else if (POST_SEND_RECOVERY_NOTIFICATION.equals(internalEventName)) {
            // TODO: This should be "$forgot_password". Please check.
            return "$user_update";
        }

        throw new IdentityFraudDetectorRequestException("Cannot resolve reason for update credential event.");
    }

    private static String resolveStatus(SiftFraudDetectorRequestDTO requestDTO)
            throws IdentityFraudDetectorRequestException {

        if (POST_UPDATE_PASSWORD.equals(requestDTO.getEventName())) {

            // This section covers the post password update scenarios.
            String recoveryScenario = (String) requestDTO.getProperties().get(RECOVERY_SCENARIO);
            if (ASK_PASSWORD.name().equals(recoveryScenario)) {
                // Ask password flow where admin created the user and user set the password successfully.
                return "$success";
            } else if (NOTIFICATION_BASED_PW_RECOVERY_OFFLINE_INVITE.name().equals(recoveryScenario)) {
                // Offline invite link scenario where admin created the user and user set the password successfully.
                return "$success";
            } else if (ADMIN_FORCED_PASSWORD_RESET_VIA_EMAIL_LINK.name().equals(recoveryScenario)) {
                // TODO: Check for OTP based flow too.
                // Admin forced password reset via email link scenario and user set the password successfully.
                return "$success";
            } else if (NOTIFICATION_BASED_PW_RECOVERY.name().equals(recoveryScenario)) {
                // This is a forgot password scenario where user initiates the password reset flow.
                return "$success";
            }

            String scenario = (String) requestDTO.getProperties().get(SCENARIO);
            if (POST_CREDENTIAL_UPDATE_BY_ADMIN.equals(scenario)) {
                // Admin forcefully updates the password of the user.
                return "$success";
            } else if (POST_CREDENTIAL_UPDATE_BY_USER.equals(scenario)) {
                // User updates their own password.
                return "$success";
            }
        }

        // This section covers the password update notification scenarios.
        String internalEventName = (String) requestDTO.getProperties().get(INTERNAL_EVENT_NAME);
        if (POST_ADD_USER_WITH_ASK_PASSWORD.equals(internalEventName)
                || POST_FORCE_PASSWORD_RESET_BY_ADMIN.equals(internalEventName)
                || POST_SEND_RECOVERY_NOTIFICATION.equals(internalEventName)) {
            return "$pending";
        }

        throw new IdentityFraudDetectorRequestException("Cannot resolve status for update credential event.");
    }

    private static boolean isAdminInitiated(SiftFraudDetectorRequestDTO requestDTO) {

        String internalEventName = (String) requestDTO.getProperties().get(INTERNAL_EVENT_NAME);
        if (POST_ADD_USER_WITH_ASK_PASSWORD.equals(internalEventName)) {
            return true;
        }

        String recoveryScenario = (String) requestDTO.getProperties().get(RECOVERY_SCENARIO);
        if (POST_UPDATE_PASSWORD.equals(requestDTO.getEventName())) {

            if (ASK_PASSWORD.name().equals(recoveryScenario)) {
                return true;
            } else if (NOTIFICATION_BASED_PW_RECOVERY.name().equals(recoveryScenario)) {
                return true;
            }
        }

        return false;
    }
}
