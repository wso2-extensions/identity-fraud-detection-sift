/*
 * Copyright (c) 2025, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.wso2.carbon.identity.fraud.detection.sift.util;

import com.siftscience.exception.InvalidFieldException;
import com.siftscience.model.Browser;
import com.siftscience.model.EventResponseBody;
import com.siftscience.model.UpdatePasswordFieldSet;
import org.wso2.carbon.identity.fraud.detection.sift.models.SiftFraudDetectorRequestDTO;
import org.wso2.carbon.identity.fraud.detection.sift.models.SiftFraudDetectorResponseDTO;
import org.wso2.carbon.identity.fraud.detection.core.constant.FraudDetectionConstants;
import org.wso2.carbon.identity.fraud.detection.core.exception.IdentityFraudDetectionRequestException;
import org.wso2.carbon.identity.fraud.detection.core.exception.IdentityFraudDetectionResponseException;
import org.wso2.carbon.identity.fraud.detection.core.model.FraudDetectorResponseDTO;
import org.wso2.carbon.user.core.UserCoreConstants;

import java.util.Map;

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
import static org.wso2.carbon.identity.fraud.detection.sift.util.SiftEventUtil.resolveUserAttribute;
import static org.wso2.carbon.identity.fraud.detection.sift.util.SiftEventUtil.resolveUserId;
import static org.wso2.carbon.identity.fraud.detection.sift.util.SiftEventUtil.validateMobileNumberFormat;
import static org.wso2.carbon.identity.fraud.detection.sift.util.Util.setAPIKey;
import static org.wso2.carbon.identity.fraud.detection.core.constant.FraudDetectionConstants.FraudDetectionEvents.POST_UPDATE_PASSWORD;
import static org.wso2.carbon.identity.fraud.detection.core.constant.FraudDetectionConstants.INTERNAL_EVENT_NAME;
import static org.wso2.carbon.identity.recovery.RecoveryScenarios.ADMIN_FORCED_PASSWORD_RESET_VIA_EMAIL_LINK;
import static org.wso2.carbon.identity.recovery.RecoveryScenarios.ADMIN_FORCED_PASSWORD_RESET_VIA_OTP;
import static org.wso2.carbon.identity.recovery.RecoveryScenarios.ASK_PASSWORD;
import static org.wso2.carbon.identity.recovery.RecoveryScenarios.NOTIFICATION_BASED_PW_RECOVERY;
import static org.wso2.carbon.identity.recovery.RecoveryScenarios.NOTIFICATION_BASED_PW_RECOVERY_OFFLINE_INVITE;

/**
 * Utility class for handling Sift update password events.
 */
public class SiftUpdatePasswordEventUtil {

    public static String handleUpdatePasswordEventPayload(SiftFraudDetectorRequestDTO requestDTO)
            throws IdentityFraudDetectionRequestException {

        Map<String, Object> properties = requestDTO.getProperties();
        String tenantDomain = (String) properties.get(TENANT_DOMAIN);

        try {
            UpdatePasswordFieldSet fieldSet = new UpdatePasswordFieldSet()
                    .setUserId(resolveUserId(properties))
                    .setReason(resolveReason(requestDTO))
                    .setStatus(resolveStatus(requestDTO))
                    .setBrowser(new Browser().setUserAgent(resolveUserAgent(properties)))
                    .setIp(resolveRemoteAddress(properties))
                    .setUserEmail(resolveUserAttribute(properties, UserCoreConstants.ClaimTypeURIs.EMAIL_ADDRESS))
                    .setVerificationPhoneNumber(validateMobileNumberFormat(
                            resolveUserAttribute(properties, UserCoreConstants.ClaimTypeURIs.MOBILE)));
            fieldSet.validate();
            return setAPIKey(fieldSet, tenantDomain);
        } catch (InvalidFieldException e) {
            throw new IdentityFraudDetectionRequestException("Error while building update credential event payload: "
                    + e.getMessage(), e);
        }
    }

    /**
     * Handles the update password event response from Sift.
     *
     * @param responseContent JSON string of the response content from Sift.
     * @param requestDTO      Sift fraud detector request DTO.
     * @return Sift fraud detector response DTO.
     * @throws IdentityFraudDetectionResponseException if an error occurs while handling the response.
     */
    public static FraudDetectorResponseDTO handleUpdatePasswordResponse(String responseContent,
                                                                        SiftFraudDetectorRequestDTO requestDTO)
            throws IdentityFraudDetectionResponseException {

        EventResponseBody responseBody = EventResponseBody.fromJson(responseContent);
        FraudDetectionConstants.FraudDetectionEvents eventName = requestDTO.getEventName();
        if (responseBody.getStatus() != 0) {
            throw new IdentityFraudDetectionResponseException("Error occurred while publishing event to Sift. Returned" +
                    "Sift status code: " + responseBody.getStatus() + " for event: " + eventName.name());
        }
        return new SiftFraudDetectorResponseDTO(FraudDetectionConstants.ExecutionStatus.SUCCESS, eventName);
    }

    /**
     * Resolves the reason for the update credential event.
     *
     * @param requestDTO Sift fraud detector request DTO.
     * @return Resolved reason.
     * @throws IdentityFraudDetectionRequestException if an error occurs while resolving the reason.
     */
    private static String resolveReason(SiftFraudDetectorRequestDTO requestDTO)
            throws IdentityFraudDetectionRequestException {

        if (POST_UPDATE_PASSWORD.equals(requestDTO.getEventName())) {

            // This section covers the post password update scenarios came through POST_ADD_NEW_PASSWORD internal event.
            String recoveryScenario = (String) requestDTO.getProperties().get(RECOVERY_SCENARIO);
            if (ASK_PASSWORD.name().equals(recoveryScenario)) {
                // Ask password flow where admin created the user and user set the password successfully.
                return "$forced_reset";
            } else if (NOTIFICATION_BASED_PW_RECOVERY_OFFLINE_INVITE.name().equals(recoveryScenario)) {
                // Offline invite link scenario where admin created the user and user set the password successfully.
                return "$forced_reset";
            } else if (ADMIN_FORCED_PASSWORD_RESET_VIA_EMAIL_LINK.name().equals(recoveryScenario)
                    || ADMIN_FORCED_PASSWORD_RESET_VIA_OTP.name().equals(recoveryScenario)) {
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
            return "$forgot_password";
        }

        throw new IdentityFraudDetectionRequestException("Cannot resolve reason for update credential event.");
    }

    /**
     * Resolves the reason for the update credential event.
     *
     * @param requestDTO Sift fraud detector request DTO.
     * @return Resolved reason.
     * @throws IdentityFraudDetectionRequestException if an error occurs while resolving the reason.
     */
    private static String resolveStatus(SiftFraudDetectorRequestDTO requestDTO)
            throws IdentityFraudDetectionRequestException {

        if (POST_UPDATE_PASSWORD.equals(requestDTO.getEventName())) {

            // This section covers the post password update scenarios.
            String recoveryScenario = (String) requestDTO.getProperties().get(RECOVERY_SCENARIO);
            if (ASK_PASSWORD.name().equals(recoveryScenario)) {
                // Ask password flow where admin created the user and user set the password successfully.
                return "$success";
            } else if (NOTIFICATION_BASED_PW_RECOVERY_OFFLINE_INVITE.name().equals(recoveryScenario)) {
                // Offline invite link scenario where admin created the user and user set the password successfully.
                return "$success";
            } else if (ADMIN_FORCED_PASSWORD_RESET_VIA_EMAIL_LINK.name().equals(recoveryScenario)
                    || ADMIN_FORCED_PASSWORD_RESET_VIA_OTP.name().equals(recoveryScenario)) {
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

        throw new IdentityFraudDetectionRequestException("Cannot resolve status for update credential event.");
    }

    // TODO: Check if the admin actions has to be marked differently.
}
