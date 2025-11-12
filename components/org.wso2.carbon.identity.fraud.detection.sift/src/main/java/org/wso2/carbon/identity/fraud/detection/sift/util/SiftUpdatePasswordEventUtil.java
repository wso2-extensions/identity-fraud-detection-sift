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
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.fraud.detection.core.constant.FraudDetectionConstants;
import org.wso2.carbon.identity.fraud.detection.core.exception.IdentityFraudDetectionRequestException;
import org.wso2.carbon.identity.fraud.detection.core.exception.IdentityFraudDetectionResponseException;
import org.wso2.carbon.identity.fraud.detection.core.model.FraudDetectorResponseDTO;
import org.wso2.carbon.identity.fraud.detection.sift.models.SiftFraudDetectorRequestDTO;
import org.wso2.carbon.identity.fraud.detection.sift.models.SiftFraudDetectorResponseDTO;
import org.wso2.carbon.identity.recovery.IdentityRecoveryClientException;
import org.wso2.carbon.identity.recovery.RecoveryScenarios;
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
import static org.wso2.carbon.identity.fraud.detection.core.constant.FraudDetectionConstants.FraudDetectionEvents.POST_UPDATE_PASSWORD;
import static org.wso2.carbon.identity.fraud.detection.core.constant.FraudDetectionConstants.INTERNAL_EVENT_NAME;
import static org.wso2.carbon.identity.fraud.detection.sift.Constants.ACTION_PERFORMED_BY_ADMIN;
import static org.wso2.carbon.identity.fraud.detection.sift.Constants.PasswordUpdateReason.FORCED_RESET;
import static org.wso2.carbon.identity.fraud.detection.sift.Constants.PasswordUpdateReason.FORGOT_PASSWORD;
import static org.wso2.carbon.identity.fraud.detection.sift.Constants.PasswordUpdateReason.USER_UPDATE;
import static org.wso2.carbon.identity.fraud.detection.sift.Constants.ProgressStatus.PENDING;
import static org.wso2.carbon.identity.fraud.detection.sift.Constants.ProgressStatus.SUCCESS;
import static org.wso2.carbon.identity.fraud.detection.sift.Constants.USER_UUID;
import static org.wso2.carbon.identity.fraud.detection.sift.util.SiftEventUtil.resolveRemoteAddress;
import static org.wso2.carbon.identity.fraud.detection.sift.util.SiftEventUtil.resolveUserAgent;
import static org.wso2.carbon.identity.fraud.detection.sift.util.SiftEventUtil.resolveUserAttribute;
import static org.wso2.carbon.identity.fraud.detection.sift.util.SiftEventUtil.resolveUserId;
import static org.wso2.carbon.identity.fraud.detection.sift.util.SiftEventUtil.resolveUserUUID;
import static org.wso2.carbon.identity.fraud.detection.sift.util.SiftEventUtil.validateMobileNumberFormat;
import static org.wso2.carbon.identity.fraud.detection.sift.util.Util.setAPIKey;
import static org.wso2.carbon.identity.recovery.RecoveryScenarios.ADMIN_FORCED_PASSWORD_RESET_VIA_EMAIL_LINK;
import static org.wso2.carbon.identity.recovery.RecoveryScenarios.ADMIN_FORCED_PASSWORD_RESET_VIA_OTP;
import static org.wso2.carbon.identity.recovery.RecoveryScenarios.ASK_PASSWORD;
import static org.wso2.carbon.identity.recovery.RecoveryScenarios.NOTIFICATION_BASED_PW_RECOVERY;

/**
 * Utility class for handling Sift update password events.
 */
public class SiftUpdatePasswordEventUtil {

    private static final Log LOG = LogFactory.getLog(SiftUpdatePasswordEventUtil.class);

    /**
     * Builds the update password event payload for Sift.
     *
     * @param requestDTO Sift fraud detector request DTO.
     * @return JSON string of the update password event payload.
     * @throws IdentityFraudDetectionRequestException if an error occurs while building the payload.
     */
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
                            resolveUserAttribute(properties, UserCoreConstants.ClaimTypeURIs.MOBILE)))
                    .setCustomField(USER_UUID, resolveUserUUID(properties));
            setCustomFields(properties, fieldSet);
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
            throw new IdentityFraudDetectionResponseException("Error occurred while publishing event to Sift. Returned"
                    + " Sift status code: " + responseBody.getStatus() + " for event: " + eventName.name());
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
                return FORCED_RESET.getValue();
            } else if (ADMIN_FORCED_PASSWORD_RESET_VIA_EMAIL_LINK.name().equals(recoveryScenario)
                    || ADMIN_FORCED_PASSWORD_RESET_VIA_OTP.name().equals(recoveryScenario)) {
                // Admin forced password reset via email link scenario and user set the password successfully.
                return FORCED_RESET.getValue();
            } else if (NOTIFICATION_BASED_PW_RECOVERY.name().equals(recoveryScenario)) {
                // This is a forgot password scenario where user initiates the password reset flow.
                return FORGOT_PASSWORD.getValue();
            }

            // This section covers the post password update scenarios came through POST_UPDATE_CREDENTIAL_BY_SCIM
            // internal event.
            String scenario = (String) requestDTO.getProperties().get(SCENARIO);
            if (POST_CREDENTIAL_UPDATE_BY_ADMIN.equals(scenario)) {
                // Admin forcefully updates the password of the user.
                return FORCED_RESET.getValue();
            } else if (POST_CREDENTIAL_UPDATE_BY_USER.equals(scenario)) {
                // User updates their own password.
                return USER_UPDATE.getValue();
            }
        }

        // This section covers the password update notification scenarios.
        String internalEventName = (String) requestDTO.getProperties().get(INTERNAL_EVENT_NAME);
        if (POST_ADD_USER_WITH_ASK_PASSWORD.equals(internalEventName)
                || POST_FORCE_PASSWORD_RESET_BY_ADMIN.equals(internalEventName)) {
            return FORCED_RESET.getValue();
        } else if (POST_SEND_RECOVERY_NOTIFICATION.equals(internalEventName)) {
            return FORGOT_PASSWORD.getValue();
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

        Map<String, Object> properties = requestDTO.getProperties();

        if (POST_UPDATE_PASSWORD.equals(requestDTO.getEventName())) {

            String recoveryScenario = properties.containsKey(RECOVERY_SCENARIO) ?
                    (String) properties.get(RECOVERY_SCENARIO) : null;
            if (StringUtils.isNotEmpty(recoveryScenario)) {
                try {
                    RecoveryScenarios scenarioEnum = RecoveryScenarios.getRecoveryScenario(recoveryScenario);
                    switch (scenarioEnum) {
                        case ASK_PASSWORD:
                        case ADMIN_FORCED_PASSWORD_RESET_VIA_EMAIL_LINK:
                        case ADMIN_FORCED_PASSWORD_RESET_VIA_OTP:
                        case NOTIFICATION_BASED_PW_RECOVERY:
                            return SUCCESS.getValue();
                        default:
                            break;
                    }
                } catch (IdentityRecoveryClientException e) {
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("Invalid recovery scenario: " + recoveryScenario, e);
                    }
                }
            }

            String scenario = properties.containsKey(SCENARIO) ? (String) properties.get(SCENARIO) : null;
            if (StringUtils.isNotEmpty(scenario)) {
                switch (scenario) {
                    case POST_CREDENTIAL_UPDATE_BY_ADMIN:
                    case POST_CREDENTIAL_UPDATE_BY_USER:
                        return SUCCESS.getValue();
                    default:
                        break;
                }
            }
        }

        String internalEventName = properties.containsKey(INTERNAL_EVENT_NAME) ?
                (String) properties.get(INTERNAL_EVENT_NAME) : null;
        if (StringUtils.isNotEmpty(internalEventName)) {
            switch (internalEventName) {
                case POST_ADD_USER_WITH_ASK_PASSWORD:
                case POST_FORCE_PASSWORD_RESET_BY_ADMIN:
                case POST_SEND_RECOVERY_NOTIFICATION:
                    return PENDING.getValue();
                default:
                    break;
            }
        }

        throw new IdentityFraudDetectionRequestException("Cannot resolve status for update credential event.");
    }

    /**
     * Sets custom fields for the update password event.
     *
     * @param properties Event properties map.
     * @param fieldSet   Update password field set.
     */
    public static void setCustomFields(Map<String, Object> properties, UpdatePasswordFieldSet fieldSet) {

        String scenario = properties.containsKey(SCENARIO) ? (String) properties.get(SCENARIO) : StringUtils.EMPTY;
        String reason = fieldSet.getReason();
        String status = fieldSet.getStatus();
        boolean isActionPerformedByAdmin = false;

        if (PENDING.getValue().equals(status)) {
            if (FORCED_RESET.getValue().equals(reason)) {
                isActionPerformedByAdmin = true;
            }
        } else if (SUCCESS.getValue().equals(reason)) {
            if (FORCED_RESET.getValue().equals(reason) && POST_CREDENTIAL_UPDATE_BY_ADMIN.equals(scenario)) {
                isActionPerformedByAdmin = true;
            }
        }

        fieldSet.setCustomField(ACTION_PERFORMED_BY_ADMIN, isActionPerformedByAdmin);
    }
}
