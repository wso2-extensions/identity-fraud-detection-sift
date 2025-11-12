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
import com.siftscience.model.VerificationFieldSet;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.lang.StringUtils;
import org.wso2.carbon.identity.fraud.detection.core.constant.FraudDetectionConstants;
import org.wso2.carbon.identity.fraud.detection.core.exception.IdentityFraudDetectionRequestException;
import org.wso2.carbon.identity.fraud.detection.core.exception.IdentityFraudDetectionResponseException;
import org.wso2.carbon.identity.fraud.detection.core.model.FraudDetectorResponseDTO;
import org.wso2.carbon.identity.fraud.detection.sift.Constants;
import org.wso2.carbon.identity.fraud.detection.sift.models.SiftFraudDetectorRequestDTO;
import org.wso2.carbon.identity.fraud.detection.sift.models.SiftFraudDetectorResponseDTO;
import org.wso2.carbon.identity.governance.service.notification.NotificationChannels;
import org.wso2.carbon.user.core.UserCoreConstants;

import java.util.Map;

import static org.wso2.carbon.identity.event.IdentityEventConstants.Event.POST_GENERATE_EMAIL_OTP;
import static org.wso2.carbon.identity.event.IdentityEventConstants.Event.POST_GENERATE_SMS_OTP;
import static org.wso2.carbon.identity.event.IdentityEventConstants.Event.POST_USER_ACCOUNT_CONFIRMATION;
import static org.wso2.carbon.identity.event.IdentityEventConstants.Event.POST_VALIDATE_EMAIL_OTP;
import static org.wso2.carbon.identity.event.IdentityEventConstants.Event.POST_VALIDATE_SMS_OTP;
import static org.wso2.carbon.identity.event.IdentityEventConstants.Event.TRIGGER_NOTIFICATION;
import static org.wso2.carbon.identity.event.IdentityEventConstants.EventProperty.CONFIRMATION_CODE;
import static org.wso2.carbon.identity.event.IdentityEventConstants.EventProperty.CORRELATION_ID;
import static org.wso2.carbon.identity.event.IdentityEventConstants.EventProperty.OTP_STATUS;
import static org.wso2.carbon.identity.event.IdentityEventConstants.EventProperty.RECOVERY_SCENARIO;
import static org.wso2.carbon.identity.event.IdentityEventConstants.EventProperty.TENANT_DOMAIN;
import static org.wso2.carbon.identity.event.IdentityEventConstants.EventProperty.VERIFIED_BY_END_USER;
import static org.wso2.carbon.identity.event.IdentityEventConstants.EventProperty.VERIFIED_CHANNEL;
import static org.wso2.carbon.identity.event.IdentityEventConstants.EventProperty.VERIFIED_EMAIL;
import static org.wso2.carbon.identity.event.IdentityEventConstants.EventProperty.VERIFIED_MOBILE;
import static org.wso2.carbon.identity.fraud.detection.core.constant.FraudDetectionConstants.FraudDetectionEvents.AUTHENTICATION_STEP_NOTIFICATION_VERIFICATION;
import static org.wso2.carbon.identity.fraud.detection.core.constant.FraudDetectionConstants.FraudDetectionEvents.POST_SELF_REGISTRATION_VERIFICATION;
import static org.wso2.carbon.identity.fraud.detection.core.constant.FraudDetectionConstants.FraudDetectionEvents.POST_USER_ATTRIBUTE_UPDATE_VERIFICATION;
import static org.wso2.carbon.identity.fraud.detection.core.constant.FraudDetectionConstants.FraudDetectionEvents.SELF_REGISTRATION_VERIFICATION_NOTIFICATION;
import static org.wso2.carbon.identity.fraud.detection.core.constant.FraudDetectionConstants.FraudDetectionEvents.USER_ATTRIBUTE_UPDATE_VERIFICATION_NOTIFICATION;
import static org.wso2.carbon.identity.fraud.detection.core.constant.FraudDetectionConstants.INTERNAL_EVENT_NAME;
import static org.wso2.carbon.identity.fraud.detection.sift.Constants.EMAIL_KEY;
import static org.wso2.carbon.identity.fraud.detection.sift.Constants.MANUAL_REVIEW_VERIFICATION_TYPE;
import static org.wso2.carbon.identity.fraud.detection.sift.Constants.ProgressStatus.FAILURE;
import static org.wso2.carbon.identity.fraud.detection.sift.Constants.ProgressStatus.PENDING;
import static org.wso2.carbon.identity.fraud.detection.sift.Constants.ProgressStatus.SUCCESS;
import static org.wso2.carbon.identity.fraud.detection.sift.Constants.SMS_KEY;
import static org.wso2.carbon.identity.fraud.detection.sift.Constants.SiftEventType.PROFILE_UPDATE;
import static org.wso2.carbon.identity.fraud.detection.sift.Constants.SiftEventType.USER_LOGIN;
import static org.wso2.carbon.identity.fraud.detection.sift.Constants.SiftEventType.USER_REGISTRATION;
import static org.wso2.carbon.identity.fraud.detection.sift.Constants.USER_UUID;
import static org.wso2.carbon.identity.fraud.detection.sift.util.SiftEventUtil.resolveRemoteAddress;
import static org.wso2.carbon.identity.fraud.detection.sift.util.SiftEventUtil.resolveUserAgent;
import static org.wso2.carbon.identity.fraud.detection.sift.util.SiftEventUtil.resolveUserAttribute;
import static org.wso2.carbon.identity.fraud.detection.sift.util.SiftEventUtil.resolveUserId;
import static org.wso2.carbon.identity.fraud.detection.sift.util.SiftEventUtil.resolveUserUUID;
import static org.wso2.carbon.identity.fraud.detection.sift.util.SiftEventUtil.validateMobileNumberFormat;
import static org.wso2.carbon.identity.fraud.detection.sift.util.Util.setAPIKey;
import static org.wso2.carbon.identity.recovery.IdentityRecoveryConstants.EMAIL_VERIFIED_CLAIM;
import static org.wso2.carbon.identity.recovery.IdentityRecoveryConstants.NOTIFICATION_TYPE_ACCOUNT_CONFIRM;
import static org.wso2.carbon.identity.recovery.IdentityRecoveryConstants.SEND_TO;
import static org.wso2.carbon.identity.recovery.IdentityRecoveryConstants.TEMPLATE_TYPE;
import static org.wso2.carbon.identity.recovery.RecoveryScenarios.EMAIL_VERIFICATION_ON_UPDATE;
import static org.wso2.carbon.identity.recovery.RecoveryScenarios.MOBILE_VERIFICATION_ON_UPDATE;

/**
 * Utility class for handling Sift verification events.
 */
public class SiftVerificationEventUtil {

    /**
     * Builds the verification event payload for Sift.
     *
     * @param requestDTO Sift fraud detector request DTO.
     * @return JSON string of the verification event payload.
     * @throws IdentityFraudDetectionRequestException if an error occurs while building the payload.
     */
    public static String handleVerificationEventPayload(SiftFraudDetectorRequestDTO requestDTO)
            throws IdentityFraudDetectionRequestException {

        Map<String, Object> properties = requestDTO.getProperties();
        FraudDetectionConstants.FraudDetectionEvents event = requestDTO.getEventName();
        String tenantDomain = (String) properties.get(TENANT_DOMAIN);

        try {
            String verifiedEvent = resolveVerifiedEvent(event, properties);
            String sessionId = resolveSessionId(event, properties);
            String verificationType = resolveVerificationType(event, properties);
            VerificationFieldSet fieldSet = new VerificationFieldSet()
                    .setUserId(resolveUserId(properties))
                    .setSessionId(sessionId)
                    .setStatus(resolveStatus(event, properties))
                    .setBrowser(new Browser().setUserAgent(resolveUserAgent(properties)))
                    .setIp(resolveRemoteAddress(properties))
                    .setReason(resolveReason(event))
                    .setVerifiedEvent(verifiedEvent)
                    .setVerifiedEntityId(resolveEntityId(verifiedEvent, sessionId))
                    .setVerificationType(verificationType)
                    .setVerifiedValue(resolveVerifiedValue(verificationType, event, properties))
                    .setCustomField(USER_UUID, resolveUserUUID(properties));
            setCustomFields(event, fieldSet, properties);
            fieldSet.validate();
            return setAPIKey(fieldSet, tenantDomain);
        } catch (InvalidFieldException e) {
            throw new IdentityFraudDetectionRequestException("Error while building verification event payload: "
                    + e.getMessage(), e);
        }
    }

    /**
     * Handles the verification event response from Sift.
     *
     * @param responseContent JSON string of the response content from Sift.
     * @param requestDTO      Sift fraud detector request DTO.
     * @return Sift fraud detector response DTO.
     * @throws IdentityFraudDetectionResponseException if an error occurs while handling the response.
     */
    public static FraudDetectorResponseDTO handleVerificationResponse(String responseContent,
                                                                      SiftFraudDetectorRequestDTO requestDTO)
            throws IdentityFraudDetectionResponseException {

        EventResponseBody responseBody = EventResponseBody.fromJson(responseContent);
        FraudDetectionConstants.FraudDetectionEvents eventName = requestDTO.getEventName();
        if (responseBody.getStatus() != 0) {
            throw new IdentityFraudDetectionResponseException("Error occurred while publishing event to Sift. Returned "
                    + "Sift status code: " + responseBody.getStatus() + " for event: " + eventName.name());
        }
        return new SiftFraudDetectorResponseDTO(FraudDetectionConstants.ExecutionStatus.SUCCESS, eventName);
    }

    /**
     * Resolves the session ID for the verification event.
     *
     * @param event      Fraud detection event.
     * @param properties Map of event properties.
     * @return Resolved session ID.
     * @throws IdentityFraudDetectionRequestException if an error occurs while resolving the session ID.
     */
    private static String resolveSessionId(FraudDetectionConstants.FraudDetectionEvents event,
                                           Map<String, Object> properties)
            throws IdentityFraudDetectionRequestException {

        if (isAttributeUpdateVerificationEvent(event)) {

            String recoveryScenario = (String) properties.get(RECOVERY_SCENARIO);
            if (EMAIL_VERIFICATION_ON_UPDATE.name().equals(recoveryScenario)
                    || MOBILE_VERIFICATION_ON_UPDATE.name().equals(recoveryScenario)) {
                String confirmationCode = (String) properties.get(CONFIRMATION_CODE);
                return DigestUtils.sha256Hex(confirmationCode);
            }
            throw new IdentityFraudDetectionRequestException("Cannot resolve session id for the attribute update " +
                    "verification event.");

        } else if (isSelfRegistrationVerificationEvent(event)) {

            String internalEventName = (String) properties.get(INTERNAL_EVENT_NAME);
            if (TRIGGER_NOTIFICATION.equals(internalEventName)
                    || POST_USER_ACCOUNT_CONFIRMATION.equals(internalEventName)) {
                String confirmationCode = (String) properties.get(CONFIRMATION_CODE);
                return DigestUtils.sha256Hex(confirmationCode);
            }
            throw new IdentityFraudDetectionRequestException("Cannot resolve session id for the self registration " +
                    "verification event.");

        } else if (AUTHENTICATION_STEP_NOTIFICATION_VERIFICATION.equals(event)) {

            if (properties.containsKey(CORRELATION_ID)) {
                return DigestUtils.sha256Hex((String) properties.get(CORRELATION_ID));
            } else {
                throw new IdentityFraudDetectionRequestException("Cannot resolve session id for the authentication " +
                        "step notification verification event.");
            }
        }

        throw new IdentityFraudDetectionRequestException("Cannot resolve session id for the verification event.");
    }

    /**
     * Resolves the status for the verification event.
     *
     * @param event      Fraud detection event.
     * @param properties Map of event properties.
     * @return Resolved status.
     * @throws IdentityFraudDetectionRequestException if an error occurs while resolving the status.
     */
    private static String resolveStatus(FraudDetectionConstants.FraudDetectionEvents event,
                                        Map<String, Object> properties) throws IdentityFraudDetectionRequestException {

        if (USER_ATTRIBUTE_UPDATE_VERIFICATION_NOTIFICATION.equals(event)
                || SELF_REGISTRATION_VERIFICATION_NOTIFICATION.equals(event)) {
            return PENDING.getValue();
        } else if (POST_USER_ATTRIBUTE_UPDATE_VERIFICATION.equals(event)
                || POST_SELF_REGISTRATION_VERIFICATION.equals(event)) {
            return SUCCESS.getValue();
        } else if (AUTHENTICATION_STEP_NOTIFICATION_VERIFICATION.equals(event)) {
            String internalEventName = (String) properties.get(INTERNAL_EVENT_NAME);
            if (POST_GENERATE_SMS_OTP.equals(internalEventName)
                    || POST_GENERATE_EMAIL_OTP.equals(internalEventName)) {
                return PENDING.getValue();
            } else if (POST_VALIDATE_SMS_OTP.equals(internalEventName)
                    || POST_VALIDATE_EMAIL_OTP.equals(internalEventName)) {
                String status = (String) properties.get(OTP_STATUS);
                if ("success".equals(status)) {
                    return SUCCESS.getValue();
                } else {
                    return FAILURE.getValue();
                }
            }
        }

        throw new IdentityFraudDetectionRequestException("Cannot resolve status for the verification event.");
    }

    /**
     * Resolves the verified event for the verification event.
     *
     * @param event      Fraud detection event.
     * @param properties Map of event properties.
     * @return Resolved verified event.
     */
    private static String resolveVerifiedEvent(FraudDetectionConstants.FraudDetectionEvents event,
                                               Map<String, Object> properties) {

        if (isAttributeUpdateVerificationEvent(event)) {
            String recoveryScenario = (String) properties.get(RECOVERY_SCENARIO);
            if (EMAIL_VERIFICATION_ON_UPDATE.name().equals(recoveryScenario)
                    || MOBILE_VERIFICATION_ON_UPDATE.name().equals(recoveryScenario)) {
                return PROFILE_UPDATE.getValue();
            }
        } else if (isSelfRegistrationVerificationEvent(event)) {
            String internalEventName = (String) properties.get(INTERNAL_EVENT_NAME);
            if (TRIGGER_NOTIFICATION.equals(internalEventName)) {
                String templateType = (String) properties.get(TEMPLATE_TYPE);
                if (templateType.equals(NOTIFICATION_TYPE_ACCOUNT_CONFIRM)) {
                    return USER_REGISTRATION.getValue();
                }
            } else if (POST_USER_ACCOUNT_CONFIRMATION.equals(internalEventName)) {
                return USER_REGISTRATION.getValue();
            }
        } else if (AUTHENTICATION_STEP_NOTIFICATION_VERIFICATION.equals(event)) {
            return USER_LOGIN.getValue();
        }

        return null;
    }

    /**
     * Resolves the entity ID for the verification event.
     *
     * @param verifiedEvent Verified event.
     * @param sessionId     Session ID.
     * @return Resolved entity ID.
     */
    private static String resolveEntityId(String verifiedEvent, String sessionId) {

        if (USER_LOGIN.getValue().equals(verifiedEvent)) {
            return sessionId;
        }
        return null;
    }

    /**
     * Resolves the verification type for the verification event.
     *
     * @param event      Fraud detection event.
     * @param properties Map of event properties.
     * @return Resolved verification type.
     */
    private static String resolveVerificationType(FraudDetectionConstants.FraudDetectionEvents event,
                                                  Map<String, Object> properties) {

        if (isAttributeUpdateVerificationEvent(event)) {

            String recoveryScenario = (String) properties.get(RECOVERY_SCENARIO);
            if (EMAIL_VERIFICATION_ON_UPDATE.name().equals(recoveryScenario)) {
                return EMAIL_KEY;
            } else if (MOBILE_VERIFICATION_ON_UPDATE.name().equals(recoveryScenario)) {
                return SMS_KEY;
            }

        } else if (isSelfRegistrationVerificationEvent(event)) {

            String internalEventName = (String) properties.get(INTERNAL_EVENT_NAME);
            if (TRIGGER_NOTIFICATION.equals(internalEventName)) {
                // This event is only triggered for email related notifications.
                return EMAIL_KEY;
            } else if (POST_USER_ACCOUNT_CONFIRMATION.equals(internalEventName)) {
                String verifiedChannelClaim = (String) properties.get(VERIFIED_CHANNEL);
                if (EMAIL_VERIFIED_CLAIM.equals(verifiedChannelClaim)) {
                    return EMAIL_KEY;
                } else if (NotificationChannels.SMS_CHANNEL.getVerifiedClaimUrl().equals(verifiedChannelClaim)) {
                    return SMS_KEY;
                }
            }

        } else if (AUTHENTICATION_STEP_NOTIFICATION_VERIFICATION.equals(event)) {

            String internalEventName = (String) properties.get(INTERNAL_EVENT_NAME);
            if (POST_GENERATE_SMS_OTP.equals(internalEventName) || POST_VALIDATE_SMS_OTP.equals(internalEventName)) {
                return SMS_KEY;
            } else if (POST_GENERATE_EMAIL_OTP.equals(internalEventName)
                    || POST_VALIDATE_EMAIL_OTP.equals(internalEventName)) {
                return EMAIL_KEY;
            }
        }

        return null;
    }

    /**
     * Resolves the verified value for the verification event.
     *
     * @param verificationType Verification type.
     * @param event            Fraud detection event.
     * @param properties       Map of event properties.
     * @return Resolved verified value.
     * @throws IdentityFraudDetectionRequestException if an error occurs while resolving the verified value.
     */
    private static String resolveVerifiedValue(String verificationType,
                                               FraudDetectionConstants.FraudDetectionEvents event,
                                               Map<String, Object> properties)
            throws IdentityFraudDetectionRequestException {

        if (StringUtils.isEmpty(verificationType)) {
            return null;
        }

        if (USER_ATTRIBUTE_UPDATE_VERIFICATION_NOTIFICATION.equals(event)) {

            String notificationChannelValue = properties.containsKey(SEND_TO) ? (String) properties.get(SEND_TO) : null;
            if (EMAIL_KEY.equals(verificationType)) {
                return validateMobileNumberFormat((String) properties.get(SEND_TO));
            }

            return notificationChannelValue;
        }

        if (isSelfRegistrationVerificationEvent(event)) {

            if (EMAIL_KEY.equals(verificationType)) {
                return resolveUserAttribute(properties, UserCoreConstants.ClaimTypeURIs.EMAIL_ADDRESS);
            } else if (SMS_KEY.equals(verificationType)) {
                return validateMobileNumberFormat(
                        resolveUserAttribute(properties, UserCoreConstants.ClaimTypeURIs.MOBILE));
            }
        }

        if (POST_USER_ATTRIBUTE_UPDATE_VERIFICATION.equals(event)) {

            if (properties.containsKey(VERIFIED_EMAIL)) {
                return (String) properties.get(VERIFIED_EMAIL);
            } else if (properties.containsKey(VERIFIED_MOBILE)) {
                return validateMobileNumberFormat((String) properties.get(VERIFIED_MOBILE));
            }
        }

        if (AUTHENTICATION_STEP_NOTIFICATION_VERIFICATION.equals(event)) {

            String internalEventName = (String) properties.get(INTERNAL_EVENT_NAME);
            if (POST_GENERATE_SMS_OTP.equals(internalEventName) || POST_VALIDATE_SMS_OTP.equals(internalEventName)) {
                return validateMobileNumberFormat(
                        resolveUserAttribute(properties, UserCoreConstants.ClaimTypeURIs.MOBILE));
            } else if (POST_GENERATE_EMAIL_OTP.equals(internalEventName)
                    || POST_VALIDATE_EMAIL_OTP.equals(internalEventName)) {
                return resolveUserAttribute(properties, UserCoreConstants.ClaimTypeURIs.EMAIL_ADDRESS);
            }
        }

        return null;
    }

    /**
     * Resolves the reason for the verification event.
     *
     * @param event Fraud detection event.
     * @return Resolved reason.
     */
    private static String resolveReason(FraudDetectionConstants.FraudDetectionEvents event) {

        if (isAttributeUpdateVerificationEvent(event) || isSelfRegistrationVerificationEvent(event)
                || AUTHENTICATION_STEP_NOTIFICATION_VERIFICATION.equals(event)) {
            return MANUAL_REVIEW_VERIFICATION_TYPE;
        }
        return null;
    }

    /**
     * Checks if the event is an attribute update verification event.
     *
     * @param event Fraud detection event.
     * @return true if it is an attribute update verification event, false otherwise.
     */
    private static boolean isAttributeUpdateVerificationEvent(FraudDetectionConstants.FraudDetectionEvents event) {

        return USER_ATTRIBUTE_UPDATE_VERIFICATION_NOTIFICATION.equals(event)
                || POST_USER_ATTRIBUTE_UPDATE_VERIFICATION.equals(event);
    }

    /**
     * Checks if the event is a self registration verification event.
     *
     * @param event Fraud detection event.
     * @return true if it is a self registration verification event, false otherwise.
     */
    private static boolean isSelfRegistrationVerificationEvent(FraudDetectionConstants.FraudDetectionEvents event) {

        return SELF_REGISTRATION_VERIFICATION_NOTIFICATION.equals(event)
                || POST_SELF_REGISTRATION_VERIFICATION.equals(event);
    }

    /**
     * Sets custom fields for the verification event.
     *
     * @param event      Fraud detection event.
     * @param fieldSet   Verification field set.
     * @param properties Map of event properties.
     */
    private static void setCustomFields(FraudDetectionConstants.FraudDetectionEvents event,
                                        VerificationFieldSet fieldSet, Map<String, Object> properties) {

        if (!POST_USER_ATTRIBUTE_UPDATE_VERIFICATION.equals(event)) {
            return;
        }

        String recoveryScenario = (String) properties.get(RECOVERY_SCENARIO);
        if (MOBILE_VERIFICATION_ON_UPDATE.name().equals(recoveryScenario)) {
            boolean verifiedByEndUser =
                    properties.containsKey(VERIFIED_BY_END_USER) && (boolean) properties.get(VERIFIED_BY_END_USER);
            fieldSet.setCustomField(Constants.VERIFIED_BY_END_USER, verifiedByEndUser);
        } else if (EMAIL_VERIFICATION_ON_UPDATE.name().equals(recoveryScenario)) {
            fieldSet.setCustomField(Constants.VERIFIED_BY_END_USER, true);
        }
    }

}
