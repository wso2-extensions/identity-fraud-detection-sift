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
import com.siftscience.model.AbuseScore;
import com.siftscience.model.Browser;
import com.siftscience.model.EventResponseBody;
import com.siftscience.model.LoginFieldSet;
import com.siftscience.model.ScoreResponse;
import com.siftscience.model.WorkflowStatus;
import com.siftscience.model.WorkflowStatusHistoryConfig;
import com.siftscience.model.WorkflowStatusHistoryItem;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.lang.StringUtils;
import org.wso2.carbon.identity.application.authentication.framework.config.model.graph.js.JsAuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.common.model.User;
import org.wso2.carbon.identity.fraud.detection.sift.Constants;
import org.wso2.carbon.identity.fraud.detection.sift.models.SiftFraudDetectorRequestDTO;
import org.wso2.carbon.identity.fraud.detection.sift.models.SiftFraudDetectorResponseDTO;
import org.wso2.carbon.identity.fraud.detectors.core.constant.FraudDetectorConstants;
import org.wso2.carbon.identity.fraud.detectors.core.exception.IdentityFraudDetectorRequestException;
import org.wso2.carbon.identity.fraud.detectors.core.exception.IdentityFraudDetectorResponseException;
import org.wso2.carbon.identity.fraud.detectors.core.model.FraudDetectorResponseDTO;
import org.wso2.carbon.user.core.UserCoreConstants;

import java.util.Map;

import static org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants.AnalyticsAttributes.USER;
import static org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants.AnalyticsData.CURRENT_AUTHENTICATOR_ERROR_CODE;
import static org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants.JSAttributes.JS_LAST_LOGIN_FAILED_USER;
import static org.wso2.carbon.identity.event.IdentityEventConstants.EventName.AUTHENTICATION_FAILURE;
import static org.wso2.carbon.identity.event.IdentityEventConstants.EventName.AUTHENTICATION_STEP_FAILURE;
import static org.wso2.carbon.identity.event.IdentityEventConstants.EventName.AUTHENTICATION_SUCCESS;
import static org.wso2.carbon.identity.event.IdentityEventConstants.EventProperty.CONTEXT;
import static org.wso2.carbon.identity.event.IdentityEventConstants.EventProperty.PARAMS;
import static org.wso2.carbon.identity.event.IdentityEventConstants.EventProperty.TENANT_DOMAIN;
import static org.wso2.carbon.identity.event.IdentityEventConstants.EventProperty.USER_NAME;
import static org.wso2.carbon.identity.event.IdentityEventConstants.EventProperty.USER_STORE_DOMAIN;
import static org.wso2.carbon.identity.fraud.detection.sift.Constants.AUTHENTICATION_CONTEXT;
import static org.wso2.carbon.identity.fraud.detection.sift.Constants.CUSTOM_PARAMS;
import static org.wso2.carbon.identity.fraud.detection.sift.Constants.LOGIN_STATUS;
import static org.wso2.carbon.identity.fraud.detection.sift.Constants.LoginStatus.LOGIN_SUCCESS;
import static org.wso2.carbon.identity.fraud.detection.sift.Constants.SIFT_ACCOUNT_TAKEOVER;
import static org.wso2.carbon.identity.fraud.detection.sift.Constants.SIFT_DECISION;
import static org.wso2.carbon.identity.fraud.detection.sift.Constants.SIFT_SESSION;
import static org.wso2.carbon.identity.fraud.detection.sift.util.SiftEventUtil.validateMobileNumberFormat;
import static org.wso2.carbon.identity.fraud.detection.sift.util.Util.getLoginStatus;
import static org.wso2.carbon.identity.fraud.detection.sift.util.Util.processCustomParameters;
import static org.wso2.carbon.identity.fraud.detection.sift.util.Util.processDefaultParameters;
import static org.wso2.carbon.identity.fraud.detection.sift.util.Util.resolvePayloadData;
import static org.wso2.carbon.identity.fraud.detection.sift.util.Util.setAPIKey;
import static org.wso2.carbon.identity.fraud.detectors.core.constant.FraudDetectorConstants.INTERNAL_EVENT_NAME;
import static org.wso2.carbon.identity.mgt.store.UserIdentityDataStore.ACCOUNT_DISABLED;
import static org.wso2.carbon.identity.mgt.store.UserIdentityDataStore.ACCOUNT_LOCK;
import static org.wso2.carbon.user.core.UserCoreConstants.ClaimTypeURIs.EMAIL_ADDRESS;
import static org.wso2.carbon.user.core.UserCoreConstants.ClaimTypeURIs.MOBILE;
import static org.wso2.carbon.user.core.constants.UserCoreErrorConstants.ErrorMessages.ERROR_CODE_NON_EXISTING_USER;

/**
 * Utility class for handling Sift login events.
 */
public class SiftLoginEventUtil {

    /**
     * Handles the login event payload based on the source of the event.
     *
     * @param requestDTO Sift fraud detector request DTO.
     * @return JSON string representing the login event payload.
     * @throws IdentityFraudDetectorRequestException if an error occurs while handling the payload.
     */
    public static String handleLoginEventPayload(SiftFraudDetectorRequestDTO requestDTO)
            throws IdentityFraudDetectorRequestException {

        if (requestDTO.getProperties().containsKey(INTERNAL_EVENT_NAME)) {
            return handleLoginEventFromInternalEvent(requestDTO);
        } else {
            return handleLoginEventFromScript(requestDTO);
        }
    }

    /**
     * Handles login event payload from authentication script.
     *
     * @param requestDTO Sift fraud detector request DTO.
     * @return JSON string representing the login event payload.
     * @throws IdentityFraudDetectorRequestException if an error occurs while handling the payload.
     */
    private static String handleLoginEventFromScript(SiftFraudDetectorRequestDTO requestDTO)
            throws IdentityFraudDetectorRequestException {

        Map<String, Object> properties = requestDTO.getProperties();
        JsAuthenticationContext context = properties.get(AUTHENTICATION_CONTEXT) != null ?
                (JsAuthenticationContext) properties.get(AUTHENTICATION_CONTEXT) : null;
        if (context == null) {
            throw new IdentityFraudDetectorRequestException("Authentication context is null in the request.");
        }

        try {
            String loginStatus = getLoginStatus((String) properties.get(Constants.LOGIN_STATUS)).getSiftValue();
            LoginFieldSet loginFieldSet = new LoginFieldSet()
                    .setLoginStatus(loginStatus)
                    .setUserId(resolvePayloadData(Constants.USER_ID_KEY, context))
                    .setBrowser(new Browser().setUserAgent(resolvePayloadData(Constants.USER_AGENT_KEY, context)))
                    .setIp(resolvePayloadData(Constants.IP_KEY, context))
                    .setSessionId(resolvePayloadData(Constants.SESSION_ID_KEY, context))
                    .setFailureReason(resolveFailureReason(properties, context))
                    .setUsername(resolveUsername(properties))
                    .setUserEmail(resolveUserClaim(properties, EMAIL_ADDRESS))
                    .setVerificationPhoneNumber(validateMobileNumberFormat(resolveUserClaim(properties, MOBILE)));
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

    /**
     * Handles login event payload from internal event.
     *
     * @param requestDTO Sift fraud detector request DTO.
     * @return JSON string representing the login event payload.
     * @throws IdentityFraudDetectorRequestException if an error occurs while handling the payload.
     */
    private static String handleLoginEventFromInternalEvent(SiftFraudDetectorRequestDTO requestDTO)
            throws IdentityFraudDetectorRequestException {

        Map<String, Object> properties = requestDTO.getProperties();
        AuthenticationContext context = (AuthenticationContext) properties.get(CONTEXT);
        try {
            LoginFieldSet loginFieldSet = new LoginFieldSet()
                    .setLoginStatus(resolveLoginStatus(properties))
                    .setUserId(resolveUserId(properties))
                    .setBrowser(new Browser().setUserAgent(resolvePayloadData(Constants.USER_AGENT_KEY, context)))
                    .setIp(resolvePayloadData(Constants.IP_KEY, context))
                    .setSessionId(resolvePayloadData(Constants.SESSION_ID_KEY, context))
                    .setFailureReason(resolveFailureReason(properties, context))
                    .setUsername(resolveUsername(properties))
                    .setUserEmail(resolveUserClaim(properties, EMAIL_ADDRESS))
                    .setVerificationPhoneNumber(validateMobileNumberFormat(resolveUserClaim(properties, MOBILE)));
            loginFieldSet.validate();
            return setAPIKey(loginFieldSet, context.getTenantDomain());
        } catch (InvalidFieldException e) {
            throw new IdentityFraudDetectorRequestException("Error while building login event payload: "
                    + e.getMessage(), e);
        } catch (FrameworkException e) {
            throw new IdentityFraudDetectorRequestException("Error while resolving payload data: "
                    + e.getMessage(), e);
        }
    }

    /**
     * Handles the login event response from Sift.
     *
     * @param responseContent JSON string representing the response from Sift.
     * @param requestDTO      Sift fraud detector request DTO.
     * @return Sift fraud detector response DTO.
     * @throws IdentityFraudDetectorResponseException if an error occurs while handling the response.
     */
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

    /**
     * Resolves the login status for the login event.
     *
     * @param properties Map of properties related to the event.
     * @return Resolved login status.
     * @throws IdentityFraudDetectorRequestException if an error occurs while resolving the login status.
     */
    private static String resolveLoginStatus(Map<String, Object> properties)
            throws IdentityFraudDetectorRequestException {

        String internalEventName = (String) properties.get(INTERNAL_EVENT_NAME);
        if (AUTHENTICATION_SUCCESS.name().equals(internalEventName)) {
            return "$success";
        } else if (AUTHENTICATION_FAILURE.name().equals(internalEventName)
                || AUTHENTICATION_STEP_FAILURE.name().equals(internalEventName)) {
            return "$failure";
        }

        throw new IdentityFraudDetectorRequestException("Cannot resolve login status for the login event.");
    }

    /**
     * Resolves the user ID for the login event.
     *
     * @param properties Map of properties related to the event.
     * @return Resolved user ID.
     * @throws IdentityFraudDetectorRequestException if an error occurs while resolving the user ID.
     */
    private static String resolveUserId(Map<String, Object> properties) throws IdentityFraudDetectorRequestException {

        Map<String, Object> params = (Map<String, Object>) properties.get(PARAMS);
        if (params.containsKey(USER) && params.get(USER) != null) {
            return DigestUtils.sha256Hex(params.get(USER).toString());
        }

        AuthenticationContext context = resolveAuthenticationContext(properties);
        if (context != null && context.getLastAuthenticatedUser() != null) {
            AuthenticatedUser authenticatedUser = context.getLastAuthenticatedUser();
            return DigestUtils.sha256Hex(authenticatedUser.toString());
        }

        throw new IdentityFraudDetectorRequestException("Cannot resolve user ID for the login event. " +
                "Authenticated user is null in the authentication context.");
    }

    /**
     * Resolves the failure reason for the login event.
     *
     * @param properties Map of properties related to the event.
     * @param context    JsAuthenticationContext of the event.
     * @return Resolved failure reason.
     */
    private static String resolveFailureReason(Map<String, Object> properties, JsAuthenticationContext context) {

        AuthenticationContext authenticationContext = context.getWrapped();
        return resolveFailureReason(properties, authenticationContext);
    }

    /**
     * Resolves the failure reason for the login event.
     *
     * @param properties Map of properties related to the event.
     * @param context    AuthenticationContext of the event.
     * @return Resolved failure reason.
     */
    private static String resolveFailureReason(Map<String, Object> properties, AuthenticationContext context) {

        try {
            if (isLoginSuccessful(properties)) {
                return null;
            }
        } catch (IdentityFraudDetectorRequestException e) {
            return null;
        }

        AuthenticatedUser failedUser;
        boolean fromInternalEvent = !properties.containsKey(INTERNAL_EVENT_NAME);
        if (fromInternalEvent) {
            Map<String, Object> params = (Map<String, Object>) properties.get(PARAMS);
            failedUser = params.containsKey(USER) ? new AuthenticatedUser((User) params.get(USER)) : null;
        } else {
            failedUser = context.getProperties().get(JS_LAST_LOGIN_FAILED_USER) != null ?
                    (AuthenticatedUser) context.getProperties().get(JS_LAST_LOGIN_FAILED_USER) : null;
        }

        String currentErrorCode = context.getAnalyticsData(CURRENT_AUTHENTICATOR_ERROR_CODE) != null ?
                (String) context.getAnalyticsData(CURRENT_AUTHENTICATOR_ERROR_CODE) : null;

        if (failedUser == null) {
            // Cannot resolve the user to get the account state claims.
            return null;
        }

        if (!properties.containsKey(USER_NAME)) {
            properties.put(USER_NAME, failedUser.getUserName());
        }
        if (!properties.containsKey(TENANT_DOMAIN)) {
            properties.put(TENANT_DOMAIN, failedUser.getTenantDomain());
        }
        if (!properties.containsKey(USER_STORE_DOMAIN)) {
            properties.put(USER_STORE_DOMAIN, failedUser.getUserStoreDomain());
        }

        String siftFailureReason = null;
        try {
            String accountLockClaimValue = resolveUserClaim(properties, ACCOUNT_LOCK, true);
            String accountDisableClaimValue = resolveUserClaim(properties, ACCOUNT_DISABLED, true);
            if (UserCoreConstants.ErrorCode.INVALID_CREDENTIAL.equals(currentErrorCode)) {
                // In this situation, either the password is incorrect or the account don't exist.
                siftFailureReason = "$wrong_password";
            } else {
                if (Boolean.parseBoolean(accountLockClaimValue)) {
                    siftFailureReason = "$account_suspended";
                } else if (Boolean.parseBoolean(accountDisableClaimValue)) {
                    siftFailureReason = "$account_disabled";
                }
            }
        } catch (IdentityFraudDetectorRequestException e) {
            // Catch the relevant exception to user not existing and return user not available as the reason.
            String errorMessage = e.getMessage();
            if (errorMessage != null && errorMessage.contains(ERROR_CODE_NON_EXISTING_USER.getCode())) {
                return "$account_unknown";
            }
        }

        // TODO: Add a debug log here.
        return siftFailureReason;
    }

    /**
     * Resolves the username for the login event.
     *
     * @param properties Map of properties related to the event.
     * @return Resolved username.
     */
    private static String resolveUsername(Map<String, Object> properties) {

        AuthenticationContext authenticationContext = resolveAuthenticationContext(properties);
        if (authenticationContext == null) {
            return null;
        }

        return authenticationContext.getProperties().containsKey("usernameUserInput") ?
                (String) authenticationContext.getProperties().get("usernameUserInput") : null;
    }

    /**
     * Checks whether the login was successful.
     *
     * @param properties Map of properties related to the event.
     * @return true if the login was successful, false otherwise.
     * @throws IdentityFraudDetectorRequestException if an error occurs while checking the login status.
     */
    private static boolean isLoginSuccessful(Map<String, Object> properties)
            throws IdentityFraudDetectorRequestException {

        String internalEventName = properties.containsKey(INTERNAL_EVENT_NAME) ?
                (String) properties.get(INTERNAL_EVENT_NAME) : null;
        if (StringUtils.isNotEmpty(internalEventName)) {
            return AUTHENTICATION_SUCCESS.name().equals(internalEventName);
        }

        String loginStatus = properties.containsKey(LOGIN_STATUS)
                ? (String) properties.get(Constants.LOGIN_STATUS) : null;
        if (StringUtils.isNotEmpty(loginStatus)) {
            return LOGIN_SUCCESS.name().equals(loginStatus);
        }

        throw new IdentityFraudDetectorRequestException("Cannot resolve login status for the login event.");
    }

    /**
     * Resolves a user claim for the login event.
     *
     * @param properties Map of properties related to the event.
     * @param claimUri   Claim URI to be resolved.
     * @return Resolved claim value.
     * @throws IdentityFraudDetectorRequestException if an error occurs while resolving the claim.
     */
    private static String resolveUserClaim(Map<String, Object> properties, String claimUri)
            throws IdentityFraudDetectorRequestException {

        return resolveUserClaim(properties, claimUri, false);
    }

    /**
     * Resolves a user claim for the login event.
     *
     * @param properties      Map of properties related to the event.
     * @param claimUri        Claim URI to be resolved.
     * @param isIdentityClaim Whether the claim is an identity claim.
     * @return Resolved claim value.
     * @throws IdentityFraudDetectorRequestException if an error occurs while resolving the claim.
     */
    private static String resolveUserClaim(Map<String, Object> properties, String claimUri, boolean isIdentityClaim)
            throws IdentityFraudDetectorRequestException {

        try {
            if (!isLoginSuccessful(properties)) {
                return null;
            }
        } catch (IdentityFraudDetectorRequestException e) {
            return null;
        }

        AuthenticatedUser authenticatedUser = resolveAuthenticatedUser(properties);
        if (authenticatedUser == null) {
            return null;
        }

        if (!properties.containsKey(USER_NAME)) {
            properties.put(USER_NAME, authenticatedUser.getUserName());
        }
        if (!properties.containsKey(TENANT_DOMAIN)) {
            properties.put(TENANT_DOMAIN, authenticatedUser.getTenantDomain());
        }
        if (!properties.containsKey(USER_STORE_DOMAIN)) {
            properties.put(USER_STORE_DOMAIN, authenticatedUser.getUserStoreDomain());
        }

        return SiftEventUtil.resolveUserAttribute(properties, claimUri, isIdentityClaim);
    }

    /**
     * Resolves the authenticated user from the properties.
     *
     * @param properties Map of properties related to the event.
     * @return Resolved authenticated user.
     */
    private static AuthenticatedUser resolveAuthenticatedUser(Map<String, Object> properties) {

        AuthenticationContext authenticationContext = resolveAuthenticationContext(properties);
        if (authenticationContext == null) {
            return null;
        }

        return authenticationContext.getLastAuthenticatedUser();
    }

    /**
     * Resolves the authentication context from the properties.
     *
     * @param properties Map of properties related to the event.
     * @return Resolved authentication context.
     */
    private static AuthenticationContext resolveAuthenticationContext(Map<String, Object> properties) {

        AuthenticationContext authenticationContext = null;
        if (properties.containsKey(CONTEXT)) {
            authenticationContext = (AuthenticationContext) properties.get(CONTEXT);
        } else if (properties.containsKey(AUTHENTICATION_CONTEXT)) {
            JsAuthenticationContext jsAuthenticationContext =
                    (JsAuthenticationContext) properties.get(AUTHENTICATION_CONTEXT);
            authenticationContext = jsAuthenticationContext.getWrapped();
        }

        return authenticationContext;
    }

    /**
     * Checks if the abuse type is account takeover.
     *
     * @param workflowStatus Workflow status to be checked.
     * @return true if the abuse type is account takeover, false otherwise.
     */
    private static boolean isATOAbuseType(WorkflowStatus workflowStatus) {

        for (String abuseType : workflowStatus.getAbuseTypes()) {
            if (SIFT_ACCOUNT_TAKEOVER.equals(abuseType)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Checks if the workflow status is of session type.
     *
     * @param workflowStatus Workflow status to be checked.
     * @return true if the workflow status is of session type, false otherwise.
     */
    private static boolean isSessionType(WorkflowStatus workflowStatus) {

        if (workflowStatus.getEntity() == null) {
            return false;
        }
        return SIFT_SESSION.equals(workflowStatus.getEntity().getType());
    }

    /**
     * Retrieves the decision from the workflow status.
     *
     * @param workflowStatus Workflow status to retrieve the decision from.
     * @return Decision string if found, null otherwise.
     */
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
