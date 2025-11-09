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

import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.common.model.User;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.fraud.detection.sift.exception.SiftUnsupportedEventException;
import org.wso2.carbon.identity.fraud.detection.sift.models.SiftFraudDetectorRequestDTO;
import org.wso2.carbon.identity.fraud.detectors.core.exception.FraudDetectionConfigServerException;
import org.wso2.carbon.identity.fraud.detectors.core.exception.IdentityFraudDetectorRequestException;
import org.wso2.carbon.identity.fraud.detectors.core.exception.IdentityFraudDetectorResponseException;
import org.wso2.carbon.identity.fraud.detectors.core.model.FraudDetectorRequestDTO;
import org.wso2.carbon.identity.fraud.detectors.core.model.FraudDetectorResponseDTO;
import org.wso2.carbon.identity.fraud.detectors.core.util.EventUtil;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.user.core.util.UserCoreUtil;

import java.util.HashMap;
import java.util.Map;

import static org.wso2.carbon.identity.event.IdentityEventConstants.EventProperty.TENANT_DOMAIN;
import static org.wso2.carbon.identity.event.IdentityEventConstants.EventProperty.USER;
import static org.wso2.carbon.identity.event.IdentityEventConstants.EventProperty.USER_CLAIMS;
import static org.wso2.carbon.identity.event.IdentityEventConstants.EventProperty.USER_NAME;
import static org.wso2.carbon.identity.event.IdentityEventConstants.EventProperty.USER_STORE_DOMAIN;
import static org.wso2.carbon.identity.event.IdentityEventConstants.EventProperty.USER_STORE_MANAGER;
import static org.wso2.carbon.identity.fraud.detection.sift.Constants.REMOTE_ADDRESS;
import static org.wso2.carbon.identity.fraud.detection.sift.Constants.USER_AGENT_HEADER;
import static org.wso2.carbon.user.core.UserCoreConstants.ClaimTypeURIs.GIVEN_NAME;
import static org.wso2.carbon.user.core.UserCoreConstants.ClaimTypeURIs.SURNAME;
import static org.wso2.carbon.user.core.UserCoreConstants.RealmConfig.PROPERTY_DOMAIN_NAME;
import static org.wso2.carbon.user.core.constants.UserCoreErrorConstants.ErrorMessages.ERROR_CODE_NON_EXISTING_USER;

/**
 * Utility class for Sift event handling.
 */
public class SiftEventUtil {

    private static final Log LOG = LogFactory.getLog(SiftEventUtil.class);
    private static final String E164_REGEX = "^\\+[1-9]\\d{1,14}$";

    /**
     * Builds the Sift event payload based on the event name in the request DTO.
     *
     * @param requestDTO Sift fraud detector request DTO.
     * @return Sift event payload as a JSON string.
     * @throws IdentityFraudDetectorRequestException If an error occurs while building the payload.
     * @throws SiftUnsupportedEventException        If the event name is not supported by Sift.
     */
    public static String buildSiftEventPayload(SiftFraudDetectorRequestDTO requestDTO)
            throws IdentityFraudDetectorRequestException, SiftUnsupportedEventException {

        switch (requestDTO.getEventName()) {
            case LOGIN:
                return SiftLoginEventUtil.handleLoginEventPayload(requestDTO);
            case LOGOUT:
                return SiftLogoutEventUtil.handleLogoutEventPayload(requestDTO);
            case POST_USER_CREATION:
                 return SiftUserRegistrationEventUtil.handlePostUserRegistrationEventPayload(requestDTO);
            case PRE_UPDATE_PASSWORD_NOTIFICATION:
            case POST_UPDATE_PASSWORD:
                return SiftUpdatePasswordEventUtil.handleUpdatePasswordEventPayload(requestDTO);
            case SELF_REGISTRATION_VERIFICATION_NOTIFICATION:
            case POST_SELF_REGISTRATION_VERIFICATION:
            case USER_ATTRIBUTE_UPDATE_VERIFICATION_NOTIFICATION:
            case POST_USER_ATTRIBUTE_UPDATE_VERIFICATION:
            case AUTHENTICATION_STEP_NOTIFICATION_VERIFICATION:
                return SiftVerificationEventUtil.handleVerificationEventPayload(requestDTO);
            case POST_UPDATE_USER_PROFILE:
                return SiftUserProfileUpdateEventUtil.handlePostUserProfileUpdateEventPayload(requestDTO);
            default:
                throw new SiftUnsupportedEventException("Unsupported event name by Sift: "
                        + requestDTO.getEventName());
        }
    }

    /**
     * Handles the Sift event response based on the event name in the request DTO.
     *
     * @param responseContent Sift event response content.
     * @param requestDTO      Sift fraud detector request DTO.
     * @return Fraud detector response DTO.
     * @throws IdentityFraudDetectorResponseException If an error occurs while handling the response.
     * @throws SiftUnsupportedEventException         If the event name is not supported by Sift.
     */
    public static FraudDetectorResponseDTO handleResponse(String responseContent, FraudDetectorRequestDTO requestDTO)
            throws IdentityFraudDetectorResponseException, SiftUnsupportedEventException {

        switch (requestDTO.getEventName()) {
            case LOGIN:
                return SiftLoginEventUtil.handleLoginResponse(responseContent,
                        (SiftFraudDetectorRequestDTO) requestDTO);
            case LOGOUT:
                return SiftLogoutEventUtil.handleLogoutResponse(responseContent,
                        (SiftFraudDetectorRequestDTO) requestDTO);
            case POST_USER_CREATION:
                return SiftUserRegistrationEventUtil.handlePostUserRegistrationResponse(responseContent,
                        (SiftFraudDetectorRequestDTO) requestDTO);
            case PRE_UPDATE_PASSWORD_NOTIFICATION:
            case POST_UPDATE_PASSWORD:
                return SiftUpdatePasswordEventUtil.handleUpdatePasswordResponse(responseContent,
                        (SiftFraudDetectorRequestDTO) requestDTO);
            case SELF_REGISTRATION_VERIFICATION_NOTIFICATION:
            case POST_SELF_REGISTRATION_VERIFICATION:
            case USER_ATTRIBUTE_UPDATE_VERIFICATION_NOTIFICATION:
            case POST_USER_ATTRIBUTE_UPDATE_VERIFICATION:
            case AUTHENTICATION_STEP_NOTIFICATION_VERIFICATION:
                return SiftVerificationEventUtil.handleVerificationResponse(responseContent,
                        (SiftFraudDetectorRequestDTO) requestDTO);
            case POST_UPDATE_USER_PROFILE:
                return SiftUserProfileUpdateEventUtil.handlePostUserProfileUpdateResponse(responseContent,
                        (SiftFraudDetectorRequestDTO) requestDTO);
            default:
                throw new SiftUnsupportedEventException(requestDTO.getEventName()
                        + " event cannot be handled by Sift.");
        }
    }

    /**
     * Resolves the user store domain from the properties map.
     *
     * @param properties Map of properties related to the event.
     * @return Resolved user store domain.
     * @throws IdentityFraudDetectorRequestException If an error occurs while resolving the user store domain.
     */
    protected static String resolveUserStoreDomain(Map<String, Object> properties)
            throws IdentityFraudDetectorRequestException {

        String userStoreDomain = properties.get(USER_STORE_DOMAIN) != null ?
                (String) properties.get(USER_STORE_DOMAIN) : null;

        if (userStoreDomain == null) {

            UserStoreManager userStoreManager = (UserStoreManager) properties.get(USER_STORE_MANAGER);
            if (userStoreManager == null) {
                throw new IdentityFraudDetectorRequestException("Cannot resolve user id. User store manager is null.");
            }
            userStoreDomain = userStoreManager.getRealmConfiguration().getUserStoreProperty(PROPERTY_DOMAIN_NAME);
            properties.put(USER_STORE_DOMAIN, userStoreDomain);
            return userStoreDomain;
        }

        return userStoreDomain;
    }

    /**
     * Resolves the user id from the properties map.
     *
     * @param properties Map of properties related to the event.
     * @return Resolved user id.
     * @throws IdentityFraudDetectorRequestException If an error occurs while resolving the user id.
     */
    protected static String resolveUserId(Map<String, Object> properties) throws IdentityFraudDetectorRequestException {

        String username;
        String tenantDomain;
        String userStoreDomain;
        if (properties.containsKey(USER)) {
            User userObj = (User) properties.get(USER);
            username = userObj.getUserName();
            properties.put(USER_NAME, username);
            tenantDomain = userObj.getTenantDomain();
            properties.put(TENANT_DOMAIN, tenantDomain);
            userStoreDomain = userObj.getUserStoreDomain();
            properties.put(USER_STORE_DOMAIN, userStoreDomain);
        } else {
            username = properties.get(USER_NAME) != null ? (String) properties.get(USER_NAME) : null;
            tenantDomain = properties.get(TENANT_DOMAIN) != null ? (String) properties.get(TENANT_DOMAIN) : null;
            userStoreDomain = resolveUserStoreDomain(properties);
        }

        if (StringUtils.isEmpty(username) || StringUtils.isEmpty(tenantDomain) ||
                StringUtils.isEmpty(userStoreDomain)) {
            throw new IdentityFraudDetectorRequestException("Cannot resolve user id. Username, tenant domain " +
                    "or user store domain is null.");
        }

        return DigestUtils.sha256Hex(getFullQualifiedUsername(username, userStoreDomain, tenantDomain));
    }

    /**
     * Constructs the fully qualified username.
     *
     * @param tenantAwareUsername Tenant-aware username.
     * @param userStoreDomain     User store domain.
     * @param tenantDomain       Tenant domain.
     * @return Fully qualified username.
     */
    private static String getFullQualifiedUsername(String tenantAwareUsername, String userStoreDomain,
                                                   String tenantDomain) {

        String fullyQualifiedUsername = UserCoreUtil.addDomainToName(tenantAwareUsername, userStoreDomain);
        fullyQualifiedUsername = UserCoreUtil.addTenantDomainToEntry(fullyQualifiedUsername, tenantDomain);
        return fullyQualifiedUsername;
    }

    /**
     * Resolves the session id from the properties map.
     *
     * @param properties Map of properties related to the event.
     * @return Resolved session id.
     * @throws IdentityFraudDetectorRequestException If an error occurs while resolving the session id.
     */
    protected static String resolveSessionId(Map<String, Object> properties)
            throws IdentityFraudDetectorRequestException {

        // TODO: Implement session id resolution logic.
        return null;
    }

    /**
     * Validates the mobile number format to be in E.164 format.
     *
     * @param mobileNumber Mobile number to be validated.
     * @return Validated mobile number if in E.164 format, null otherwise.
     */
    protected static String validateMobileNumberFormat(String mobileNumber) {

        if (StringUtils.isEmpty(mobileNumber)) {
            return null;
        }
        if (mobileNumber.matches(E164_REGEX)) {
            return mobileNumber;
        } else {
            LOG.debug("Mobile number: " + mobileNumber + " is not in E.164 format. Hence not " +
                    "adding to the payload.");
            return null;
        }
    }

    /**
     * Resolves the user attribute from the properties map.
     *
     * @param properties Map of properties related to the event.
     * @param claimUri   Claim URI of the user attribute to be resolved.
     * @return Resolved user attribute value.
     * @throws IdentityFraudDetectorRequestException If an error occurs while resolving the user attribute.
     */
    protected static String resolveUserAttribute(Map<String, Object> properties, String claimUri)
            throws IdentityFraudDetectorRequestException {

        return resolveUserAttribute(properties, claimUri, false);
    }

    /**
     * Resolves the user attribute from the properties map.
     *
     * @param properties     Map of properties related to the event.
     * @param claimUri       Claim URI of the user attribute to be resolved.
     * @param isIdentityClaim Flag indicating if the claim is an identity claim.
     * @return Resolved user attribute value.
     * @throws IdentityFraudDetectorRequestException If an error occurs while resolving the user attribute.
     */
    protected static String resolveUserAttribute(Map<String, Object> properties, String claimUri,
                                                 boolean isIdentityClaim)
            throws IdentityFraudDetectorRequestException {

        if (!isIdentityClaim && !isAllowUserInfoInPayload(properties)) {
            LOG.debug("Cannot resolve claim: " + claimUri + " as user info is not allowed in payload.");
            return null;
        }

        Map<String, String> userClaims = properties.get(USER_CLAIMS) != null ?
                (Map<String, String>) properties.get(USER_CLAIMS) : null;
        if (userClaims != null) {
            String claimValue = userClaims.get(claimUri);
            if (StringUtils.isNotEmpty(claimValue)) {
                return claimValue;
            }
        }
        try {
            String claimValue = getUserClaimValuesFromDB(properties, new String[]{claimUri}).get(claimUri);
            if (StringUtils.isNotEmpty(claimValue)) {
                addClaimToProperties(properties, claimUri, claimValue);
            }
            return claimValue;
        } catch (IdentityFraudDetectorRequestException e) {
            LOG.debug("Cannot resolve claim: " + claimUri + " from the user store.", e);
            return null;
        } catch (UserStoreException e) {
            if (e.getMessage().contains(ERROR_CODE_NON_EXISTING_USER.getCode())) {
                throw new IdentityFraudDetectorRequestException(e.getMessage());
            }
            return null;
        }
    }

    /**
     * Adds the resolved claim to the properties map.
     *
     * @param properties Map of properties related to the event.
     * @param claimUri   Claim URI of the user attribute.
     * @param claimValue Resolved claim value.
     */
    private static void addClaimToProperties(Map<String, Object> properties, String claimUri, String claimValue) {

        Map<String, String> userClaims = properties.get(USER_CLAIMS) != null ?
                (Map<String, String>) properties.get(USER_CLAIMS) : null;
        if (userClaims == null) {
            userClaims = new HashMap<>();
            properties.put(USER_CLAIMS, userClaims);
        }
        userClaims.put(claimUri, claimValue);
    }

    /**
     * Resolves the full name of the user from the properties map.
     *
     * @param properties Map of properties related to the event.
     * @return Resolved full name of the user.
     * @throws IdentityFraudDetectorRequestException If an error occurs while resolving the full name.
     */
    protected static String resolveFullName(Map<String, Object> properties)
            throws IdentityFraudDetectorRequestException {

        String fullName = resolveUserAttribute(properties, "http://wso2.org/claims/fullname");
        if (StringUtils.isNotEmpty(fullName)) {
            return fullName;
        }

        String firstname = resolveUserAttribute(properties, GIVEN_NAME);
        String lastname = resolveUserAttribute(properties, SURNAME);
        if (StringUtils.isNotEmpty(firstname) && StringUtils.isNotEmpty(lastname)) {
            return firstname + " " + lastname;
        } else if (StringUtils.isNotEmpty(firstname)) {
            return firstname;
        } else if (StringUtils.isNotEmpty(lastname)) {
            return lastname;
        }

        return null;
    }

    /**
     * Resolves the user agent from the properties map.
     *
     * @param properties Map of properties related to the event.
     * @return Resolved user agent.
     * @throws IdentityFraudDetectorRequestException If an error occurs while resolving the user agent.
     */
    protected static String resolveUserAgent(Map<String, Object> properties)
            throws IdentityFraudDetectorRequestException {

        if (!isAllowDeviceMetadataInPayload(properties)) {
            LOG.debug("Cannot resolve user agent as device metadata is not allowed in payload.");
            return null;
        }

        if (IdentityUtil.threadLocalProperties.get().containsKey("User-Agent-Of-User-Portal")) {
            return (String) IdentityUtil.threadLocalProperties.get().get("User-Agent-Of-User-Portal");
        } else if (IdentityUtil.threadLocalProperties.get().containsKey(USER_AGENT_HEADER)) {
            return (String) IdentityUtil.threadLocalProperties.get().get(USER_AGENT_HEADER);
        } else {
            return null;
        }
    }

    /**
     * Resolves the remote address from the properties map.
     *
     * @param properties Map of properties related to the event.
     * @return Resolved remote address.
     * @throws IdentityFraudDetectorRequestException If an error occurs while resolving the remote address.
     */
    protected static String resolveRemoteAddress(Map<String, Object> properties)
            throws IdentityFraudDetectorRequestException {

        if (!isAllowDeviceMetadataInPayload(properties)) {
            LOG.debug("Cannot resolve remote address as device metadata is not allowed in payload.");
            return null;
        }

        String ipAddress = (String) IdentityUtil.threadLocalProperties.get().get(REMOTE_ADDRESS);
        if (StringUtils.isNotEmpty(ipAddress)) {
            return ipAddress;
        } else {
            return null;
        }
    }

    /**
     * Retrieves user claim values from the user store.
     *
     * @param properties Map of properties related to the event.
     * @param claims     Array of claim URIs to be retrieved.
     * @return Map of claim URIs and their corresponding values.
     * @throws IdentityFraudDetectorRequestException If an error occurs while retrieving the claim values.
     * @throws UserStoreException                    If an error occurs in the user store.
     */
    private static Map<String, String> getUserClaimValuesFromDB(Map<String, Object> properties, String[] claims)
            throws IdentityFraudDetectorRequestException, UserStoreException {

        String username = properties.get(USER_NAME) != null ? (String) properties.get(USER_NAME) : null;
        String tenantDomain = properties.get(TENANT_DOMAIN) != null ? (String) properties.get(TENANT_DOMAIN) : null;
        String userStoreDomain = resolveUserStoreDomain(properties);

        return EventUtil.getUserClaimValues(username, tenantDomain, userStoreDomain, claims);
    }

    /**
     * Checks if user info is allowed in the payload based on tenant configuration.
     *
     * @param properties Map of properties related to the event.
     * @return true if user info is allowed in the payload, false otherwise.
     * @throws IdentityFraudDetectorRequestException If an error occurs while checking the configuration.
     */
    protected static boolean isAllowUserInfoInPayload(Map<String, Object> properties)
            throws IdentityFraudDetectorRequestException {

        String tenantDomain = properties.get(TENANT_DOMAIN) != null ?
                (String) properties.get(TENANT_DOMAIN) : null;
        if (StringUtils.isEmpty(tenantDomain)) {
            throw new IdentityFraudDetectorRequestException("Cannot check allow user info in payload. " +
                    "Tenant domain is null.");
        }

        try {
            return EventUtil.isAllowUserInfoInPayload(tenantDomain);
        } catch (FraudDetectionConfigServerException e) {
            throw new IdentityFraudDetectorRequestException("Error while retrieving fraud detection config for tenant: "
                    + tenantDomain, e);
        }
    }

    /**
     * Checks if user info is allowed in the payload based on tenant configuration.
     *
     * @param properties Map of properties related to the event.
     * @return true if user info is allowed in the payload, false otherwise.
     * @throws IdentityFraudDetectorRequestException If an error occurs while checking the configuration.
     */
    protected static boolean isAllowDeviceMetadataInPayload(Map<String, Object> properties)
            throws IdentityFraudDetectorRequestException {

        String tenantDomain = properties.get(TENANT_DOMAIN) != null ?
                (String) properties.get(TENANT_DOMAIN) : null;
        if (StringUtils.isEmpty(tenantDomain)) {
            throw new IdentityFraudDetectorRequestException("Cannot check allow device metadata in payload. " +
                    "Tenant domain is null.");
        }

        try {
            return EventUtil.isAllowDeviceMetadataInPayload(tenantDomain);
        } catch (FraudDetectionConfigServerException e) {
            throw new IdentityFraudDetectorRequestException("Error while retrieving fraud detection config for tenant: "
                    + tenantDomain, e);
        }
    }
}
