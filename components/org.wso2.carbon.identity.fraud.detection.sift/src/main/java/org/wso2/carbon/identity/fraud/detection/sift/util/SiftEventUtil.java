package org.wso2.carbon.identity.fraud.detection.sift.util;

import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.HttpEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.util.EntityUtils;
import org.wso2.carbon.identity.application.common.model.User;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.fraud.detection.sift.exception.SiftUnsupportedEventException;
import org.wso2.carbon.identity.fraud.detection.sift.models.SiftFraudDetectorRequestDTO;
import org.wso2.carbon.identity.fraud.detectors.core.exception.FraudDetectionConfigServerException;
import org.wso2.carbon.identity.fraud.detectors.core.exception.IdentityFraudDetectorException;
import org.wso2.carbon.identity.fraud.detectors.core.exception.IdentityFraudDetectorRequestException;
import org.wso2.carbon.identity.fraud.detectors.core.exception.IdentityFraudDetectorResponseException;
import org.wso2.carbon.identity.fraud.detectors.core.model.FraudDetectorRequestDTO;
import org.wso2.carbon.identity.fraud.detectors.core.model.FraudDetectorResponseDTO;
import org.wso2.carbon.identity.fraud.detectors.core.util.EventUtil;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.user.core.util.UserCoreUtil;

import java.io.IOException;
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

public class SiftEventUtil {

    private static final Log LOG = LogFactory.getLog(SiftEventUtil.class);
    private static final String E164_REGEX = "^\\+[1-9]\\d{1,14}$";

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
            case NOTIFICATION_BASED_VERIFICATION:
                return SiftVerificationEventUtil.handleVerificationEventPayload(requestDTO);
            case POST_UPDATE_USER_PROFILE:
                return SiftUserProfileUpdateEventUtil.handlePostUserProfileUpdateEventPayload(requestDTO);
            default:
                throw new SiftUnsupportedEventException("Unsupported event name by Sift: "
                        + requestDTO.getEventName());
        }
    }

    public static FraudDetectorResponseDTO handleResponse(CloseableHttpResponse closeableHttpResponse,
                                                          FraudDetectorRequestDTO requestDTO)
            throws IdentityFraudDetectorResponseException, SiftUnsupportedEventException {

        String responseContent = getResponseContent(closeableHttpResponse);
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
            case NOTIFICATION_BASED_VERIFICATION:
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

    private static String getResponseContent(CloseableHttpResponse closeableHttpResponse)
            throws IdentityFraudDetectorResponseException {

        String responseContent;
        try {
            HttpEntity entity = closeableHttpResponse.getEntity();
            if (entity == null) {
                throw new IdentityFraudDetectorResponseException("Error occurred while reading response from Sift. " +
                        "Response entity is null.");
            }
            responseContent = EntityUtils.toString(entity);
            if (StringUtils.isBlank(responseContent)) {
                throw new IdentityFraudDetectorResponseException("Error occurred while reading response from Sift. " +
                        "Response content is empty.");
            }
            return responseContent;
        } catch (IOException e) {
            throw new IdentityFraudDetectorResponseException("Error occurred while reading response from Sift.", e);
        }
    }

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

    private static String getFullQualifiedUsername(String tenantAwareUsername, String userStoreDomain,
                                                   String tenantDomain) {

        String fullyQualifiedUsername = UserCoreUtil.addDomainToName(tenantAwareUsername, userStoreDomain);
        fullyQualifiedUsername = UserCoreUtil.addTenantDomainToEntry(fullyQualifiedUsername, tenantDomain);
        return fullyQualifiedUsername;
    }

    protected static String resolveSessionId(Map<String, Object> properties)
            throws IdentityFraudDetectorRequestException {

        // TODO: Implement session id resolution logic.
        return null;
    }

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

    protected static String resolveUserClaim(Map<String, Object> properties, String claimUri)
            throws IdentityFraudDetectorRequestException {

        if (!isAllowUserInfoInPayload(properties)) {
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
        }
    }

    private static void addClaimToProperties(Map<String, Object> properties, String claimUri, String claimValue) {

        Map<String, String> userClaims = properties.get(USER_CLAIMS) != null ?
                (Map<String, String>) properties.get(USER_CLAIMS) : null;
        if (userClaims == null) {
            userClaims = new HashMap<>();
            properties.put(USER_CLAIMS, userClaims);
        }
        userClaims.put(claimUri, claimValue);
    }

    protected static String resolveFullName(Map<String, Object> properties)
            throws IdentityFraudDetectorRequestException {

        String fullName = resolveUserClaim(properties, "http://wso2.org/claims/fullname");
        if (StringUtils.isNotEmpty(fullName)) {
            return fullName;
        }

        String firstname = resolveUserClaim(properties, GIVEN_NAME);
        String lastname = resolveUserClaim(properties, SURNAME);
        if (StringUtils.isNotEmpty(firstname) && StringUtils.isNotEmpty(lastname)) {
            return firstname + " " + lastname;
        } else if (StringUtils.isNotEmpty(firstname)) {
            return firstname;
        } else if (StringUtils.isNotEmpty(lastname)) {
            return lastname;
        }

        return null;
    }

    protected static String resolveUserAgent() throws IdentityFraudDetectorRequestException {

        String userAgent = (String) IdentityUtil.threadLocalProperties.get().get(USER_AGENT_HEADER);
        if (StringUtils.isNotEmpty(userAgent)) {
            return userAgent;
        } else {
            throw new IdentityFraudDetectorRequestException("Cannot resolve user agent. User agent is null.");
        }
    }

    protected static String resolveRemoteAddress() throws IdentityFraudDetectorRequestException {

        String ipAddress = (String) IdentityUtil.threadLocalProperties.get().get(REMOTE_ADDRESS);
        if (StringUtils.isNotEmpty(ipAddress)) {
            return ipAddress;
        } else {
            throw new IdentityFraudDetectorRequestException("Cannot resolve IP address. IP address is null.");
        }
    }

    private static Map<String, String> getUserClaimValuesFromDB(Map<String, Object> properties, String[] claims)
            throws IdentityFraudDetectorRequestException {

        String username = properties.get(USER_NAME) != null ? (String) properties.get(USER_NAME) : null;
        String tenantDomain = properties.get(TENANT_DOMAIN) != null ? (String) properties.get(TENANT_DOMAIN) : null;
        String userStoreDomain = resolveUserStoreDomain(properties);

        try {
            return EventUtil.getUserClaimValues(username, tenantDomain, userStoreDomain, claims);
        } catch (IdentityFraudDetectorException e) {
            throw new IdentityFraudDetectorRequestException("Error while retrieving user claim values for user: "
                    + username, e);
        }
    }

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
}
