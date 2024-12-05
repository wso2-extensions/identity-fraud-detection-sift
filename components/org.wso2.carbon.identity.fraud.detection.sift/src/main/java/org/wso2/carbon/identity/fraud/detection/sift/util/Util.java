/*
 * Copyright (c) 2024, WSO2 LLC. (https://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.fraud.detection.sift.util;

import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.json.JSONObject;
import org.wso2.carbon.identity.application.authentication.framework.config.model.graph.js.JsAuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.config.model.graph.js.graaljs.JsGraalAuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.context.TransientObjectWrapper;
import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;
import org.wso2.carbon.identity.application.authentication.framework.exception.UserIdNotFoundException;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.fraud.detection.sift.Constants;
import org.wso2.carbon.identity.fraud.detection.sift.internal.SiftDataHolder;
import org.wso2.carbon.identity.governance.IdentityGovernanceException;
import org.wso2.carbon.identity.governance.IdentityGovernanceService;
import org.wso2.carbon.identity.governance.bean.ConnectorConfig;

import java.util.HashMap;
import java.util.Map;

import javax.servlet.http.HttpServletRequestWrapper;

import static org.wso2.carbon.identity.fraud.detection.sift.Constants.CONNECTOR_NAME;
import static org.wso2.carbon.identity.fraud.detection.sift.Constants.HTTP_SERVLET_REQUEST;
import static org.wso2.carbon.identity.fraud.detection.sift.Constants.LOGIN_TYPE;
import static org.wso2.carbon.identity.fraud.detection.sift.Constants.SIFT_API_KEY_PROP;
import static org.wso2.carbon.identity.fraud.detection.sift.Constants.USER_AGENT_HEADER;

/**
 * Util class to build the payload to be sent to Sift.
 */
public class Util {

    private static final Log LOG = LogFactory.getLog(Util.class);

    public static JSONObject buildPayload(JsAuthenticationContext context, String loginStatus,
                                          Map<String, Object> passedCustomParams)
            throws FrameworkException {

        String loginSts = getLoginStatus(loginStatus).getSiftValue();


        JSONObject payload = new JSONObject();

        // Add the required parameters to the payload.
        payload.put(Constants.TYPE, LOGIN_TYPE);
        payload.put(Constants.API_KEY, getSiftApiKey(context.getWrapped().getTenantDomain()));
        payload.put(Constants.LOGIN_STATUS, loginSts);
        payload.put(Constants.USER_ID_KEY, resolvePayloadData(Constants.USER_ID_KEY, context));

        Map<String, String> browserProperties = new HashMap<>();
        browserProperties.put(Constants.USER_AGENT_KEY, resolvePayloadData(Constants.USER_AGENT_KEY, context));
        payload.put(Constants.BROWSER_KEY, browserProperties);

        payload.put(Constants.IP_KEY, resolvePayloadData(Constants.IP_KEY, context));

        payload.put(Constants.SESSION_ID_KEY, resolvePayloadData(Constants.SESSION_ID_KEY, context));

        processDefaultParameters(passedCustomParams, payload);

        if (passedCustomParams != null) {
            for (Map.Entry<String, Object> entry : passedCustomParams.entrySet()) {
                payload.put(entry.getKey(), entry.getValue());
            }
        }
        return payload;
    }

    // Process the default parameters and remove them from the custom parameters. If the default parameters are
    // passed as empty values, remove them from the payload.
    private static void processDefaultParameters(Map<String, Object> passedCustomParams, JSONObject payload) {

        if (passedCustomParams != null) {

            if (passedCustomParams.containsKey(Constants.IP_KEY)) {
                String ip = (String) passedCustomParams.get(Constants.IP_KEY);
                if (StringUtils.isNotBlank(ip)) {
                    payload.put(Constants.IP_KEY, ip);
                } else {
                    payload.remove(Constants.IP_KEY);
                }
                passedCustomParams.remove(Constants.IP_KEY);
            }

            if (passedCustomParams.containsKey(Constants.SESSION_ID_KEY)) {
                String sessionId = (String) passedCustomParams.get(Constants.SESSION_ID_KEY);
                if (StringUtils.isNotBlank(sessionId)) {
                    payload.put(Constants.SESSION_ID_KEY, sessionId);
                } else {
                    payload.remove(Constants.SESSION_ID_KEY);
                }
                passedCustomParams.remove(Constants.SESSION_ID_KEY);
            }

            if (passedCustomParams.containsKey(Constants.USER_AGENT_KEY)) {
                String userAgent = (String) passedCustomParams.get(Constants.USER_AGENT_KEY);
                if (StringUtils.isNotBlank(userAgent)) {
                    Map<String, String> browserProperties = new HashMap<>();
                    browserProperties.put(Constants.USER_AGENT_KEY, userAgent);
                    payload.put(Constants.BROWSER_KEY, browserProperties);
                } else {
                    payload.remove(Constants.BROWSER_KEY);
                }
                passedCustomParams.remove(Constants.USER_AGENT_KEY);
            }

            // As the user_id is a mandatory field, it shouldn't be removed from the payload.
            if (passedCustomParams.containsKey(Constants.USER_ID_KEY)) {
                String userId = (String) passedCustomParams.get(Constants.USER_ID_KEY);
                if (StringUtils.isNotBlank(userId)) {
                    payload.put(Constants.USER_ID_KEY, userId);
                }
                passedCustomParams.remove(Constants.USER_ID_KEY);
            }
        }
    }

    public static Map<String, Object> getPassedCustomParams(Object[] paramMap) {

        Map<String, Object> passedCustomParams = null;
        if (paramMap.length == 1) {
            if (paramMap[0] instanceof Map) {
                passedCustomParams = (Map<String, Object>) paramMap[0];
            } else {
                throw new IllegalArgumentException("Invalid argument type. Expected paramMap " +
                        "(Map<String, Object>).");
            }
        }
        return passedCustomParams;
    }

    private static String getSiftApiKey(String tenantDomain) throws FrameworkException {

        String apiKey = getSiftConfigs(tenantDomain).get(SIFT_API_KEY_PROP);
        if (apiKey == null) {
            throw new FrameworkException("Sift API key not found for tenant: " + tenantDomain);
        }
        return apiKey;
    }

    static Map<String, String> getSiftConfigs(String tenantDomain) throws FrameworkException {

        try {
            ConnectorConfig connectorConfig =
                    getIdentityGovernanceService().getConnectorWithConfigs(tenantDomain, CONNECTOR_NAME);
            if (connectorConfig == null) {
                throw new FrameworkException("Sift configurations not found for tenant: " + tenantDomain);
            }
            Map<String, String> siftConfigs = new HashMap<>();
            // Go through the connector config and get the sift configurations.
            for (Property prop : connectorConfig.getProperties()) {
                siftConfigs.put(prop.getName(), prop.getValue());
            }

            return siftConfigs;
        } catch (IdentityGovernanceException e) {
            throw new FrameworkException("Error while retrieving sift configurations: " + e.getMessage());
        }

    }

    public static String getMaskedSiftPayload(JSONObject payload) {

        JSONObject maskedPayload = new JSONObject(payload.toString());
        String apiKey = (String) maskedPayload.get(Constants.API_KEY);

        // Masked half of the API key for logging.
        int length = apiKey.length();
        int maskStart = length / 2;
        StringBuilder maskedAPIKey = new StringBuilder(apiKey.substring(0, maskStart));
        for (int i = maskStart; i < length; i++) {
            maskedAPIKey.append('*');
        }

        maskedPayload.put(Constants.API_KEY, maskedAPIKey.toString());
        return maskedPayload.toString();

    }

    private static IdentityGovernanceService getIdentityGovernanceService() {

        return SiftDataHolder.getInstance().getIdentityGovernanceService();
    }

    private static Constants.LoginStatus getLoginStatus(String status) {

        if (Constants.LoginStatus.LOGIN_SUCCESS.getStatus().equalsIgnoreCase(status)) {
            return Constants.LoginStatus.LOGIN_SUCCESS;
        } else if (Constants.LoginStatus.LOGIN_FAILED.getStatus().equalsIgnoreCase(status)) {
            return Constants.LoginStatus.LOGIN_FAILED;
        } else {
            throw new IllegalArgumentException("Invalid login status: " + status);
        }
    }

    private static String resolvePayloadData(String key, JsAuthenticationContext context) throws FrameworkException {

        switch (key) {
            case Constants.USER_ID_KEY:
                return getHashedUserId(context);
            case Constants.USER_AGENT_KEY:
                return getUserAgent(context);
            case Constants.IP_KEY:
                return getIpAddress(context);
            case Constants.SESSION_ID_KEY:
                return generateSessionHash(context);
            default:
                return null;
        }
    }

    private static String getHashedUserId(JsAuthenticationContext context) {

        try {
            String userId = ((JsGraalAuthenticatedUser) context.getMember(Constants.CURRENT_KNOWN_SUBJECT))
                    .getWrapped().getUserId();
            return DigestUtils.sha256Hex(userId);
        } catch (UserIdNotFoundException e) {
            LOG.debug("Unable to resolve the user id.", e);
            return null;
        }
    }

    private static String getUserAgent(JsAuthenticationContext context) {

        Object httpServletRequest = ((TransientObjectWrapper<?>) context.getWrapped().getParameter
                (HTTP_SERVLET_REQUEST)).getWrapped();
        if (httpServletRequest instanceof HttpServletRequestWrapper) {
            HttpServletRequestWrapper httpServletRequestWrapper = (HttpServletRequestWrapper) httpServletRequest;
            return httpServletRequestWrapper.getHeader(USER_AGENT_HEADER);
        }
        return null;
    }

    private static String getIpAddress(JsAuthenticationContext context) {

        Object httpServletRequest = ((TransientObjectWrapper<?>) context.getWrapped().getParameter
                (HTTP_SERVLET_REQUEST)).getWrapped();
        if (httpServletRequest instanceof HttpServletRequestWrapper) {
            HttpServletRequestWrapper authenticationFrameworkWrapper = (HttpServletRequestWrapper) httpServletRequest;
            return authenticationFrameworkWrapper.getRemoteAddr();
        }
        return null;
    }

    public static boolean isLoggingEnabled(Map<String, Object> passedCustomParams) {

        boolean isLoggingEnabled = false;
        if (passedCustomParams != null) {
            isLoggingEnabled = passedCustomParams.containsKey(Constants.LOGGING_ENABLED) &&
                    (Boolean) passedCustomParams.get(Constants.LOGGING_ENABLED);
            passedCustomParams.remove(Constants.LOGGING_ENABLED);
        }
        return isLoggingEnabled;
    }

    private static String generateSessionHash(JsAuthenticationContext context) throws FrameworkException {

        if (context.getWrapped().getContextIdentifier() == null) {
            throw new FrameworkException("Context identifier is null.");
        }
        return DigestUtils.sha256Hex(context.getWrapped().getContextIdentifier());
    }
}
