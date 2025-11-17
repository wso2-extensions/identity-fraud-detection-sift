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
import com.siftscience.model.EventResponseBody;
import com.siftscience.model.LogoutFieldSet;
import org.apache.commons.codec.digest.DigestUtils;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.context.SessionContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;
import org.wso2.carbon.identity.fraud.detection.core.constant.FraudDetectionConstants;
import org.wso2.carbon.identity.fraud.detection.core.exception.IdentityFraudDetectionRequestException;
import org.wso2.carbon.identity.fraud.detection.core.exception.IdentityFraudDetectionResponseException;
import org.wso2.carbon.identity.fraud.detection.core.model.FraudDetectorResponseDTO;
import org.wso2.carbon.identity.fraud.detection.sift.models.SiftFraudDetectorRequestDTO;
import org.wso2.carbon.identity.fraud.detection.sift.models.SiftFraudDetectorResponseDTO;

import java.util.Map;

import static org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants.AUTHENTICATED_USER;
import static org.wso2.carbon.identity.event.IdentityEventConstants.EventProperty.CONTEXT;
import static org.wso2.carbon.identity.event.IdentityEventConstants.EventProperty.SESSION_CONTEXT;
import static org.wso2.carbon.identity.event.IdentityEventConstants.EventProperty.TENANT_DOMAIN;
import static org.wso2.carbon.identity.fraud.detection.sift.Constants.LOGOUT_TRIGGERED_FROM_APPLICATION;
import static org.wso2.carbon.identity.fraud.detection.sift.Constants.USER_UUID;
import static org.wso2.carbon.identity.fraud.detection.sift.util.SiftEventUtil.resolveBrowser;
import static org.wso2.carbon.identity.fraud.detection.sift.util.SiftEventUtil.resolveUserAgent;
import static org.wso2.carbon.identity.fraud.detection.sift.util.SiftEventUtil.resolveUserUUID;
import static org.wso2.carbon.identity.fraud.detection.sift.util.Util.setAPIKey;

/**
 * Utility class for handling Sift logout events.
 */
public class SiftLogoutEventUtil {

    /**
     * Builds the logout event payload for Sift.
     *
     * @param requestDTO Sift fraud detector request DTO.
     * @return JSON string of the logout event payload.
     * @throws IdentityFraudDetectionRequestException if an error occurs while building the payload.
     */
    public static String handleLogoutEventPayload(SiftFraudDetectorRequestDTO requestDTO)
            throws IdentityFraudDetectionRequestException {

        Map<String, Object> properties = requestDTO.getProperties();
        String tenantDomain = (String) properties.get(TENANT_DOMAIN);
        AuthenticationContext authenticationContext = (AuthenticationContext) properties.get(CONTEXT);
        SessionContext sessionContext = (SessionContext) properties.get(SESSION_CONTEXT);
        boolean isLogoutTriggeredFromApplication = authenticationContext != null;
        try {
            LogoutFieldSet logoutFieldSet = new LogoutFieldSet()
                    .setUserId(resolveUserId(sessionContext))
                    .setBrowser(resolveBrowser(resolveUserAgent(properties)))
                    .setIp(SiftEventUtil.resolveRemoteAddress(properties))
                    .setCustomField(LOGOUT_TRIGGERED_FROM_APPLICATION, isLogoutTriggeredFromApplication)
                    .setCustomField(USER_UUID, resolveUserUUID(properties));
            logoutFieldSet.validate();
            return setAPIKey(logoutFieldSet, tenantDomain);
        } catch (InvalidFieldException e) {
            throw new IdentityFraudDetectionRequestException("Error while building logout event payload: "
                    + e.getMessage(), e);
        } catch (FrameworkException e) {
            throw new IdentityFraudDetectionRequestException("Error while resolving payload data: "
                    + e.getMessage(), e);
        }
    }

    /**
     * Handles the logout event response from Sift.
     *
     * @param responseContent JSON string of the response content from Sift.
     * @param requestDTO      Sift fraud detector request DTO.
     * @return Sift fraud detector response DTO.
     * @throws IdentityFraudDetectionResponseException if an error occurs while handling the response.
     */
    public static FraudDetectorResponseDTO handleLogoutResponse(String responseContent,
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
     * Resolves the user ID from the session context.
     *
     * @param sessionContext Session context.
     * @return Resolved user ID.
     * @throws FrameworkException                       if an error occurs while accessing the session context.
     * @throws IdentityFraudDetectionRequestException    if the user ID cannot be resolved.
     */
    private static String resolveUserId(SessionContext sessionContext)
            throws FrameworkException, IdentityFraudDetectionRequestException {

        if (sessionContext == null) {
            throw new IdentityFraudDetectionRequestException("Cannot resolve payload data. Both authentication " +
                    "context and session context are null.");
        }
        if (sessionContext.getProperties().containsKey(AUTHENTICATED_USER)) {
            return DigestUtils.sha256Hex(sessionContext.getProperties().get(AUTHENTICATED_USER).toString());
        } else {
            throw new IdentityFraudDetectionRequestException("Cannot resolve payload data. Authenticated user is not " +
                    "available in the session context.");
        }
    }
}
