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
import com.siftscience.model.CreateAccountFieldSet;
import com.siftscience.model.EventResponseBody;
import org.wso2.carbon.identity.fraud.detection.core.constant.FraudDetectionConstants;
import org.wso2.carbon.identity.fraud.detection.core.exception.IdentityFraudDetectionRequestException;
import org.wso2.carbon.identity.fraud.detection.core.exception.IdentityFraudDetectionResponseException;
import org.wso2.carbon.identity.fraud.detection.core.model.FraudDetectorRequestDTO;
import org.wso2.carbon.identity.fraud.detection.core.model.FraudDetectorResponseDTO;
import org.wso2.carbon.identity.fraud.detection.sift.models.SiftFraudDetectorRequestDTO;
import org.wso2.carbon.identity.fraud.detection.sift.models.SiftFraudDetectorResponseDTO;
import org.wso2.carbon.user.core.UserCoreConstants;

import java.util.Map;

import static org.wso2.carbon.identity.event.IdentityEventConstants.EventProperty.TENANT_DOMAIN;
import static org.wso2.carbon.identity.fraud.detection.sift.Constants.USER_CREATED_BY_ADMIN;
import static org.wso2.carbon.identity.fraud.detection.sift.Constants.USER_SELF_REGISTRATION_FLOW;
import static org.wso2.carbon.identity.fraud.detection.sift.Constants.USER_UUID;
import static org.wso2.carbon.identity.fraud.detection.sift.util.SiftEventUtil.resolveFullName;
import static org.wso2.carbon.identity.fraud.detection.sift.util.SiftEventUtil.resolveRemoteAddress;
import static org.wso2.carbon.identity.fraud.detection.sift.util.SiftEventUtil.resolveUserAgent;
import static org.wso2.carbon.identity.fraud.detection.sift.util.SiftEventUtil.resolveUserAttribute;
import static org.wso2.carbon.identity.fraud.detection.sift.util.SiftEventUtil.resolveUserId;
import static org.wso2.carbon.identity.fraud.detection.sift.util.SiftEventUtil.resolveUserUUID;
import static org.wso2.carbon.identity.fraud.detection.sift.util.SiftEventUtil.validateMobileNumberFormat;
import static org.wso2.carbon.identity.fraud.detection.sift.util.Util.setAPIKey;

/**
 * Utility class for handling Sift user registration events.
 */
public class SiftUserRegistrationEventUtil {

    /**
     * Builds the user registration event payload for Sift.
     *
     * @param requestDTO Fraud detector request DTO.
     * @return JSON string of the user registration event payload.
     * @throws IdentityFraudDetectionRequestException if an error occurs while building the payload.
     */
    public static String handlePostUserRegistrationEventPayload(FraudDetectorRequestDTO requestDTO)
            throws IdentityFraudDetectionRequestException {

        Map<String, Object> properties = requestDTO.getProperties();
        String tenantDomain = (String) properties.get(TENANT_DOMAIN);

        try {
            String validatedMobileNumber = validateMobileNumberFormat(
                    resolveUserAttribute(properties, UserCoreConstants.ClaimTypeURIs.MOBILE));
            CreateAccountFieldSet fieldSet = new CreateAccountFieldSet()
                    .setUserId(resolveUserId(properties))
                    .setBrowser(new Browser().setUserAgent(resolveUserAgent(properties)))
                    .setIp(resolveRemoteAddress(properties))
                    .setUserEmail(resolveUserAttribute(properties, UserCoreConstants.ClaimTypeURIs.EMAIL_ADDRESS))
                    .setPhone(validatedMobileNumber)
                    .setVerificationPhoneNumber(validatedMobileNumber)
                    .setName(resolveFullName(properties))
                    .setCustomField(USER_CREATED_BY_ADMIN, !resolveIsSelfRegistrationFlow(properties))
                    .setCustomField(USER_UUID, resolveUserUUID(properties));
            fieldSet.validate();
            return setAPIKey(fieldSet, tenantDomain);
        } catch (InvalidFieldException e) {
            throw new IdentityFraudDetectionRequestException("Error while building user registration event payload: "
                    + e.getMessage(), e);
        }
    }

    /**
     * Handles the user registration event response from Sift.
     *
     * @param responseContent JSON string of the response content from Sift.
     * @param requestDTO      Sift fraud detector request DTO.
     * @return Sift fraud detector response DTO.
     * @throws IdentityFraudDetectionResponseException if an error occurs while handling the response.
     */
    public static FraudDetectorResponseDTO handlePostUserRegistrationResponse(String responseContent,
                                                                              SiftFraudDetectorRequestDTO requestDTO)
            throws IdentityFraudDetectionResponseException {

        EventResponseBody responseBody = EventResponseBody.fromJson(responseContent);
        FraudDetectionConstants.FraudDetectionEvents eventName = requestDTO.getEventName();
        if (responseBody.getStatus() != 0) {
            throw new IdentityFraudDetectionResponseException("Error occurred while publishing event to Sift. " +
                    "Returned Sift status code: " + responseBody.getStatus() + " for event: " + eventName.name());
        }
        return new SiftFraudDetectorResponseDTO(FraudDetectionConstants.ExecutionStatus.SUCCESS, eventName);
    }

    /**
     * Resolves whether the user registration flow is a self-registration flow.
     *
     * @param properties Map of properties.
     * @return true if it is a self-registration flow, false otherwise.
     */
    private static boolean resolveIsSelfRegistrationFlow(Map<String, Object> properties) {

        return properties.containsKey(USER_SELF_REGISTRATION_FLOW)
                && (Boolean) properties.get(USER_SELF_REGISTRATION_FLOW);
    }
}
