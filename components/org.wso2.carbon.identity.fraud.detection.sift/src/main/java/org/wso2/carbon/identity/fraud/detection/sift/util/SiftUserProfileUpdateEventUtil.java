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
import com.siftscience.model.UpdateAccountFieldSet;
import org.wso2.carbon.identity.fraud.detection.sift.models.SiftFraudDetectorRequestDTO;
import org.wso2.carbon.identity.fraud.detection.sift.models.SiftFraudDetectorResponseDTO;
import org.wso2.carbon.identity.fraud.detection.core.constant.FraudDetectionConstants;
import org.wso2.carbon.identity.fraud.detection.core.exception.IdentityFraudDetectionRequestException;
import org.wso2.carbon.identity.fraud.detection.core.exception.IdentityFraudDetectionResponseException;
import org.wso2.carbon.identity.fraud.detection.core.model.FraudDetectorRequestDTO;
import org.wso2.carbon.identity.fraud.detection.core.model.FraudDetectorResponseDTO;
import org.wso2.carbon.user.core.UserCoreConstants;

import java.util.Map;

import static org.wso2.carbon.identity.event.IdentityEventConstants.EventProperty.SCENARIO;
import static org.wso2.carbon.identity.event.IdentityEventConstants.EventProperty.TENANT_DOMAIN;
import static org.wso2.carbon.identity.fraud.detection.sift.util.SiftEventUtil.resolveFullName;
import static org.wso2.carbon.identity.fraud.detection.sift.util.SiftEventUtil.resolveRemoteAddress;
import static org.wso2.carbon.identity.fraud.detection.sift.util.SiftEventUtil.resolveSessionId;
import static org.wso2.carbon.identity.fraud.detection.sift.util.SiftEventUtil.resolveUserAgent;
import static org.wso2.carbon.identity.fraud.detection.sift.util.SiftEventUtil.resolveUserAttribute;
import static org.wso2.carbon.identity.fraud.detection.sift.util.SiftEventUtil.resolveUserId;
import static org.wso2.carbon.identity.fraud.detection.sift.util.SiftEventUtil.validateMobileNumberFormat;
import static org.wso2.carbon.identity.fraud.detection.sift.util.Util.setAPIKey;

/**
 * Utility class for handling Sift user profile update events.
 */
public class SiftUserProfileUpdateEventUtil {

    /**
     * Builds the user profile update event payload for Sift.
     *
     * @param requestDTO Fraud detector request DTO.
     * @return JSON string of the user profile update event payload.
     * @throws IdentityFraudDetectionRequestException if an error occurs while building the payload.
     */
    public static String handlePostUserProfileUpdateEventPayload(FraudDetectorRequestDTO requestDTO)
            throws IdentityFraudDetectionRequestException {

        Map<String, Object> properties = requestDTO.getProperties();
        String tenantDomain = (String) properties.get(TENANT_DOMAIN);

        try {
            String validatedMobileNumber = validateMobileNumberFormat(
                    resolveUserAttribute(properties, UserCoreConstants.ClaimTypeURIs.MOBILE));
            UpdateAccountFieldSet fieldSet = new UpdateAccountFieldSet()
                    .setUserId(resolveUserId(properties))
                    .setSessionId(resolveSessionId(properties))
                    .setUserEmail(resolveUserAttribute(properties, UserCoreConstants.ClaimTypeURIs.EMAIL_ADDRESS))
                    .setVerificationPhoneNumber(validatedMobileNumber)
                    .setPhone(validatedMobileNumber)
                    .setName(resolveFullName(properties))
                    .setBrowser(new Browser().setUserAgent(resolveUserAgent(properties)))
                    .setIp(resolveRemoteAddress(properties))
                    .setCustomField("is_user_profile_updated_by_admin", isProfileUpdateByAdmin(properties));
            fieldSet.validate();
            return setAPIKey(fieldSet, tenantDomain);
        } catch (InvalidFieldException e) {
            throw new IdentityFraudDetectionRequestException("Error while building user profile update event payload: "
                    + e.getMessage(), e);
        }
    }

    /**
     * Handles the user profile update event response from Sift.
     *
     * @param responseContent JSON string of the response content from Sift.
     * @param requestDTO      Sift fraud detector request DTO.
     * @return Sift fraud detector response DTO.
     * @throws IdentityFraudDetectionResponseException if an error occurs while handling the response.
     */
    public static FraudDetectorResponseDTO handlePostUserProfileUpdateResponse(String responseContent,
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
     * Determines if the profile update was performed by an admin.
     *
     * @param properties Map of event properties.
     * @return true if updated by admin, false if by user.
     * @throws IdentityFraudDetectionRequestException if the scenario is invalid.
     */
    private static boolean isProfileUpdateByAdmin(Map<String, Object> properties)
            throws IdentityFraudDetectionRequestException {

        String scenario = (String) properties.get(SCENARIO);
        if ("POST_USER_PROFILE_UPDATE_BY_ADMIN".equals(scenario)) {
            return true;
        } else if ("POST_USER_PROFILE_UPDATE_BY_USER".equals(scenario)) {
            return false;
        }

        throw new IdentityFraudDetectionRequestException("Unable to determine profile update initiator. " +
                "Invalid scenario: " + scenario);
    }

}
