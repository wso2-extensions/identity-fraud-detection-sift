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
package org.wso2.carbon.identity.fraud.detection.sift;

import org.apache.commons.lang.StringUtils;
import org.apache.http.HttpStatus;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.json.JSONObject;
import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.fraud.detection.sift.models.SiftFraudDetectorRequestDTO;
import org.wso2.carbon.identity.fraud.detection.sift.util.SiftEventUtil;
import org.wso2.carbon.identity.fraud.detection.sift.util.SiftLogUtil;
import org.wso2.carbon.identity.fraud.detection.sift.util.Util;
import org.wso2.carbon.identity.fraud.detectors.core.AbstractIdentityFraudDetector;
import org.wso2.carbon.identity.fraud.detectors.core.IdentityFraudDetector;
import org.wso2.carbon.identity.fraud.detectors.core.exception.IdentityFraudDetectorException;
import org.wso2.carbon.identity.fraud.detectors.core.exception.IdentityFraudDetectorResponseException;
import org.wso2.carbon.identity.fraud.detectors.core.model.FraudDetectorRequestDTO;
import org.wso2.carbon.identity.fraud.detectors.core.model.FraudDetectorResponseDTO;

/**
 * Implementation of Sift Fraud Detector.
 */
public class SiftFraudDetector extends AbstractIdentityFraudDetector implements IdentityFraudDetector {

    @Override
    public String getName() {

        return "SiftFraudDetector";
    }

    @Override
    public boolean canHandle(String tenantDomain) {

        try {
            return StringUtils.isNotEmpty(Util.getSiftApiKey(tenantDomain));
        } catch (FrameworkException e) {
            return false;
        }
    }

    @Override
    public FraudDetectorResponseDTO publishRequest(FraudDetectorRequestDTO fraudDetectorRequestDTO) {

        if (fraudDetectorRequestDTO instanceof SiftFraudDetectorRequestDTO) {
            return super.publishRequest(fraudDetectorRequestDTO);
        }
        return super.publishRequest(convertToSiftRequestDTO(fraudDetectorRequestDTO));
    }

    @Override
    public HttpUriRequest buildRequest(FraudDetectorRequestDTO fraudDetectorRequestDTO)
            throws IdentityFraudDetectorException {

        String payload = SiftEventUtil.buildSiftEventPayload((SiftFraudDetectorRequestDTO) fraudDetectorRequestDTO);
        String siftRequestPath = Util.buildSiftRequestPath((SiftFraudDetectorRequestDTO) fraudDetectorRequestDTO);

        HttpPost request = new HttpPost(siftRequestPath);
        request.addHeader(Constants.CONTENT_TYPE_HEADER, FrameworkConstants.ContentTypes.TYPE_APPLICATION_JSON);
        StringEntity entity = new StringEntity(payload, ContentType.APPLICATION_JSON);
        request.setEntity(entity);
        return request;
    }

    @Override
    public FraudDetectorResponseDTO handleResponse(int responseStatusCode, String responseContent,
                                                   FraudDetectorRequestDTO requestDTO)
            throws IdentityFraudDetectorException {

        if (responseStatusCode != HttpStatus.SC_OK) {
            throw new IdentityFraudDetectorResponseException("Error occurred while publishing event to Sift. " +
                    "HTTP error code: " + responseStatusCode);
        }

        return SiftEventUtil.handleResponse(responseContent, requestDTO);
    }

    @Override
    public String getMaskedRequestPayload(String payload) throws IdentityFraudDetectorException {

        return SiftLogUtil.getMaskedSiftPayload(new JSONObject(payload));
    }

    /**
     * Converts a generic FraudDetectorRequestDTO to a SiftFraudDetectorRequestDTO.
     *
     * @param requestDTO Generic fraud detector request DTO.
     * @return Sift fraud detector request DTO.
     */
    private SiftFraudDetectorRequestDTO convertToSiftRequestDTO(FraudDetectorRequestDTO requestDTO) {

        return new SiftFraudDetectorRequestDTO(requestDTO);
    }
}
