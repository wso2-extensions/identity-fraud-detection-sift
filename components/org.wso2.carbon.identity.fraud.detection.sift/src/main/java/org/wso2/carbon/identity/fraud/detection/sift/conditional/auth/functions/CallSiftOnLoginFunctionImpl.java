/*
 * Copyright (c) 2024 - 2025, WSO2 LLC. (https://www.wso2.com).
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

package org.wso2.carbon.identity.fraud.detection.sift.conditional.auth.functions;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.graalvm.polyglot.HostAccess;
import org.wso2.carbon.identity.application.authentication.framework.config.model.graph.js.JsAuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;
import org.wso2.carbon.identity.fraud.detection.core.IdentityFraudDetector;
import org.wso2.carbon.identity.fraud.detection.core.constant.FraudDetectionConstants;
import org.wso2.carbon.identity.fraud.detection.sift.Constants;
import org.wso2.carbon.identity.fraud.detection.sift.internal.SiftDataHolder;
import org.wso2.carbon.identity.fraud.detection.sift.models.SiftFraudDetectorRequestDTO;
import org.wso2.carbon.identity.fraud.detection.sift.models.SiftFraudDetectorResponseDTO;
import org.wso2.carbon.identity.fraud.detection.sift.util.Util;

import java.util.HashMap;
import java.util.Map;

import static org.wso2.carbon.identity.event.IdentityEventConstants.EventProperty.TENANT_DOMAIN;
import static org.wso2.carbon.identity.fraud.detection.sift.Constants.AUTHENTICATION_CONTEXT;
import static org.wso2.carbon.identity.fraud.detection.sift.Constants.CUSTOM_PARAMS;

/**
 * Function to call Sift on login.
 */
public class CallSiftOnLoginFunctionImpl implements CallSiftOnLoginFunction {

    private static final Log LOG = LogFactory.getLog(CallSiftOnLoginFunctionImpl.class);

    @Override
    @HostAccess.Export
    public double getSiftRiskScoreForLogin(JsAuthenticationContext context, String loginStatus, Object... paramMap)
        throws FrameworkException {

        Map<String, Object> passedCustomParams = Util.getPassedCustomParams(paramMap);
        boolean isLoggingEnabled = Util.isLoggingEnabled(passedCustomParams);

        Map<String, Object> properties = new HashMap<>();
        properties.put(CUSTOM_PARAMS, passedCustomParams);
        properties.put(AUTHENTICATION_CONTEXT, context);
        properties.put(Constants.LOGIN_STATUS, loginStatus);
        properties.put(TENANT_DOMAIN, context.getWrapped().getTenantDomain());

        SiftFraudDetectorRequestDTO requestDTO = new SiftFraudDetectorRequestDTO(
                FraudDetectionConstants.FraudDetectionEvents.LOGIN, properties);
        requestDTO.setLogRequestPayload(isLoggingEnabled);
        requestDTO.setReturnRiskScore(true);

        IdentityFraudDetector siftFraudDetector = SiftDataHolder.getInstance().getSiftFraudDetector();
        SiftFraudDetectorResponseDTO responseDTO
                = (SiftFraudDetectorResponseDTO) siftFraudDetector.publishRequest(requestDTO);
        double riskScore = responseDTO.getRiskScore();
        if (isLoggingEnabled) {
            LOG.info("Sift risk score: " + riskScore);
        }
        return riskScore;
    }
}
