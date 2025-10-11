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

package org.wso2.carbon.identity.fraud.detection.sift.conditional.auth.functions;

import java.util.HashMap;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.HttpEntity;
import org.apache.http.HttpStatus;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.graalvm.polyglot.HostAccess;
import org.json.JSONObject;
import org.json.JSONTokener;
import org.wso2.carbon.identity.application.authentication.framework.config.model.graph.js.JsAuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.fraud.detection.sift.Constants;
import org.wso2.carbon.identity.fraud.detection.sift.internal.SiftDataHolder;
import org.wso2.carbon.identity.fraud.detection.sift.models.SiftFraudDetectorRequestDTO;
import org.wso2.carbon.identity.fraud.detection.sift.models.SiftFraudDetectorResponseDTO;
import org.wso2.carbon.identity.fraud.detection.sift.util.Util;

import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import org.wso2.carbon.identity.fraud.detectors.core.IdentityFraudDetector;
import org.wso2.carbon.identity.fraud.detectors.core.constant.FraudDetectorConstants;

import static org.wso2.carbon.identity.event.IdentityEventConstants.EventProperty.TENANT_DOMAIN;
import static org.wso2.carbon.identity.fraud.detection.sift.Constants.AUTHENTICATION_CONTEXT;
import static org.wso2.carbon.identity.fraud.detection.sift.Constants.CUSTOM_PARAMS;
import static org.wso2.carbon.identity.fraud.detection.sift.util.Util.getMaskedSiftPayload;

/**
 * Function to call Sift on login.
 */
public class CallSiftOnLoginFunctionImpl implements CallSiftOnLoginFunction {

    private static final Log LOG = LogFactory.getLog(CallSiftOnLoginFunctionImpl.class);
    private final CloseableHttpClient httpClient;

    public CallSiftOnLoginFunctionImpl(CloseableHttpClient httpClient) {

        this.httpClient = httpClient;
    }

//    @Override
//    @HostAccess.Export
    public double getSiftRiskScoreForLoginOld(JsAuthenticationContext context, String loginStatus, Object... paramMap)
            throws FrameworkException {

        HttpPost request = new HttpPost(Constants.SIFT_API_URL + Constants.RETURN_SCORE_PARAM);
        request.addHeader(Constants.CONTENT_TYPE_HEADER, FrameworkConstants.ContentTypes.TYPE_APPLICATION_JSON);

        Map<String, Object> passedCustomParams = Util.getPassedCustomParams(paramMap);

        boolean isLoggingEnabled = Util.isLoggingEnabled(passedCustomParams);

        JSONObject payload = Util.buildPayload(context, loginStatus, passedCustomParams);

        if (isLoggingEnabled) {
            LOG.info("Payload sent to Sift for risk score evaluation: " + getMaskedSiftPayload(payload));
        }

        StringEntity entity = new StringEntity(payload.toString(), ContentType.APPLICATION_JSON);
        request.setEntity(entity);

        try (CloseableHttpResponse response = httpClient.execute(request)) {

            if (response.getStatusLine().getStatusCode() != HttpStatus.SC_OK) {
                LOG.error("Error occurred while getting the risk score from Sift. HTTP Status code: " +
                        response.getStatusLine().getStatusCode());
                return Constants.DEFAULT_ERROR_VALUE;
            }

            HttpEntity responseEntity = response.getEntity();
            if (responseEntity == null) {
                LOG.error("Error occurred while getting the risk score from Sift. Response is null.");
                return Constants.DEFAULT_ERROR_VALUE;
            }

            JSONObject jsonResponse = new JSONObject(new JSONTokener(new InputStreamReader(
                    response.getEntity().getContent(), StandardCharsets.UTF_8)));
            if (jsonResponse.has(Constants.SIFT_STATUS) &&
                    jsonResponse.getInt(Constants.SIFT_STATUS) != Constants.SIFT_STATUS_OK) {
                LOG.error("Error occurred from Sift while getting the risk score. Received Sift status: " +
                        jsonResponse.getInt(Constants.SIFT_STATUS));
                return Constants.DEFAULT_ERROR_VALUE;
            }

            JSONObject scoreResponse = jsonResponse.optJSONObject(Constants.SIFT_SCORE_RESPONSE);
            JSONObject scores = scoreResponse != null ? scoreResponse.optJSONObject(Constants.SIFT_SCORES) : null;
            JSONObject accountTakeover = scores != null ? scores.optJSONObject(Constants.SIFT_ACCOUNT_TAKEOVER) : null;

            if (accountTakeover != null && accountTakeover.has(Constants.SIFT_SCORE)) {
                double riskScore = accountTakeover.getDouble(Constants.SIFT_SCORE);
                if (isLoggingEnabled) {
                    LOG.info("Sift risk score: " + riskScore);
                }
                return riskScore;
            }
        } catch (IOException e) {
            throw new FrameworkException("Error while executing the request: " + e);
        }
        return Constants.DEFAULT_ERROR_VALUE;
    }

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
                FraudDetectorConstants.FraudDetectionEvents.LOGIN, properties);
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
