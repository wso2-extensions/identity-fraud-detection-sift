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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
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
import org.wso2.carbon.identity.fraud.detection.sift.util.Util;

import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.Map;

import static org.wso2.carbon.identity.fraud.detection.sift.util.Util.getMaskedSiftPayload;

/**
 * Function to publish login event to Sift.
 */
public class PublishLoginToSiftFunctionImpl implements PublishLoginToSiftFunction {

    private static final Log LOG = LogFactory.getLog(PublishLoginToSiftFunctionImpl.class);
    private final CloseableHttpClient httpClient;

    public PublishLoginToSiftFunctionImpl(CloseableHttpClient httpClient) {

        this.httpClient = httpClient;
    }

    @Override
    @HostAccess.Export
    public void publishLoginEventToSift(JsAuthenticationContext context, String loginStatus, Object... paramMap)
            throws FrameworkException {

        HttpPost request = new HttpPost(Constants.SIFT_API_URL);
        request.addHeader(Constants.CONTENT_TYPE_HEADER, FrameworkConstants.ContentTypes.TYPE_APPLICATION_JSON);

        Map<String, Object> passedCustomParams = Util.getPassedCustomParams(paramMap);

        boolean isLoggingEnabled = Util.isLoggingEnabled(passedCustomParams);

        JSONObject payload = Util.buildPayload(context, loginStatus, passedCustomParams);

        if (isLoggingEnabled) {
            LOG.info("Payload sent to Sift for login event publishing: " + getMaskedSiftPayload(payload));
        }

        StringEntity entity = new StringEntity(payload.toString(), ContentType.APPLICATION_JSON);
        request.setEntity(entity);

        try (CloseableHttpResponse response = httpClient.execute(request)) {
            if (response.getStatusLine().getStatusCode() != HttpStatus.SC_OK) {
                LOG.error("Error occurred while publishing login event information to Sift. HTTP Status code: " +
                        response.getStatusLine().getStatusCode());
                return;
            }

            JSONObject jsonResponse = new JSONObject(new JSONTokener(new InputStreamReader(
                    response.getEntity().getContent(), StandardCharsets.UTF_8)));
            if (jsonResponse.has(Constants.SIFT_STATUS) &&
                    jsonResponse.getInt(Constants.SIFT_STATUS) == Constants.SIFT_STATUS_OK) {
                if (isLoggingEnabled) {
                    LOG.info("Successfully published login event information to Sift.");
                }
            } else {
                LOG.error("Error occurred from Sift while publishing login event information. " +
                        "Received Sift status: " + jsonResponse.getInt(Constants.SIFT_STATUS));
            }

        } catch (IOException e) {
            throw new FrameworkException("Error occurred while publishing login event information to Sift.", e);
        }
    }
}
