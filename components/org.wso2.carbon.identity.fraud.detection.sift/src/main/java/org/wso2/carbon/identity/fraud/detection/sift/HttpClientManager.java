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

package org.wso2.carbon.identity.fraud.detection.sift;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.wso2.carbon.identity.fraud.detection.sift.models.ConnectionConfig;

import java.io.IOException;

/**
 * HttpClientManager class to manage HttpClient instances.
 */
public class HttpClientManager {

    private static final Log LOG = LogFactory.getLog(HttpClientManager.class);
    private static final HttpClientManager instance = new HttpClientManager();

    private HttpClientManager() {

    }

    public static HttpClientManager getInstance() {

        return instance;
    }

    public CloseableHttpClient getHttpClient(ConnectionConfig connectionConfig) {

        return HttpClientBuilder.create().setDefaultRequestConfig(getRequestConfig(connectionConfig)).build();
    }

    public void closeHttpClient(CloseableHttpClient httpClient) {

        try {
            httpClient.close();
        } catch (IOException e) {
            LOG.error("Error occurred while closing the HttpClient.", e);
        }
    }

    private RequestConfig getRequestConfig(ConnectionConfig connectionConfig) {

        return RequestConfig.custom()
                .setConnectTimeout(connectionConfig.getConnectionTimeout())
                .setConnectionRequestTimeout(connectionConfig.getConnectionRequestTimeout())
                .setSocketTimeout(connectionConfig.getReadTimeout())
                .setRedirectsEnabled(false)
                .setRelativeRedirectsAllowed(false)
                .build();
    }
}
