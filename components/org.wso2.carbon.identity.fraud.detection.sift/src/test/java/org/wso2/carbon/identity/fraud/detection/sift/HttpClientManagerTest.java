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

import org.apache.http.client.config.RequestConfig;
import org.apache.http.impl.client.CloseableHttpClient;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.testng.Assert;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.fraud.detection.sift.models.ConnectionConfig;

import java.io.IOException;

import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

/**
 * Test class for HttpClientManager.
 */
public class HttpClientManagerTest {

    @Mock
    private CloseableHttpClient mockHttpClient;

    @BeforeClass
    public void setUp() {

        MockitoAnnotations.openMocks(this);
    }

    @Test
    public void testGetHttpClient() {

        ConnectionConfig connectionConfig = new ConnectionConfig.Builder()
                .setConnectionTimeout(400)
                .setReadTimeout(400)
                .setConnectionRequestTimeout(400)
                .build();

        CloseableHttpClient httpClient = HttpClientManager.getInstance().getHttpClient(connectionConfig);
        Assert.assertNotNull(httpClient);

        RequestConfig requestConfig = RequestConfig.custom()
                .setConnectTimeout(connectionConfig.getConnectionTimeout())
                .setConnectionRequestTimeout(connectionConfig.getConnectionRequestTimeout())
                .setSocketTimeout(connectionConfig.getReadTimeout())
                .build();

        Assert.assertEquals(requestConfig.getConnectTimeout(), connectionConfig.getConnectionTimeout());
        Assert.assertEquals(requestConfig.getConnectionRequestTimeout(),
                connectionConfig.getConnectionRequestTimeout());
        Assert.assertEquals(requestConfig.getSocketTimeout(), connectionConfig.getReadTimeout());
    }

    @Test
    public void testCloseHttpClient() throws IOException {

        doNothing().when(mockHttpClient).close();
        HttpClientManager.getInstance().closeHttpClient(mockHttpClient);
        verify(mockHttpClient, times(1)).close();
    }
}
