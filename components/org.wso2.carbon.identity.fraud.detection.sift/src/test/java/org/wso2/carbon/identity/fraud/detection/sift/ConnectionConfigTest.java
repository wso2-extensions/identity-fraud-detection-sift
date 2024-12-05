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

import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.testng.Assert;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.fraud.detection.sift.models.ConnectionConfig;

/**
 * Test class for ConnectionConfig.
 */
public class ConnectionConfigTest {

    @Test
    public void testBuilderWithPassedValues() {

        int connectionTimeout = 5000;
        int readTimeout = 6000;
        int connectionRequestTimeout = 7000;

        ConnectionConfig config = new ConnectionConfig.Builder()
                .setConnectionTimeout(connectionTimeout)
                .setReadTimeout(readTimeout)
                .setConnectionRequestTimeout(connectionRequestTimeout)
                .build();

        Assert.assertEquals(config.getConnectionTimeout(), connectionTimeout);
        Assert.assertEquals(config.getReadTimeout(), readTimeout);
        Assert.assertEquals(config.getConnectionRequestTimeout(), connectionRequestTimeout);
    }

    @Test
    public void testBuilderWithIdentityUtilValues() {

        int connectionTimeout = 8000;
        int readTimeout = 9000;
        int connectionRequestTimeout = 10000;

        try (MockedStatic<IdentityUtil> mockedIdentityUtil = Mockito.mockStatic(IdentityUtil.class)) {
            mockedIdentityUtil.when(() -> IdentityUtil.getProperty(Constants.CONNECTION_TIMEOUT_CONFIG))
                    .thenReturn(String.valueOf(connectionTimeout));
            mockedIdentityUtil.when(() -> IdentityUtil.getProperty(Constants.READ_TIMEOUT_CONFIG))
                    .thenReturn(String.valueOf(readTimeout));
            mockedIdentityUtil.when(() -> IdentityUtil.getProperty(Constants.CONNECTION_REQUEST_TIMEOUT_CONFIG))
                    .thenReturn(String.valueOf(connectionRequestTimeout));

            ConnectionConfig config = new ConnectionConfig.Builder().build();

            Assert.assertEquals(config.getConnectionTimeout(), connectionTimeout);
            Assert.assertEquals(config.getReadTimeout(), readTimeout);
            Assert.assertEquals(config.getConnectionRequestTimeout(), connectionRequestTimeout);
        }
    }

    @Test
    public void testBuilderWithInvalidIdentityUtilValues() {

        String invalidValue = "invalid";
        try (MockedStatic<IdentityUtil> mockedIdentityUtil = Mockito.mockStatic(IdentityUtil.class)) {
            mockedIdentityUtil.when(() -> IdentityUtil.getProperty(Constants.CONNECTION_TIMEOUT_CONFIG))
                    .thenReturn(invalidValue);
            mockedIdentityUtil.when(() -> IdentityUtil.getProperty(Constants.READ_TIMEOUT_CONFIG))
                    .thenReturn(invalidValue);
            mockedIdentityUtil.when(() -> IdentityUtil.getProperty(Constants.CONNECTION_REQUEST_TIMEOUT_CONFIG))
                    .thenReturn(invalidValue);

            ConnectionConfig config = new ConnectionConfig.Builder().build();

            Assert.assertEquals(config.getConnectionTimeout(), Constants.CONNECTION_TIMEOUT);
            Assert.assertEquals(config.getReadTimeout(), Constants.READ_TIMEOUT);
            Assert.assertEquals(config.getConnectionRequestTimeout(), Constants.CONNECTION_REQUEST_TIMEOUT);
        }
    }

    @Test
    public void testBuilderWithNoValuesPassed() {

        ConnectionConfig config = new ConnectionConfig.Builder().build();

        Assert.assertEquals(config.getConnectionTimeout(), Constants.CONNECTION_TIMEOUT);
        Assert.assertEquals(config.getReadTimeout(), Constants.READ_TIMEOUT);
        Assert.assertEquals(config.getConnectionRequestTimeout(), Constants.CONNECTION_REQUEST_TIMEOUT);
    }
}
