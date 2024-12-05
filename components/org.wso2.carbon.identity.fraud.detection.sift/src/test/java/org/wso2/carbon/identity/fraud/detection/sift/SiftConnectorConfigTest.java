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

import org.apache.commons.collections.MapUtils;
import org.apache.commons.lang.ArrayUtils;
import org.testng.Assert;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import java.util.List;
import java.util.Map;
import java.util.Properties;

/**
 * Test class for SiftConfigConnector.
 */
public class SiftConnectorConfigTest {

    private SiftConnectorConfig siftConnectorConfig;

    @BeforeClass
    public void setUp() {

        siftConnectorConfig = new SiftConnectorConfig();
    }

    @Test
    public void testGetName() {

        Assert.assertEquals(siftConnectorConfig.getName(), Constants.CONNECTOR_NAME);
    }

    @Test
    public void testGetFriendlyName() {

        Assert.assertEquals(siftConnectorConfig.getFriendlyName(), Constants.CONNECTOR_FRIENDLY_NAME);
    }

    @Test
    public void testGetCategory() {

        Assert.assertEquals(siftConnectorConfig.getCategory(), Constants.CONNECTOR_CATEGORY);
    }

    @Test
    public void testGetSubCategory() {

        Assert.assertEquals(siftConnectorConfig.getSubCategory(), Constants.CONNECTOR_SUB_CATEGORY);
    }

    @Test
    public void testGetOrder() {

        Assert.assertEquals(siftConnectorConfig.getOrder(), Constants.CONNECTOR_ORDER);
    }

    @Test
    public void testGetPropertyNameMapping() {

        Map<String, String> propertyNameMapping = siftConnectorConfig.getPropertyNameMapping();
        Assert.assertEquals(propertyNameMapping.get(Constants.SIFT_API_KEY_PROP), Constants.SIFT_API_KEY_PROP_NAME);
    }

    @Test
    public void testGetPropertyDescriptionMapping() {

        Map<String, String> propertyDescriptionMapping = siftConnectorConfig.getPropertyDescriptionMapping();
        Assert.assertEquals(propertyDescriptionMapping.get(Constants.SIFT_API_KEY_PROP),
                Constants.SIFT_API_KEY_PROP_DESC);
    }

    @Test
    public void testGetPropertyNames() {

        String[] propertyNames = siftConnectorConfig.getPropertyNames();
        Assert.assertEquals(propertyNames.length, 1);
        Assert.assertTrue(ArrayUtils.contains(propertyNames, Constants.SIFT_API_KEY_PROP));
    }

    @Test
    public void testGetDefaultPropertyValues() {

        Map<String, String> defaultPropertyValues = siftConnectorConfig.getDefaultPropertyValues(null, "");
        Assert.assertTrue(MapUtils.isEmpty(defaultPropertyValues));
    }

    @Test
    public void testGetDefaultPropertyValuesWithTenantDomain() {

        Properties defaultPropertyValues = siftConnectorConfig.getDefaultPropertyValues("");
        Assert.assertEquals(defaultPropertyValues.getProperty(Constants.SIFT_API_KEY_PROP), "");
    }

    @Test
    public void testGetConfidentialPropertyValues() {

        List<String> confidentialPropertyValues = siftConnectorConfig.getConfidentialPropertyValues("");
        Assert.assertEquals(confidentialPropertyValues.size(), 1);
        Assert.assertTrue(confidentialPropertyValues.contains(Constants.SIFT_API_KEY_PROP));
    }
}
