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

import org.wso2.carbon.identity.governance.common.IdentityConnectorConfig;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import static org.wso2.carbon.identity.fraud.detection.sift.Constants.CONNECTOR_CATEGORY;
import static org.wso2.carbon.identity.fraud.detection.sift.Constants.CONNECTOR_FRIENDLY_NAME;
import static org.wso2.carbon.identity.fraud.detection.sift.Constants.CONNECTOR_NAME;
import static org.wso2.carbon.identity.fraud.detection.sift.Constants.CONNECTOR_ORDER;
import static org.wso2.carbon.identity.fraud.detection.sift.Constants.CONNECTOR_SUB_CATEGORY;
import static org.wso2.carbon.identity.fraud.detection.sift.Constants.SIFT_API_KEY_PROP;
import static org.wso2.carbon.identity.fraud.detection.sift.Constants.SIFT_API_KEY_PROP_DESC;
import static org.wso2.carbon.identity.fraud.detection.sift.Constants.SIFT_API_KEY_PROP_NAME;

/**
 * Sift Config Connector containing the configurations required for integrating with Sift.
 */
public class SiftConnectorConfig implements IdentityConnectorConfig {

    @Override
    public String getName() {

        return CONNECTOR_NAME;
    }

    @Override
    public String getFriendlyName() {

        return CONNECTOR_FRIENDLY_NAME;
    }

    @Override
    public String getCategory() {

        return CONNECTOR_CATEGORY;
    }

    @Override
    public String getSubCategory() {

        return CONNECTOR_SUB_CATEGORY;
    }

    @Override
    public int getOrder() {

        return CONNECTOR_ORDER;
    }

    @Override
    public Map<String, String> getPropertyNameMapping() {

        Map<String, String> mapping = new HashMap<>();
        mapping.put(SIFT_API_KEY_PROP, SIFT_API_KEY_PROP_NAME);
        return mapping;
    }

    @Override
    public Map<String, String> getPropertyDescriptionMapping() {

        Map<String, String> mapping = new HashMap<>();
        mapping.put(SIFT_API_KEY_PROP, SIFT_API_KEY_PROP_DESC);
        return mapping;
    }

    @Override
    public String[] getPropertyNames() {

        List<String> properties = new ArrayList<>();
        properties.add(SIFT_API_KEY_PROP);
        return properties.toArray(new String[0]);
    }

    @Override
    public Properties getDefaultPropertyValues(String tenantDomain) {

        Properties properties = new Properties();
        properties.put(SIFT_API_KEY_PROP, "");
        return properties;
    }

    @Override
    public Map<String, String> getDefaultPropertyValues(String[] propertyNames, String tenantDomain) {

        return new HashMap<>();
    }

    @Override
    public List<String> getConfidentialPropertyValues(String tenantDomain) {

        List<String> properties = new ArrayList<>();
        properties.add(SIFT_API_KEY_PROP);
        return properties;
    }
}
