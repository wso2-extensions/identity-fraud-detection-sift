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

package org.wso2.carbon.identity.fraud.detection.sift.models;

import org.apache.commons.lang3.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.fraud.detection.sift.Constants;

/**
 * Connection Config model containing configs for http client.
 */
public class ConnectionConfig {

    private final int connectionTimeout;
    private final int readTimeout;
    private final int connectionRequestTimeout;

    private ConnectionConfig(Builder builder) {

        this.connectionTimeout = builder.connectionTimeout;
        this.readTimeout = builder.readTimeout;
        this.connectionRequestTimeout = builder.connectionRequestTimeout;
    }

    public int getConnectionTimeout() {

        return connectionTimeout;
    }

    public int getReadTimeout() {

        return readTimeout;
    }

    public int getConnectionRequestTimeout() {

        return connectionRequestTimeout;
    }

    /**
     * Builder for ConnectionConfig.
     */
    public static class Builder {

        private static final Log LOG = LogFactory.getLog(ConnectionConfig.class);
        private int connectionTimeout;
        private int readTimeout;
        private int connectionRequestTimeout;

        public Builder() {

            String connectionTimeoutConfig = IdentityUtil.getProperty(Constants.CONNECTION_TIMEOUT_CONFIG);
            try {
                this.connectionTimeout = StringUtils.isNotBlank(connectionTimeoutConfig) ?
                        Integer.parseInt(connectionTimeoutConfig) : Constants.CONNECTION_TIMEOUT;
            } catch (NumberFormatException e) {
                LOG.error("Error while parsing connection timeout : " + connectionTimeoutConfig +
                        " defaulting to system default : " + Constants.CONNECTION_TIMEOUT, e);
                this.connectionTimeout = Constants.CONNECTION_TIMEOUT;
            }

            String readTimeoutConfig = IdentityUtil.getProperty(Constants.READ_TIMEOUT_CONFIG);
            try {
                this.readTimeout = StringUtils.isNotBlank(readTimeoutConfig) ?
                        Integer.parseInt(readTimeoutConfig) : Constants.READ_TIMEOUT;
            } catch (NumberFormatException e) {
                LOG.error("Error while parsing read timeout : " + readTimeoutConfig +
                        " defaulting to system default : " + Constants.READ_TIMEOUT, e);
                this.readTimeout = Constants.READ_TIMEOUT;
            }

            String connectionRequestTimeoutConfig =
                    IdentityUtil.getProperty(Constants.CONNECTION_REQUEST_TIMEOUT_CONFIG);
            try {
                this.connectionRequestTimeout = StringUtils.isNotBlank(connectionRequestTimeoutConfig) ?
                        Integer.parseInt(connectionRequestTimeoutConfig) : Constants.CONNECTION_REQUEST_TIMEOUT;
            } catch (NumberFormatException e) {
                LOG.error("Error while parsing connection request timeout : " + connectionRequestTimeoutConfig +
                        " defaulting to system default : " + Constants.CONNECTION_REQUEST_TIMEOUT, e);
                this.connectionRequestTimeout = Constants.CONNECTION_REQUEST_TIMEOUT;
            }
        }

        public Builder setConnectionTimeout(int connectionTimeout) {

            this.connectionTimeout = connectionTimeout;
            return this;
        }

        public Builder setReadTimeout(int readTimeout) {

            this.readTimeout = readTimeout;
            return this;
        }

        public Builder setConnectionRequestTimeout(int connectionRequestTimeout) {

            this.connectionRequestTimeout = connectionRequestTimeout;
            return this;
        }

        public ConnectionConfig build() {

            return new ConnectionConfig(this);
        }
    }
}
