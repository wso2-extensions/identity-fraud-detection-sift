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

import org.wso2.carbon.identity.application.authentication.framework.config.model.graph.js.JsAuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;

/**
 * Functional interface to call Sift on login.
 */
@FunctionalInterface
public interface CallSiftOnLoginFunction {

    /**
     * Get Sift risk score for login.
     *
     * @param context     Authentication context.
     * @param loginStatus Login status. Expected values are "LOGIN_SUCCESS", "LOGIN_FAILED" and "PRE_LOGIN".
     * @param paramMap    [Optional] An arbitrary data map to be sent to Sift. A json object can be passed to the
     *                    function which will be included as it is in the payload to Sift.
     * @return Sift risk score.
     * @throws FrameworkException FrameworkException.
     */
    double getSiftRiskScoreForLogin(JsAuthenticationContext context, String loginStatus, Object... paramMap)
            throws FrameworkException;
}
