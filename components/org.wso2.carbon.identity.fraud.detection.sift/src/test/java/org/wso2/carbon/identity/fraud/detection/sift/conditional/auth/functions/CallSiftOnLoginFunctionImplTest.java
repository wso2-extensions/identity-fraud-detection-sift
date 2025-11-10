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

import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.MockitoAnnotations;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.config.model.graph.js.JsAuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;
import org.wso2.carbon.identity.fraud.detection.core.IdentityFraudDetector;
import org.wso2.carbon.identity.fraud.detection.sift.internal.SiftDataHolder;
import org.wso2.carbon.identity.fraud.detection.sift.models.SiftFraudDetectorRequestDTO;
import org.wso2.carbon.identity.fraud.detection.sift.models.SiftFraudDetectorResponseDTO;
import org.wso2.carbon.identity.fraud.detection.sift.util.Util;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.util.HashMap;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertTrue;

/**
 * Unit tests for CallSiftOnLoginFunctionImpl class.
 */
public class CallSiftOnLoginFunctionImplTest {

    @Mock
    private IdentityFraudDetector siftFraudDetector;

    @Mock
    private SiftDataHolder siftDataHolder;

    @InjectMocks
    private CallSiftOnLoginFunctionImpl callSiftOnLoginFunction;

    private MockedStatic<Util> utilMockedStatic;
    private MockedStatic<SiftDataHolder> siftDataHolderMockedStatic;
    private ByteArrayOutputStream logOutput;

    @BeforeClass
    public void setUp() throws FrameworkException {

        MockitoAnnotations.openMocks(this);
        utilMockedStatic = mockStatic(Util.class);
        siftDataHolderMockedStatic = mockStatic(SiftDataHolder.class);

        when(Util.getPassedCustomParams(any())).thenReturn(new HashMap<>());
        when(Util.isLoggingEnabled(any())).thenReturn(true);

        // Mock SiftDataHolder singleton behavior
        when(SiftDataHolder.getInstance()).thenReturn(siftDataHolder);
        when(siftDataHolder.getSiftFraudDetector()).thenReturn(siftFraudDetector);
    }

    @BeforeMethod
    public void redirectOutputStreams() {

        // Redirect System.out to capture logs.
        logOutput = new ByteArrayOutputStream();
        System.setOut(new PrintStream(logOutput));
    }

    @AfterClass
    public void tearDown() {

        utilMockedStatic.close();
        siftDataHolderMockedStatic.close();
    }

    @Test
    public void testGetSiftRiskScoreForLoginSuccess() throws Exception {

        // Mock successful response from SiftFraudDetector with risk score
        SiftFraudDetectorResponseDTO successResponse = mock(SiftFraudDetectorResponseDTO.class);
        when(successResponse.getRiskScore()).thenReturn(0.85);
        when(siftFraudDetector.publishRequest(any(SiftFraudDetectorRequestDTO.class))).thenReturn(successResponse);

        // Mock JsAuthenticationContext
        JsAuthenticationContext jsContext = mock(JsAuthenticationContext.class);
        org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext authContext =
                mock(org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext.class);
        when(jsContext.getWrapped()).thenReturn(authContext);
        when(authContext.getTenantDomain()).thenReturn("carbon.super");

        double riskScore = callSiftOnLoginFunction.getSiftRiskScoreForLogin(jsContext, "LOGIN_SUCCESS",
                new HashMap<String, Object>());

        assertEquals(riskScore, 0.85);
        assertTrue(logOutput.toString().contains("Sift risk score: 0.85"));
    }

}
