/*
 * Copyright (c) 2025, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.fraud.detection.sift.conditional.auth.functions;

import org.apache.http.HttpEntity;
import org.apache.http.HttpStatus;
import org.apache.http.StatusLine;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.json.JSONArray;
import org.json.JSONObject;
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
import org.wso2.carbon.identity.fraud.detection.sift.Constants;
import org.wso2.carbon.identity.fraud.detection.sift.util.Util;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertTrue;

/**
 * Unit tests for GetSiftWorkflowDecisionFunctionImpl class.
 */
public class GetSiftWorkflowStatusFunctionImplTest {

    @Mock
    private CloseableHttpClient httpClient;

    @Mock
    private CloseableHttpResponse httpResponse;

    @Mock
    private HttpEntity httpEntity;

    @InjectMocks
    private GetSiftWorkflowDecisionFunctionImpl getSiftWorkflowDecisionFunction;

    private MockedStatic<Util> utilMockedStatic;
    private ByteArrayOutputStream logOutput;
    private JSONObject payload;

    private static final String DECISION_ID = "BLOCK_USER";

    @BeforeClass
    public void setUp() throws FrameworkException {

        MockitoAnnotations.openMocks(this);
        utilMockedStatic = mockStatic(Util.class);
        when(Util.getPassedCustomParams(any())).thenReturn(new HashMap<>());
        when(Util.isLoggingEnabled(any())).thenReturn(true);
        payload = new JSONObject();
        payload.put(Constants.API_KEY, "testApiKey");
        when(Util.buildPayload(any(), anyString(), anyMap())).thenReturn(new JSONObject());
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
    }

    @Test
    public void testGetSiftWorkflowForLoginSuccess() throws Exception {

        when(httpClient.execute(any(HttpPost.class))).thenReturn(httpResponse);
        StatusLine statusLine = mock(StatusLine.class);
        when(httpResponse.getStatusLine()).thenReturn(statusLine);
        when(httpResponse.getStatusLine().getStatusCode()).thenReturn(HttpStatus.SC_OK);
        when(httpResponse.getEntity()).thenReturn(httpEntity);

        JSONObject jsonResponse = getJsonResponse();

        when(httpEntity.getContent()).thenReturn(new StringEntity(jsonResponse.toString(), StandardCharsets.UTF_8)
                .getContent());

        String status = getSiftWorkflowDecisionFunction.getSiftWorkFlowDecision(
                mock(JsAuthenticationContext.class), "LOGIN_SUCCESS", new ArrayList<>(),
                new HashMap<String, Object>());

        assertEquals(status, DECISION_ID);
        assertTrue(logOutput.toString().contains("Sift workflow decision id: " + DECISION_ID));
        assertTrue(logOutput.toString().contains("Payload sent to Sift for workflow execution: "));
    }

    private static JSONObject getJsonResponse() {

        JSONObject config = new JSONObject();
        config.put("decision_id", DECISION_ID);

        JSONObject historyItem = new JSONObject();
        historyItem.put("app", "decision");
        historyItem.put("config", config);

        JSONArray historyArray = new JSONArray();
        historyArray.put(historyItem);

        JSONObject entity = new JSONObject();
        entity.put("type", "session");

        JSONObject workflowStatus = new JSONObject();
        workflowStatus.put("abuse_types", new JSONArray().put("account_takeover"));
        workflowStatus.put("entity", entity);
        workflowStatus.put("history", historyArray);

        JSONArray workflowStatuses = new JSONArray();
        workflowStatuses.put(workflowStatus);

        JSONObject scoreResponse = new JSONObject();
        scoreResponse.put("workflow_statuses", workflowStatuses);

        JSONObject jsonResponse = new JSONObject();
        jsonResponse.put("status", 0);
        jsonResponse.put("score_response", scoreResponse);
        return jsonResponse;
    }

    @Test
    public void testGetSiftRiskScoreForLoginNullResponse() throws Exception {

        when(httpClient.execute(any(HttpPost.class))).thenReturn(httpResponse);
        StatusLine statusLine = mock(StatusLine.class);
        when(httpResponse.getStatusLine()).thenReturn(statusLine);
        when(httpResponse.getStatusLine().getStatusCode()).thenReturn(HttpStatus.SC_OK);
        when(httpResponse.getEntity()).thenReturn(null);

        String workFlowDecision = getSiftWorkflowDecisionFunction.getSiftWorkFlowDecision(
                mock(JsAuthenticationContext.class), "LOGIN_SUCCESS", new ArrayList<>(),
                new HashMap<String, Object>());

        assertNull(workFlowDecision);
    }

    @Test
    public void testGetSiftRiskScoreForLoginSiftError() throws Exception {

        when(httpClient.execute(any(HttpPost.class))).thenReturn(httpResponse);
        StatusLine statusLine = mock(StatusLine.class);
        when(httpResponse.getStatusLine()).thenReturn(statusLine);
        when(httpResponse.getStatusLine().getStatusCode()).thenReturn(HttpStatus.SC_OK);
        when(httpResponse.getEntity()).thenReturn(httpEntity);

        JSONObject jsonResponse = new JSONObject();
        jsonResponse.put(Constants.SIFT_STATUS, "2");

        when(httpEntity.getContent()).thenReturn(new StringEntity(jsonResponse.toString(), StandardCharsets.UTF_8)
                .getContent());

        String workFlowDecision = getSiftWorkflowDecisionFunction.getSiftWorkFlowDecision(
                mock(JsAuthenticationContext.class), "LOGIN_SUCCESS", new ArrayList<>(),
                new HashMap<String, Object>());

        assertNull(workFlowDecision);
    }

    @Test
    public void testGetSiftRiskScoreForLoginErrorResponse() throws Exception {

        when(httpClient.execute(any(HttpPost.class))).thenReturn(httpResponse);
        StatusLine statusLine = mock(StatusLine.class);
        when(httpResponse.getStatusLine()).thenReturn(statusLine);
        when(httpResponse.getStatusLine().getStatusCode()).thenReturn(HttpStatus.SC_INTERNAL_SERVER_ERROR);
        when(httpResponse.getEntity()).thenReturn(httpEntity);

        String workFlowDecision = getSiftWorkflowDecisionFunction.getSiftWorkFlowDecision(
                mock(JsAuthenticationContext.class), "LOGIN_SUCCESS", new ArrayList<>(),
                new HashMap<String, Object>());

        assertNull(workFlowDecision);
    }

    @Test
    public void testGetSiftRiskScoreForLoginException() throws Exception {

        when(httpClient.execute(any(HttpPost.class))).thenReturn(httpResponse);
        StatusLine statusLine = mock(StatusLine.class);
        when(httpResponse.getStatusLine()).thenReturn(statusLine);
        when(httpResponse.getStatusLine().getStatusCode()).thenReturn(HttpStatus.SC_INTERNAL_SERVER_ERROR);
        when(httpResponse.getEntity()).thenReturn(httpEntity);

        String workFlowDecision = getSiftWorkflowDecisionFunction.getSiftWorkFlowDecision(
                mock(JsAuthenticationContext.class), "SUCCESS", new ArrayList<>(),
                new HashMap<String, Object>());

        assertNull(workFlowDecision);
    }
}
