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

package org.wso2.carbon.identity.fraud.detection.sift.util;

import org.apache.commons.codec.digest.DigestUtils;
import org.json.JSONObject;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.MockitoAnnotations;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.config.model.SequenceConfig;
import org.wso2.carbon.identity.application.authentication.framework.config.model.StepConfig;
import org.wso2.carbon.identity.application.authentication.framework.config.model.graph.js.JsAuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.config.model.graph.js.JsAuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.context.TransientObjectWrapper;
import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.fraud.detection.sift.Constants;
import org.wso2.carbon.identity.fraud.detection.sift.internal.SiftDataHolder;
import org.wso2.carbon.identity.governance.IdentityGovernanceException;
import org.wso2.carbon.identity.governance.IdentityGovernanceService;
import org.wso2.carbon.identity.governance.bean.ConnectorConfig;
import org.wso2.carbon.identity.organization.management.service.OrganizationManager;
import org.wso2.carbon.identity.organization.management.service.util.OrganizationManagementUtil;

import java.util.HashMap;
import java.util.Map;

import javax.servlet.http.HttpServletRequestWrapper;

import static org.mockito.Mockito.anyString;
import static org.mockito.Mockito.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertTrue;

/**
 * Unit tests for the Util class in the Sift fraud detection module.
 */
public class UtilTest {

    private static final String TENANT = "carbon.super";
    private static final String SESSION_ID = "session123";
    private static final String USER_1 = "user123";
    private static final String STEP_USER = "stepUser";
    private static final String IP_ADDRESS = "127.0.0.1";
    private static final String USER_AGENT = "Mozilla/5.0";
    private static final String CUSTOM_IP_ADDRESS = "192.168.8.1";
    private static final String CUSTOM_USER_AGENT = "customUserAgent";
    private static final String CUSTOM_USER_ID = "customUserId";
    private static final String CUSTOM_KEY = "customKey";
    private static final String CUSTOM_VALUE = "customValue";
    private static final int STEP = 1;

    @Mock
    private JsAuthenticationContext jsContext;
    @Mock
    private IdentityGovernanceService identityService;
    @Mock
    private OrganizationManager organizationManager;

    private MockedStatic<SiftEventUtil> siftEventUtilMockedStatic;

    @BeforeMethod
    public void setup() {

        MockitoAnnotations.openMocks(this);
        SiftDataHolder.getInstance().setIdentityGovernanceService(identityService);
        SiftDataHolder.getInstance().setOrganizationManager(organizationManager);

        // Mock SiftEventUtil static methods to avoid tenant validation issues
        siftEventUtilMockedStatic = mockStatic(SiftEventUtil.class);
        siftEventUtilMockedStatic.when(() ->
                SiftEventUtil.isAllowDeviceMetadataInPayload(anyString())).thenReturn(true);
    }

    @org.testng.annotations.AfterMethod
    public void teardown() {
        if (siftEventUtilMockedStatic != null) {
            siftEventUtilMockedStatic.close();
        }
    }

    private void mockHttpRequest(AuthenticationContext ctx, String ip, String userAgent) {

        HttpServletRequestWrapper req = mock(HttpServletRequestWrapper.class);
        when(req.getHeader(Constants.USER_AGENT_HEADER)).thenReturn(userAgent);
        when(req.getRemoteAddr()).thenReturn(ip);
        TransientObjectWrapper<HttpServletRequestWrapper> wrapper = mock(TransientObjectWrapper.class);
        when(wrapper.getWrapped()).thenReturn(req);
        when(ctx.getParameter(Constants.HTTP_SERVLET_REQUEST)).thenReturn(wrapper);
    }

    private void mockApiKey(String apiKey) throws IdentityGovernanceException {

        ConnectorConfig cfg = mock(ConnectorConfig.class);
        Property p = new Property();
        p.setName(Constants.SIFT_API_KEY_PROP);
        p.setValue(apiKey);
        when(cfg.getProperties()).thenReturn(new Property[]{p});
        when(identityService.getConnectorWithConfigs(TENANT, Constants.CONNECTOR_NAME)).thenReturn(cfg);
    }

    private void mockStepConfigWithUser(AuthenticationContext ctx, String user) {

        SequenceConfig sequenceConfig = mock(SequenceConfig.class);
        StepConfig stepConfig = mock(StepConfig.class);
        AuthenticatedUser authUser = mock(AuthenticatedUser.class);
        when(authUser.getUsernameAsSubjectIdentifier(true, true)).thenReturn(user);
        when(stepConfig.getAuthenticatedUser()).thenReturn(authUser);
        Map<Integer, StepConfig> stepMap = new HashMap<>();
        stepMap.put(STEP, stepConfig);
        when(sequenceConfig.getStepMap()).thenReturn(stepMap);
        when(ctx.getSequenceConfig()).thenReturn(sequenceConfig);
        when(ctx.getCurrentStep()).thenReturn(STEP);
    }

    private void mockContextIdentifier(AuthenticationContext ctx, String sessionId) {

        when(ctx.getContextIdentifier()).thenReturn(sessionId);
    }

    @Test
    public void testBuildDefaultPayloadFromCurrentKnownSubject() throws Exception {

        try (MockedStatic<OrganizationManagementUtil> mockedUtil = mockStatic(OrganizationManagementUtil.class)) {
            mockedUtil.when(() -> OrganizationManagementUtil.isOrganization(TENANT)).thenReturn(false);

            AuthenticationContext ctx = mock(AuthenticationContext.class);
            when(jsContext.getWrapped()).thenReturn(ctx);
            when(ctx.getTenantDomain()).thenReturn(TENANT);
            mockContextIdentifier(ctx, SESSION_ID);
            mockHttpRequest(ctx, IP_ADDRESS, USER_AGENT);

            mockStepConfigWithUser(ctx, null);

            AuthenticatedUser authUser = mock(AuthenticatedUser.class);
            when(authUser.getUsernameAsSubjectIdentifier(true, true)).thenReturn(USER_1);
            JsAuthenticatedUser jsUser = mock(JsAuthenticatedUser.class);
            when(jsUser.getWrapped()).thenReturn(authUser);

            when(ctx.getLastAuthenticatedUser()).thenReturn(authUser);
            when(jsContext.getMember(FrameworkConstants.JSAttributes.JS_CURRENT_KNOWN_SUBJECT)).thenReturn(jsUser);

            mockApiKey("dummyApiKey");

            JSONObject payload = Util.buildPayload(jsContext, "LOGIN_SUCCESS", new HashMap<>());
            assertEquals(payload.getString(Constants.LOGIN_STATUS), "$success");
            assertEquals(payload.getString(Constants.USER_ID_KEY), DigestUtils.sha256Hex(USER_1));
            assertEquals(payload.getString(Constants.SESSION_ID_KEY), DigestUtils.sha256Hex(SESSION_ID));
            assertEquals(payload.getString(Constants.IP_KEY), IP_ADDRESS);
            assertEquals(payload.getJSONObject(Constants.BROWSER_KEY).getString(Constants.USER_AGENT_KEY), USER_AGENT);
        }
    }

    @Test
    public void testBuildPayloadFromStepUser() throws Exception {

        try (MockedStatic<OrganizationManagementUtil> mockedUtil = mockStatic(OrganizationManagementUtil.class)) {
            mockedUtil.when(() -> OrganizationManagementUtil.isOrganization(TENANT)).thenReturn(false);

            AuthenticationContext ctx = mock(AuthenticationContext.class);
            when(jsContext.getWrapped()).thenReturn(ctx);
            when(ctx.getTenantDomain()).thenReturn(TENANT);
            mockContextIdentifier(ctx, SESSION_ID);
            mockHttpRequest(ctx, IP_ADDRESS, USER_AGENT);
            mockStepConfigWithUser(ctx, STEP_USER);
            mockApiKey("dummyApiKey");

            JSONObject payload = Util.buildPayload(jsContext, "LOGIN_SUCCESS", new HashMap<>());
            assertEquals(payload.getString(Constants.USER_ID_KEY), DigestUtils.sha256Hex(STEP_USER));
        }
    }

    @Test
    public void testBuildPayloadWithOverriddenCustomParams() throws Exception {

        try (MockedStatic<OrganizationManagementUtil> mockedUtil = mockStatic(OrganizationManagementUtil.class)) {
            mockedUtil.when(() -> OrganizationManagementUtil.isOrganization(TENANT)).thenReturn(false);

            AuthenticationContext ctx = mock(AuthenticationContext.class);
            when(jsContext.getWrapped()).thenReturn(ctx);
            when(ctx.getTenantDomain()).thenReturn(TENANT);
            mockContextIdentifier(ctx, SESSION_ID);
            mockHttpRequest(ctx, IP_ADDRESS, USER_AGENT);
            mockStepConfigWithUser(ctx, null);

            AuthenticatedUser authUser = mock(AuthenticatedUser.class);
            when(authUser.getUsernameAsSubjectIdentifier(true, true)).thenReturn(USER_1);
            JsAuthenticatedUser jsUser = mock(JsAuthenticatedUser.class);
            when(jsUser.getWrapped()).thenReturn(authUser);
            when(ctx.getLastAuthenticatedUser()).thenReturn(authUser);
            when(jsContext.getMember(FrameworkConstants.JSAttributes.JS_CURRENT_KNOWN_SUBJECT)).thenReturn(jsUser);

            mockApiKey("dummyApiKey");

            Map<String, Object> params = new HashMap<>();
            params.put(Constants.USER_ID_KEY, CUSTOM_USER_ID);
            params.put(Constants.IP_KEY, "");
            params.put(Constants.SESSION_ID_KEY, "");
            params.put(Constants.LOGGING_ENABLED, true);
            params.put(CUSTOM_KEY, CUSTOM_VALUE);

            JSONObject payload = Util.buildPayload(jsContext, "LOGIN_FAILED", params);
            assertEquals(payload.getString(Constants.USER_ID_KEY), CUSTOM_USER_ID);
            assertTrue(payload.isNull(Constants.IP_KEY));
            assertTrue(payload.isNull(Constants.SESSION_ID_KEY));
            assertEquals(payload.getString(CUSTOM_KEY), CUSTOM_VALUE);
        }
    }

    @Test
    public void testBuildPayloadWithReplacedValues() throws Exception {

        try (MockedStatic<OrganizationManagementUtil> mockedUtil = mockStatic(OrganizationManagementUtil.class)) {
            mockedUtil.when(() -> OrganizationManagementUtil.isOrganization(TENANT)).thenReturn(false);

            AuthenticationContext ctx = mock(AuthenticationContext.class);
            when(jsContext.getWrapped()).thenReturn(ctx);
            when(ctx.getTenantDomain()).thenReturn(TENANT);
            mockContextIdentifier(ctx, SESSION_ID);
            mockHttpRequest(ctx, IP_ADDRESS, USER_AGENT);
            mockStepConfigWithUser(ctx, null);

            AuthenticatedUser authUser = mock(AuthenticatedUser.class);
            when(authUser.getUsernameAsSubjectIdentifier(true, true)).thenReturn(USER_1);
            JsAuthenticatedUser jsUser = mock(JsAuthenticatedUser.class);
            when(jsUser.getWrapped()).thenReturn(authUser);
            when(ctx.getLastAuthenticatedUser()).thenReturn(authUser);
            when(jsContext.getMember(FrameworkConstants.JSAttributes.JS_CURRENT_KNOWN_SUBJECT)).thenReturn(jsUser);

            mockApiKey("dummyApiKey");

            Map<String, Object> params = new HashMap<>();
            params.put(Constants.IP_KEY, CUSTOM_IP_ADDRESS);
            params.put(Constants.USER_AGENT_KEY, CUSTOM_USER_AGENT);
            params.put(CUSTOM_KEY, CUSTOM_VALUE);

            JSONObject payload = Util.buildPayload(jsContext, "LOGIN_SUCCESS", params);
            assertEquals(payload.getString(Constants.IP_KEY), CUSTOM_IP_ADDRESS);
            assertEquals(payload.getJSONObject(Constants.BROWSER_KEY).getString(Constants.USER_AGENT_KEY),
                    CUSTOM_USER_AGENT);
            assertEquals(payload.getString(CUSTOM_KEY), CUSTOM_VALUE);
        }
    }

    @Test(expectedExceptions = FrameworkException.class)
    public void testBuildPayloadMissingAuthenticatedUser() throws Exception {

        try (MockedStatic<OrganizationManagementUtil> mockedUtil = mockStatic(OrganizationManagementUtil.class)) {
            mockedUtil.when(() -> OrganizationManagementUtil.isOrganization(TENANT)).thenReturn(false);

            AuthenticationContext ctx = mock(AuthenticationContext.class);
            when(jsContext.getWrapped()).thenReturn(ctx);
            when(ctx.getTenantDomain()).thenReturn(TENANT);
            mockContextIdentifier(ctx, SESSION_ID);
            mockStepConfigWithUser(ctx, null);
            when(ctx.getLastAuthenticatedUser()).thenReturn(null);
            when(jsContext.hasMember(FrameworkConstants.JSAttributes.JS_LAST_LOGIN_FAILED_USER)).thenReturn(false);
            when(jsContext.hasMember(FrameworkConstants.JSAttributes.JS_CURRENT_KNOWN_SUBJECT)).thenReturn(false);

            mockApiKey("dummyApiKey");
            Util.buildPayload(jsContext, "LOGIN_FAILED", new HashMap<>());
        }
    }

    @Test(expectedExceptions = FrameworkException.class)
    public void testBuildPayloadWithNullContextId() throws Exception {

        try (MockedStatic<OrganizationManagementUtil> mockedUtil = mockStatic(OrganizationManagementUtil.class)) {
            mockedUtil.when(() -> OrganizationManagementUtil.isOrganization(TENANT)).thenReturn(false);

            AuthenticationContext ctx = mock(AuthenticationContext.class);
            when(jsContext.getWrapped()).thenReturn(ctx);
            when(ctx.getTenantDomain()).thenReturn(TENANT);
            when(ctx.getContextIdentifier()).thenReturn(null);
            mockStepConfigWithUser(ctx, USER_1);
            mockHttpRequest(ctx, IP_ADDRESS, USER_AGENT);
            mockApiKey("dummyApiKey");
            Util.buildPayload(jsContext, "LOGIN_SUCCESS", new HashMap<>());
        }
    }


    @Test(expectedExceptions = FrameworkException.class)
    public void testBuildPayloadWithMissingApiKey() throws Exception {

        try (MockedStatic<OrganizationManagementUtil> mockedUtil = mockStatic(OrganizationManagementUtil.class)) {
            mockedUtil.when(() -> OrganizationManagementUtil.isOrganization(TENANT)).thenReturn(false);

            AuthenticationContext ctx = mock(AuthenticationContext.class);
            when(jsContext.getWrapped()).thenReturn(ctx);
            when(ctx.getTenantDomain()).thenReturn(TENANT);
            mockContextIdentifier(ctx, SESSION_ID);
            ConnectorConfig config = mock(ConnectorConfig.class);
            Property p = new Property();
            p.setName("other");
            p.setValue("value");
            when(config.getProperties()).thenReturn(new Property[]{p});
            when(identityService.getConnectorWithConfigs(TENANT, Constants.CONNECTOR_NAME)).thenReturn(config);
            Util.buildPayload(jsContext, "LOGIN_SUCCESS", new HashMap<>());
        }
    }

    @Test(expectedExceptions = FrameworkException.class)
    public void testBuildPayloadWithNullConnector() throws Exception {

        try (MockedStatic<OrganizationManagementUtil> mockedUtil = mockStatic(OrganizationManagementUtil.class)) {
            mockedUtil.when(() -> OrganizationManagementUtil.isOrganization(TENANT)).thenReturn(false);

            AuthenticationContext ctx = mock(AuthenticationContext.class);
            when(jsContext.getWrapped()).thenReturn(ctx);
            when(ctx.getTenantDomain()).thenReturn(TENANT);
            mockContextIdentifier(ctx, SESSION_ID);
            mockStepConfigWithUser(ctx, USER_1);
            when(identityService.getConnectorWithConfigs(TENANT, Constants.CONNECTOR_NAME)).thenReturn(null);
            Util.buildPayload(jsContext, "LOGIN_SUCCESS", new HashMap<>());
        }
    }


    @Test(expectedExceptions = FrameworkException.class)
    public void testBuildPayloadWithGovernanceException() throws Exception {

        try (MockedStatic<OrganizationManagementUtil> mockedUtil = mockStatic(OrganizationManagementUtil.class)) {
            mockedUtil.when(() -> OrganizationManagementUtil.isOrganization(TENANT)).thenReturn(false);

            AuthenticationContext ctx = mock(AuthenticationContext.class);
            when(jsContext.getWrapped()).thenReturn(ctx);
            when(ctx.getTenantDomain()).thenReturn(TENANT);
            when(ctx.getContextIdentifier()).thenReturn(SESSION_ID);
            mockStepConfigWithUser(ctx, USER_1);
            when(identityService.getConnectorWithConfigs(eq(TENANT), anyString()))
                    .thenThrow(new IdentityGovernanceException("Test exception"));
            Util.buildPayload(jsContext, "LOGIN_SUCCESS", new HashMap<>());
        }
    }


    @Test
    public void testGetPassedCustomParamsValid() {

        Map<String, Object> map = new HashMap<>();
        map.put("key", "value");
        Object[] input = new Object[]{map};
        Map<String, Object> result = Util.getPassedCustomParams(input);
        assertNotNull(result);
        assertEquals(result.get("key"), "value");
    }

    @Test(expectedExceptions = IllegalArgumentException.class)
    public void testGetPassedCustomParamsInvalidType() {

        Object[] input = new Object[]{"invalid"};
        Util.getPassedCustomParams(input);
    }

    @Test
    public void testIsLoggingEnabledWithNullMap() {

        assertFalse(Util.isLoggingEnabled(null));
    }

    @Test
    public void testIsLoggingEnabledWithTrueFlag() {

        Map<String, Object> map = new HashMap<>();
        map.put(Constants.LOGGING_ENABLED, true);
        assertTrue(Util.isLoggingEnabled(map));
        assertFalse(map.containsKey(Constants.LOGGING_ENABLED));
    }

    @Test
    public void testGetMaskedSiftPayload() {

        JSONObject input = new JSONObject();
        input.put("key1", "value1");
        input.put(Constants.API_KEY, "abc123456789");

        String masked = Util.getMaskedSiftPayload(input);
        JSONObject result = new JSONObject(masked);
        assertEquals(result.getString("key1"), "value1");
        assertTrue(result.getString(Constants.API_KEY).startsWith("abc123"));
        assertTrue(result.getString(Constants.API_KEY).endsWith("***"));
    }

    @Test
    public void testHttpServletRequestWithInvalidWrapper() throws Exception {

        try (MockedStatic<OrganizationManagementUtil> mockedUtil = mockStatic(OrganizationManagementUtil.class)) {
            mockedUtil.when(() -> OrganizationManagementUtil.isOrganization(TENANT)).thenReturn(false);

            AuthenticationContext ctx = mock(AuthenticationContext.class);
            when(jsContext.getWrapped()).thenReturn(ctx);
            when(ctx.getTenantDomain()).thenReturn(TENANT);
            mockContextIdentifier(ctx, SESSION_ID);
            mockStepConfigWithUser(ctx, USER_1);

            Object invalidRequest = new Object();
            TransientObjectWrapper<Object> wrapper = mock(TransientObjectWrapper.class);
            when(wrapper.getWrapped()).thenReturn(invalidRequest);
            when(ctx.getParameter(Constants.HTTP_SERVLET_REQUEST)).thenReturn(wrapper);

            mockApiKey("dummyApiKey");
            JSONObject payload = Util.buildPayload(jsContext, "LOGIN_SUCCESS", new HashMap<>());

            assertFalse(payload.has(Constants.IP_KEY));
            JSONObject browser = payload.getJSONObject(Constants.BROWSER_KEY);
            assertTrue(browser.isNull(Constants.USER_AGENT_KEY));
        }
    }
}
