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

package org.wso2.carbon.identity.fraud.detection.sift.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.framework.BundleContext;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;
import org.wso2.carbon.identity.application.authentication.framework.JsFunctionRegistry;
import org.wso2.carbon.identity.core.util.IdentityCoreInitializedEvent;
import org.wso2.carbon.identity.fraud.detection.core.IdentityFraudDetector;
import org.wso2.carbon.identity.fraud.detection.sift.SiftConnectorConfig;
import org.wso2.carbon.identity.fraud.detection.sift.SiftFraudDetector;
import org.wso2.carbon.identity.fraud.detection.sift.conditional.auth.functions.CallSiftOnLoginFunction;
import org.wso2.carbon.identity.fraud.detection.sift.conditional.auth.functions.CallSiftOnLoginFunctionImpl;
import org.wso2.carbon.identity.fraud.detection.sift.conditional.auth.functions.GetSiftWorkflowDecisionFunction;
import org.wso2.carbon.identity.fraud.detection.sift.conditional.auth.functions.GetSiftWorkflowDecisionFunctionImpl;
import org.wso2.carbon.identity.fraud.detection.sift.conditional.auth.functions.PublishLoginToSiftFunction;
import org.wso2.carbon.identity.fraud.detection.sift.conditional.auth.functions.PublishLoginToSiftFunctionImpl;
import org.wso2.carbon.identity.governance.IdentityGovernanceService;
import org.wso2.carbon.identity.governance.common.IdentityConnectorConfig;
import org.wso2.carbon.identity.organization.management.service.OrganizationManager;

/**
 * Service component for Sift.
 */
@Component(
        name = "identity.fraud.detection.sift.component",
        immediate = true
)
public class SiftServiceComponent {

    public static final String FUNC_GET_WORKFLOW_DECISION = "getSiftWorkflowDecision";
    public static final String FUNC_CALL_SIFT = "getSiftRiskScoreForLogin";
    public static final String FUNC_PUBLISH_LOGIN_TO_SIFT = "publishLoginEventToSift";
    private static final Log LOG = LogFactory.getLog(SiftServiceComponent.class);

    @Activate
    protected void activate(ComponentContext context) {

        try {
            JsFunctionRegistry jsFunctionRegistry = SiftDataHolder.getInstance().getJsFunctionRegistry();
            CallSiftOnLoginFunction getSiftRiskScoreForLogin = new CallSiftOnLoginFunctionImpl();
            GetSiftWorkflowDecisionFunction getSiftWorkflowDecisionFunction = new GetSiftWorkflowDecisionFunctionImpl();
            PublishLoginToSiftFunction publishLoginToSiftFunction = new PublishLoginToSiftFunctionImpl();
            jsFunctionRegistry.register(JsFunctionRegistry.Subsystem.SEQUENCE_HANDLER, FUNC_CALL_SIFT,
                    getSiftRiskScoreForLogin);
            jsFunctionRegistry.register(JsFunctionRegistry.Subsystem.SEQUENCE_HANDLER, FUNC_GET_WORKFLOW_DECISION,
                    getSiftWorkflowDecisionFunction);
            jsFunctionRegistry.register(JsFunctionRegistry.Subsystem.SEQUENCE_HANDLER, FUNC_PUBLISH_LOGIN_TO_SIFT,
                    publishLoginToSiftFunction);

            BundleContext bundleContext = context.getBundleContext();
            SiftConnectorConfig siftConfigConnector = new SiftConnectorConfig();
            bundleContext.registerService(IdentityConnectorConfig.class.getName(), siftConfigConnector, null);

            IdentityFraudDetector siftFraudDetector = new SiftFraudDetector();
            SiftDataHolder.getInstance().setSiftFraudDetector(siftFraudDetector);
            bundleContext.registerService(IdentityFraudDetector.class.getName(), siftFraudDetector, null);
        } catch (Throwable e) {
            LOG.error("Error while activating SiftServiceComponent.", e);
        }
    }

    @Deactivate
    protected void deactivate(ComponentContext context) {

        JsFunctionRegistry jsFunctionRegistry = SiftDataHolder.getInstance()
                .getJsFunctionRegistry();
        if (jsFunctionRegistry != null) {
            jsFunctionRegistry.deRegister(JsFunctionRegistry.Subsystem.SEQUENCE_HANDLER, FUNC_CALL_SIFT);
            jsFunctionRegistry.deRegister(JsFunctionRegistry.Subsystem.SEQUENCE_HANDLER, FUNC_PUBLISH_LOGIN_TO_SIFT);
        }
    }

    @Reference(
            service = JsFunctionRegistry.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetJsFunctionRegistry"
    )
    public void setJsFunctionRegistry(JsFunctionRegistry jsFunctionRegistry) {

        SiftDataHolder.getInstance().setJsFunctionRegistry(jsFunctionRegistry);
    }

    public void unsetJsFunctionRegistry(JsFunctionRegistry jsFunctionRegistry) {

        SiftDataHolder.getInstance().setJsFunctionRegistry(null);
    }

    @Reference(
            name = "identityCoreInitializedEventService",
            service = IdentityCoreInitializedEvent.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetIdentityCoreInitializedEventService")
    protected void setIdentityCoreInitializedEventService(IdentityCoreInitializedEvent
                                                                  identityCoreInitializedEvent) {

    /* Reference IdentityCoreInitializedEvent service to guarantee that this component will wait until identity core
         is started. */
    }

    protected void unsetIdentityCoreInitializedEventService(IdentityCoreInitializedEvent
                                                                    identityCoreInitializedEvent) {

    /* Reference IdentityCoreInitializedEvent service to guarantee that this component will wait until identity core
         is started. */
    }

    @Reference(
            name = "IdentityGovernanceService",
            service = org.wso2.carbon.identity.governance.IdentityGovernanceService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetIdentityGovernanceService")
    protected void setIdentityGovernanceService(IdentityGovernanceService identityGovernanceService) {

        SiftDataHolder.getInstance().setIdentityGovernanceService(identityGovernanceService);
    }

    protected void unsetIdentityGovernanceService(IdentityGovernanceService identityGovernanceService) {

        SiftDataHolder.getInstance().setIdentityGovernanceService(null);
    }

    @Reference(
            name = "organization.management.service",
            service = OrganizationManager.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetOrganizationManager")
    protected void setOrganizationManager(OrganizationManager organizationManager) {

        SiftDataHolder.getInstance().setOrganizationManager(organizationManager);
    }

    protected void unsetOrganizationManager(OrganizationManager organizationManager) {

        SiftDataHolder.getInstance().setOrganizationManager(null);
    }
}
