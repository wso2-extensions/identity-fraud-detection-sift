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
package org.wso2.carbon.identity.fraud.detection.sift.models;

import org.wso2.carbon.identity.fraud.detectors.core.constant.FraudDetectorConstants;
import org.wso2.carbon.identity.fraud.detectors.core.model.FraudDetectorRequestDTO;

import java.util.Map;

/**
 * Data Transfer Object for Sift Fraud Detector Request.
 */
public class SiftFraudDetectorRequestDTO extends FraudDetectorRequestDTO {

    private static final long serialVersionUID = 272813212488697277L;
    private boolean returnRiskScore;
    private boolean returnWorkflowDecision;

    /**
     * Constructor to create a SiftFraudDetectorRequestDTO with the given event name and properties.
     *
     * @param eventName  Name of the fraud detection event.
     * @param properties Map of properties related to the event.
     */
    public SiftFraudDetectorRequestDTO(FraudDetectorConstants.FraudDetectionEvents eventName,
                                       Map<String, Object> properties) {

        super(eventName, properties);
        this.returnRiskScore = false;
        this.returnWorkflowDecision = false;
    }

    /**
     * Constructor to create a SiftFraudDetectorRequestDTO from an existing FraudDetectorRequestDTO.
     *
     * @param requestDTO Existing FraudDetectorRequestDTO.
     */
    public SiftFraudDetectorRequestDTO(FraudDetectorRequestDTO requestDTO) {

        super(requestDTO.getEventName(), requestDTO.getProperties());
        super.setLogRequestPayload(requestDTO.isLogRequestPayload());
        super.setInterruptFlow(requestDTO.isInterruptFlow());
        this.returnRiskScore = false;
        this.returnWorkflowDecision = false;
    }

    /**
     * Returns whether to return risk score.
     *
     * @return true if risk score is to be returned, false otherwise.
     */
    public boolean isReturnRiskScore() {

        return returnRiskScore;
    }

    /**
     * Sets whether to return risk score.
     *
     * @param returnRiskScore true if risk score is to be returned, false otherwise.
     */
    public void setReturnRiskScore(boolean returnRiskScore) {

        this.returnRiskScore = returnRiskScore;
    }

    /**
     * Returns whether to return workflow decision.
     *
     * @return true if workflow decision is to be returned, false otherwise.
     */
    public boolean isReturnWorkflowDecision() {

        return returnWorkflowDecision;
    }

    /**
     * Sets whether to return workflow decision.
     *
     * @param returnWorkflowDecision true if workflow decision is to be returned, false otherwise.
     */
    public void setReturnWorkflowDecision(boolean returnWorkflowDecision) {

        this.returnWorkflowDecision = returnWorkflowDecision;
    }
}
