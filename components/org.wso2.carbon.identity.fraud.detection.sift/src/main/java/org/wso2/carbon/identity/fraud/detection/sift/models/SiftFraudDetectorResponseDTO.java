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
import org.wso2.carbon.identity.fraud.detectors.core.model.FraudDetectorResponseDTO;

/**
 * Data Transfer Object for Sift Fraud Detector Response.
 */
public class SiftFraudDetectorResponseDTO extends FraudDetectorResponseDTO {

    private double riskScore;
    private String workflowDecision;

    /**
     * Constructor to create a SiftFraudDetectorResponseDTO with the given status and event name.
     *
     * @param status    Execution status of the fraud detection.
     * @param eventName Name of the fraud detection event.
     */
    public SiftFraudDetectorResponseDTO(FraudDetectorConstants.ExecutionStatus status,
                                        FraudDetectorConstants.FraudDetectionEvents eventName) {

        super(status, eventName);
    }

    /**
     * Sets the risk score.
     *
     * @param riskScore Risk score to be set.
     */
    public void setRiskScore(double riskScore) {

        this.riskScore = riskScore;
    }

    /**
     * Returns the risk score.
     *
     * @return Risk score.
     */
    public double getRiskScore() {

        return riskScore;
    }

    /**
     * Sets the workflow decision.
     *
     * @param workflowDecision Workflow decision to be set.
     */
    public void setWorkflowDecision(String workflowDecision) {

        this.workflowDecision = workflowDecision;
    }

    /**
     * Returns the workflow decision.
     *
     * @return Workflow decision.
     */
    public String getWorkflowDecision() {

        return workflowDecision;
    }
}
