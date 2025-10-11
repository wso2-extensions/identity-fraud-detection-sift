package org.wso2.carbon.identity.fraud.detection.sift.models;

import org.wso2.carbon.identity.fraud.detectors.core.constant.FraudDetectorConstants;
import org.wso2.carbon.identity.fraud.detectors.core.model.FraudDetectorResponseDTO;

public class SiftFraudDetectorResponseDTO extends FraudDetectorResponseDTO {

    private double riskScore;
    private String workflowDecision;

    public SiftFraudDetectorResponseDTO(FraudDetectorConstants.ExecutionStatus status) {

        super(status);
    }

    public void setRiskScore(double riskScore) {

        this.riskScore = riskScore;
    }

    public double getRiskScore() {

        return riskScore;
    }

    public void setWorkflowDecision(String workflowDecision) {

        this.workflowDecision = workflowDecision;
    }

    public String getWorkflowDecision() {

        return workflowDecision;
    }
}
