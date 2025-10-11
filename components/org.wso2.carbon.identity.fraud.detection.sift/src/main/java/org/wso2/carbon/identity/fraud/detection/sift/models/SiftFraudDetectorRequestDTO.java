package org.wso2.carbon.identity.fraud.detection.sift.models;

import org.wso2.carbon.identity.fraud.detectors.core.constant.FraudDetectorConstants;
import org.wso2.carbon.identity.fraud.detectors.core.model.FraudDetectorRequestDTO;

import java.util.Map;

public class SiftFraudDetectorRequestDTO extends FraudDetectorRequestDTO {

    private boolean returnRiskScore;
    private boolean returnWorkflowDecision;

    public SiftFraudDetectorRequestDTO(FraudDetectorConstants.FraudDetectionEvents eventName,
                                       Map<String, Object> properties) {

        super(eventName, properties);
        this.returnRiskScore = false;
        this.returnWorkflowDecision = false;
    }

    public boolean isReturnRiskScore() {

        return returnRiskScore;
    }

    public void setReturnRiskScore(boolean returnRiskScore) {

        this.returnRiskScore = returnRiskScore;
    }

    public boolean isReturnWorkflowDecision() {

        return returnWorkflowDecision;
    }

    public void setReturnWorkflowDecision(boolean returnWorkflowDecision) {

        this.returnWorkflowDecision = returnWorkflowDecision;
    }
}
