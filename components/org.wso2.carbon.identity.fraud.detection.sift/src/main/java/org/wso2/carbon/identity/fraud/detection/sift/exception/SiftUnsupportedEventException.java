package org.wso2.carbon.identity.fraud.detection.sift.exception;

import org.wso2.carbon.identity.fraud.detectors.core.exception.UnsupportedFraudDetectionEventException;

public class SiftUnsupportedEventException extends UnsupportedFraudDetectionEventException {

    public SiftUnsupportedEventException(String message) {

        super(message);
    }

    public SiftUnsupportedEventException(String errorCode, String message) {

        super(errorCode, message);
    }

    public SiftUnsupportedEventException(String message, Throwable cause) {

        super(message, cause);
    }

    public SiftUnsupportedEventException(String errorCode, String message, Throwable cause) {

        super(errorCode, message, cause);
    }
}
