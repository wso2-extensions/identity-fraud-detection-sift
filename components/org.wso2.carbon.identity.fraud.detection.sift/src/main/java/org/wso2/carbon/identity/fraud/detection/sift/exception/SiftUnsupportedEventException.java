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
package org.wso2.carbon.identity.fraud.detection.sift.exception;

import org.wso2.carbon.identity.fraud.detection.core.exception.UnsupportedFraudDetectionEventException;

/**
 * Exception class for unsupported Sift events.
 */
public class SiftUnsupportedEventException extends UnsupportedFraudDetectionEventException {

    private static final long serialVersionUID = -9040277606209652359L;

    /**
     * Constructor for SiftUnsupportedEventException.
     *
     * @param message Error message.
     */
    public SiftUnsupportedEventException(String message) {

        super(message);
    }

    /**
     * Constructor for SiftUnsupportedEventException.
     *
     * @param errorCode Error code.
     * @param message   Error message.
     */
    public SiftUnsupportedEventException(String errorCode, String message) {

        super(errorCode, message);
    }

    /**
     * Constructor for SiftUnsupportedEventException.
     *
     * @param message Error message.
     * @param cause   The cause of the exception.
     */
    public SiftUnsupportedEventException(String message, Throwable cause) {

        super(message, cause);
    }

    /**
     * Constructor for SiftUnsupportedEventException.
     *
     * @param errorCode Error code.
     * @param message   Error message.
     * @param cause     The cause of the exception.
     */
    public SiftUnsupportedEventException(String errorCode, String message, Throwable cause) {

        super(errorCode, message, cause);
    }
}
