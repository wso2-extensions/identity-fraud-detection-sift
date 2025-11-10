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

package org.wso2.carbon.identity.fraud.detection.sift;

/**
 * Constants class to hold the constants used in the Sift connector.
 */
public class Constants {

    private Constants() {
    }

    public static final String SIFT_FRAUD_DETECTOR_CONNECTOR_NAME = "SiftFraudDetector";

    public static final String SIFT_API_URL = "https://api.sift.com/v205/events?abuse_types=account_takeover";
    public static final String RETURN_SCORE_PARAM = "&return_score=true";
    public static final String RETURN_WORKFLOW_PARAM = "&return_workflow_status=true";

    // Connector configs.

    // __secret__ prefix is used to mark the property as confidential for UI rendering.
    public static final String SIFT_API_KEY_PROP = "__secret__.sift.api.key";
    public static final String SIFT_API_KEY_PROP_NAME = "API Key";
    public static final String SIFT_API_KEY_PROP_DESC = "API key of the Sift account.";
    public static final String CONNECTOR_NAME = "sift-configuration";
    public static final String CONNECTOR_FRIENDLY_NAME = "Sift Configuration";
    public static final String CONNECTOR_CATEGORY = "Login Security";
    public static final String CONNECTOR_SUB_CATEGORY = "DEFAULT";
    public static final int CONNECTOR_ORDER = 0;

    // HTTP Client configs.
    // Timeouts in milliseconds.
    public static final int CONNECTION_TIMEOUT = 5000;
    public static final int CONNECTION_REQUEST_TIMEOUT = 5000;
    public static final int READ_TIMEOUT = 5000;

    // Identity configs.
    public static final String CONNECTION_TIMEOUT_CONFIG = "Sift.HTTPClient.ConnectionTimeout";
    public static final String CONNECTION_REQUEST_TIMEOUT_CONFIG = "Sift.HTTPClient.ConnectionRequestTimeout";
    public static final String READ_TIMEOUT_CONFIG = "Sift.HTTPClient.ReadTimeout";

    public static final String TYPE = "$type";
    public static final String LOGIN_TYPE = "$login";
    public static final String API_KEY = "$api_key";
    // Supported param keys.
    public static final String LOGIN_STATUS = "login_status";
    public static final String USER_ID_KEY = "$user_id";
    public static final String SESSION_ID_KEY = "$session_id";
    public static final String IP_KEY = "$ip";
    public static final String BROWSER_KEY = "$browser";
    public static final String USER_AGENT_KEY = "$user_agent";
    public static final String USERNAME_KEY = "$username";
    public static final String VERIFIED_VALUE_KEY = "$verified_value";
    public static final String VERIFICATION_TYPE_KEY = "$verification_type";
    public static final String EMAIL_KEY = "$email";
    public static final String SMS_KEY = "$sms";
    public static final String PHONE_KEY = "$phone";
    public static final String VERIFICATION_PHONE_NUMBER_KEY = "$verification_phone_number";
    public static final String USER_EMAIL_KEY = "$user_email";

    // Sift specific keys.
    public static final int SIFT_STATUS_OK = 0;
    public static final String SIFT_STATUS = "status";
    public static final String SIFT_SCORE_RESPONSE = "score_response";
    public static final String SIFT_SCORES = "scores";
    public static final String SIFT_ACCOUNT_TAKEOVER = "account_takeover";
    public static final String SIFT_SCORE = "score";
    public static final String SIFT_WORKFLOW_STATUSES = "workflow_statuses";
    public static final String SIFT_ABUSE_TYPES = "abuse_types";
    public static final String SIFT_ENTITY = "entity";
    public static final String SIFT_TYPE = "type";
    public static final String SIFT_SESSION = "session";
    public static final String SIFT_HISTORY = "history";
    public static final String SIFT_APP = "app";
    public static final String SIFT_DECISION = "decision";
    public static final String SIFT_CONFIG = "config";
    public static final String SIFT_DECISION_ID = "decision_id";

    // Sift custom event property keys.
    public static final String USER_UUID = "user_uuid";
    public static final String USER_CREATED_BY_ADMIN = "user_created_by_admin";
    public static final String LOGOUT_TRIGGERED_FROM_APPLICATION = "logout_triggered_from_application";
    public static final String USER_PROFILE_UPDATED_BY_ADMIN = "user_profile_updated_by_admin";
    public static final String VERIFIED_BY_END_USER = "verified_by_end_user";
    public static final String ACTION_PERFORMED_BY_ADMIN = "action_performed_by_admin";

    // Sift event property values.
    public static final String MANUAL_REVIEW_VERIFICATION_TYPE = "$manual_review";

    public static final String HTTP_SERVLET_REQUEST = "HttpServletRequest";
    public static final String USER_AGENT_HEADER = "User-Agent";
    public static final String REMOTE_ADDRESS = "remoteAddress";
    public static final String CONTENT_TYPE_HEADER = "Content-Type";

    public static final String LOGGING_ENABLED = "loggingEnabled";

    public static final double DEFAULT_ERROR_VALUE = -1;

    // Internal constants
    public static final String CUSTOM_PARAMS = "customParams";
    public static final String AUTHENTICATION_CONTEXT = "authenticationContext";
    public static final String USERNAME_USER_INPUT = "usernameUserInput";
    public static final String USER_SELF_REGISTRATION_FLOW = "isUserSelfRegistrationFlow";

    /**
     * Enum to hold the login status.
     */
    public enum LoginStatus {

        LOGIN_SUCCESS("LOGIN_SUCCESS", "$success"),
        LOGIN_FAILED("LOGIN_FAILED", "$failure");

        private final String status;
        private final String siftValue;

        LoginStatus(String status, String siftValue) {

            this.status = status;
            this.siftValue = siftValue;
        }

        public String getStatus() {

            return status;
        }

        public String getSiftValue() {

            return siftValue;
        }
    }

    /**
     * Enum to hold the Sift values of password update reason.
     */
    public enum PasswordUpdateReason {

        FORCED_RESET("$forced_reset"),
        FORGOT_PASSWORD("$forgot_password"),
        USER_UPDATE("$user_update");

        private final String value;

        PasswordUpdateReason(String value) {

            this.value = value;
        }

        public String getValue() {

            return value;
        }
    }

    /**
     * Enum to hold the Sift values of progress status.
     */
    public enum ProgressStatus {

        PENDING("$pending"),
        SUCCESS("$success"),
        FAILURE("$failure");

        private final String value;

        ProgressStatus(String value) {

            this.value = value;
        }

        public String getValue() {

            return value;
        }
    }

    /**
     * Enum to hold the Sift values of login failure reason.
     */
    public enum LoginFailureReason {

        WRONG_CREDENTIALS("$wrong_password"),
        ACCOUNT_SUSPENDED("$account_suspended"),
        ACCOUNT_DISABLED("$account_disabled"),
        ACCOUNT_UNKNOWN("$account_unknown");

        private final String value;

        LoginFailureReason(String value) {

            this.value = value;
        }

        public String getValue() {

            return value;
        }
    }

    /**
     * Enum to hold the Sift event types.
     */
    public enum SiftEventType {

        USER_LOGIN("$login"),
        USER_LOGOUT("$logout"),
        USER_REGISTRATION("$create_account"),
        PASSWORD_UPDATE("$update_password"),
        PROFILE_UPDATE("$update_account"),
        VERIFICATION("$verification");

        private final String value;

        SiftEventType(String value) {

            this.value = value;
        }

        public String getValue() {

            return value;
        }
    }
}
