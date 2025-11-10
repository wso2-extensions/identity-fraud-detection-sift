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
package org.wso2.carbon.identity.fraud.detection.sift.util;

import org.apache.commons.lang.StringUtils;
import org.json.JSONObject;
import org.wso2.carbon.identity.fraud.detection.sift.Constants;

import static org.wso2.carbon.identity.fraud.detection.sift.Constants.EMAIL_KEY;
import static org.wso2.carbon.identity.fraud.detection.sift.Constants.PHONE_KEY;
import static org.wso2.carbon.identity.fraud.detection.sift.Constants.SMS_KEY;
import static org.wso2.carbon.identity.fraud.detection.sift.Constants.USERNAME_KEY;
import static org.wso2.carbon.identity.fraud.detection.sift.Constants.USER_EMAIL_KEY;
import static org.wso2.carbon.identity.fraud.detection.sift.Constants.VERIFICATION_PHONE_NUMBER_KEY;
import static org.wso2.carbon.identity.fraud.detection.sift.Constants.VERIFICATION_TYPE_KEY;
import static org.wso2.carbon.identity.fraud.detection.sift.Constants.VERIFIED_VALUE_KEY;

/**
 * Utility class for Sift logging.
 */
public class SiftLogUtil {

    private static final String DEFAULT_EMAIL_MASKING_REGEX = "(?<=.{3}).(?=[^@]*?@)";
    private static final String MASKING_CHARACTER = "*";
    private static final int MOBILE_NUMBER_UNMASKED_DIGITS = 4;


    /**
     * Mask the sensitive data in the payload before logging.
     *
     * @param payload Payload to be masked.
     * @return Masked payload.
     */
    public static String getMaskedSiftPayload(JSONObject payload) {

        JSONObject maskedPayload = new JSONObject(payload.toString());
        maskApiKey(maskedPayload);
        maskEmailAddress(maskedPayload);
        maskMobileNumber(maskedPayload);
        maskVerifiedValue(maskedPayload);
        maskUsername(maskedPayload);
        return maskedPayload.toString();
    }

    /**
     * Mask the API key in the payload.
     *
     * @param maskedPayload Payload to be masked.
     */
    private static void maskApiKey(JSONObject maskedPayload) {

        String apiKey = maskedPayload.has(Constants.API_KEY) ? maskedPayload.getString(Constants.API_KEY) : null;
        if (StringUtils.isEmpty(apiKey)) {
            return;
        }

        int length = apiKey.length();
        int maskStart = length / 2;
        StringBuilder maskedAPIKey = new StringBuilder(apiKey.substring(0, maskStart));
        for (int i = maskStart; i < length; i++) {
            maskedAPIKey.append('*');
        }
        maskedPayload.put(Constants.API_KEY, maskedAPIKey.toString());
    }

    /**
     * Mask the email address in the payload.
     *
     * @param maskedPayload Payload to be masked.
     */
    private static void maskEmailAddress(JSONObject maskedPayload) {

        String email = maskedPayload.has(USER_EMAIL_KEY) ? maskedPayload.getString(USER_EMAIL_KEY) : null;
        if (StringUtils.isEmpty(email)) {
            return;
        }
        maskedPayload.put(USER_EMAIL_KEY, getMaskedEmailAddress(email));
    }

    /**
     * Get the masked email address.
     *
     * @param email Email address to be masked.
     * @return Masked email address.
     */
    private static String getMaskedEmailAddress(String email) {

        return email.replaceAll(DEFAULT_EMAIL_MASKING_REGEX, MASKING_CHARACTER);
    }

    /**
     * Mask the mobile number in the payload.
     *
     * @param maskedPayload Payload to be masked.
     */
    private static void maskMobileNumber(JSONObject maskedPayload) {

        String verificationPhoneNumber = maskedPayload.has(VERIFICATION_PHONE_NUMBER_KEY) ?
                maskedPayload.getString(VERIFICATION_PHONE_NUMBER_KEY) : null;
        String phone = maskedPayload.has(PHONE_KEY) ? maskedPayload.getString(PHONE_KEY) : null;

        if (StringUtils.isEmpty(verificationPhoneNumber) && StringUtils.isEmpty(phone)) {
            return;
        }

        if (StringUtils.isNotEmpty(verificationPhoneNumber)) {
            String screenValue = getMaskedMobileNumber(verificationPhoneNumber);
            maskedPayload.put(VERIFICATION_PHONE_NUMBER_KEY, screenValue);
        } else if (StringUtils.isNotEmpty(phone)) {
            String screenValue = getMaskedMobileNumber(phone);
            maskedPayload.put(PHONE_KEY, screenValue);
        }
    }

    /**
     * Get the masked mobile number.
     *
     * @param verificationPhoneNumber Mobile number to be masked.
     * @return Masked mobile number.
     */
    private static String getMaskedMobileNumber(String verificationPhoneNumber) {

        int screenAttributeLength = verificationPhoneNumber.length();
        String screenValue = verificationPhoneNumber.substring(
                screenAttributeLength - MOBILE_NUMBER_UNMASKED_DIGITS, screenAttributeLength);
        String hiddenScreenValue = verificationPhoneNumber.substring(0,
                screenAttributeLength - MOBILE_NUMBER_UNMASKED_DIGITS);
        screenValue = new String(new char[hiddenScreenValue.length()]).
                replace("\\0", MASKING_CHARACTER).concat(screenValue);
        return screenValue;
    }

    /**
     * Mask the verified value in the payload.
     *
     * @param maskedPayload Payload to be masked.
     */
    private static void maskVerifiedValue(JSONObject maskedPayload) {

        // Use the correct key "$verification_value" when reading the incoming payload
        String verificationValue = maskedPayload.has(VERIFIED_VALUE_KEY) ?
                maskedPayload.getString(VERIFIED_VALUE_KEY) : null;
        if (StringUtils.isEmpty(verificationValue)) {
            return;
        }

        String verificationType = maskedPayload.has(VERIFICATION_TYPE_KEY) ?
                maskedPayload.getString(VERIFICATION_TYPE_KEY) : null;

        String maskedValue;
        if (SMS_KEY.equals(verificationType)) {
            maskedValue = getMaskedMobileNumber(verificationValue);
        } else if (EMAIL_KEY.equals(verificationType)) {
            maskedValue = getMaskedEmailAddress(verificationValue);
        } else {
            maskedValue = getDefaultMaskedValue(verificationValue);
        }

        maskedPayload.put(VERIFIED_VALUE_KEY, maskedValue);
    }

    /**
     * Get the default masked value by keeping the first and last character unmasked.
     *
     * @param value Value to be masked.
     * @return Masked value.
     */
    private static String getDefaultMaskedValue(String value) {

        // Mask the string by keeping the first and last character unmasked.
        String maskedValue;
        int length = value.length();
        if (length <= 2) {
            maskedValue = new String(new char[length]).replace("\\0", MASKING_CHARACTER);
        } else {
            StringBuilder maskedStr = new StringBuilder();
            maskedStr.append(value.charAt(0));
            for (int i = 1; i < length - 1; i++) {
                maskedStr.append(MASKING_CHARACTER);
            }
            maskedStr.append(value.charAt(length - 1));
            maskedValue = maskedStr.toString();
        }

        return maskedValue;
    }

    /**
     * Mask the username in the payload.
     *
     * @param maskedPayload Payload to be masked.
     */
    private static void maskUsername(JSONObject maskedPayload) {

        String username = maskedPayload.has(USERNAME_KEY) ? maskedPayload.getString(USERNAME_KEY) : null;
        if (StringUtils.isEmpty(username)) {
            return;
        }
        maskedPayload.put(USERNAME_KEY, getDefaultMaskedValue(username));
    }
}
