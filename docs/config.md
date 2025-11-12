# Configuring Sift Fraud Detection

Sift uses machine learning and real-time data analysis to detect fraud. You can use Sift fraud detection with WSO2 Identity Server by following the steps below.

## Prerequisites
- You need to have a Sift account. If you do not have an account, create one by visiting the [Sift website](https://sift.com/).

## Install the Sift connector

The latest project artifacts can be downloaded from the Connector Store (https://store.wso2.com/connector/identity-fraud-detection-sift).
Below are the artifacts to be downloaded from the connector store.
1. `org.wso2.carbon.identity.fraud.detection.sift-<version>.jar` - The Sift connector jar file.
2. `sift-java-<version>.jar` - The Sift Java SDK jar file.

## Deploying the Sift artifacts

Follow the steps below to deploy the Sift connector and the Sift Java SDK in WSO2 Identity Server.

1. Copy the `org.wso2.carbon.identity.fraud.detection.sift-<version>.jar` file to the `<IS_HOME>/repository/components/dropins` directory.
2. Copy the `sift-java-<version>.jar` file to the `<IS_HOME>/repository/components/lib` directory.
3. Restart the WSO2 Identity Server.

## Access the Console UI for the Sift connector and Fraud Detection Configuration

After deploying the required artifacts, you can access the Sift Connector UI from the WSO2 Identity Server Console by navigating to the `Login and Registration` 
section and selecting `Sift Configuration`, where you can manage all available Sift fraud detection configurations.

### Sift connector configurations
Add the `API Key` received from Sift to enable communication between WSO2 Identity Server and Sift.

### Fraud Detection Configurations
WSO2 Identity Server provides options to modify the event payloads sent to the Fraud Detection integration based on the requirements.

#### Information to be included in the event payload
1. Enable the `Include user profile information in the event payload` option to include user profile information such as `email`, `mobile`, and `name` in the event payload sent to Sift.
2. Enable the `Include user device metadata in the event payload` option to include user device metadata such as `IP address` and `User Agent` in the event payload sent to Sift.

#### Events to Publish
Following are the events that can be published to Sift for fraud detection.
1. **Registrations** - Enable this option to publish user registration events to Sift.
2. **Credential Updates** - Enable this option to publish user credential update events to Sift.
3. **User Profile Updates** - Enable this option to publish user profile update events to Sift.
4. **Logins** - Enable this option to publish user login events to Sift.
5. **Logouts** - Enable this option to publish user logout events to Sift.
6. **User Verifications** - Enable this option to publish notification based user verification events to Sift.

#### Diagnostic Logging
Enable the `Log event payloads locally` option to log the event payloads sent to the Sift as diagnostic logs in WSO2 Identity Server.

![Configuring Sift in WSO2 Console](../images/wso2console.png)

## Fraud Detection invoking mechanisms
WSO2 Identity Server allows you to invoke Sift fraud detection through the following mechanisms.
- **Event Publishing** - Since the Conditional Authentication approach is restricted to login events only, you can use the Event Publishing approach to publish other user events such as registration,
  credential update, profile update, logout, and user verification events to Sift for fraud detection.
- **Conditional Authentication** - You can use Sift fraud detection in your conditional authentication scripts to make authentication decisions based on the risk score or workflow decision returned by Sift.

### Sift Fraud Detection through Event Publishing

WSO2 Identity Server allows you to publish various user events to **Sift** for fraud detection using its **Event Publishing** mechanism.  
Once the fraud detection configurations are set up, the relevant events will be automatically published to Sift — no additional configuration steps are required.

#### User Data Published to Sift

Sift requires specific user information to perform fraud analysis.  
The following user attributes are included in the event payload. These fields can be selectively enabled or disabled through the Fraud Detection configuration.

**User Information**

| User Information | Description                                                                                          |
|------------------|------------------------------------------------------------------------------------------------------|
| **Email**        | The user's registered email address.                                                                 |
| **Mobile**       | The user's mobile phone number. (Mobile numbers will be published only if they are in E.164 format.) |
| **Name**         | The user's full name.<br/>If the full name is not available, the first or last name will be used.    |

**Important:**<br/>
The value published for the `$user_id` property is not the actual user UUID stored in the system.
By default, the event payload includes a hashed value of the username as the `$user_id`.
To uniquely identify users, the actual user UUID is published separately in the event payload under the 
`user_uuid` field. Therefore, you should use the `user_uuid` field in Sift to reliably and uniquely identify users 
in your system.

**User Browser and Device Metadata**

| Metadata       | Description                                                                 |
|----------------|-----------------------------------------------------------------------------|
| **IP Address** | The user's IP address at the time of the event.                             |
| **User Agent** | The browser or device user agent string associated with the user's session. |


### Sift Fraud Detection with Conditional Authentication

WSO2 Identity Server offers the following Sift-related functions that can be utilized in your conditional authentication scripts, enabling seamless integration of Sift into the user authentication process.

**`getSiftRiskScoreForLogin()`**

- This function returns the Sift risk score for a given login event, which is a value between 0 and 1. Higher the score, greater the risk.
- If an error occurs due to an invalid API key, network issue or a Sift server issue, this function returns a value of -1.
- The function takes the following arguments.
    - `AuthenticationContext` - current authentication context.
    - `LoginStatus` - Whether the user authentication was successful or not. Accepted values `LOGIN_SUCCESS`, `LOGIN_FAILED`.
    - `AdditionalParameters` - Any additional parameters can be sent to Sift.

**`getSiftWorkflowDecision()`**

- This function returns the Sift decision ID for a given login event. The decision ID is a unique identifier for the decision selected for the login event during the workflow execution. 
Workflows and decisions can be configured through the Sift console.
- If an error occurs due to an invalid API key, network issue or a Sift server issue, this function returns a null value.
- The function takes the following arguments.
  - `AuthenticationContext` - current authentication context.
  - `LoginStatus` - Whether the user authentication was successful or not. Accepted values `LOGIN_SUCCESS`, `LOGIN_FAILED`.
  - `AdditionalParameters` - Any additional parameters can be sent to Sift.


**`publishLoginEventInfoToSift`**

- This function publishes the successful or failed login events to Sift. This informs Sift that the current login attempt was successful/failed.
    - `AuthenticationContext` - current authentication context.
    - `LoginStatus` - Whether the complete login flow was successful or not. Accepted values are `LOGIN_SUCCESS`, `LOGIN_FAILED`.
    - `AdditionalParameters` - Any additional parameters can be sent to Sift.

By default, Identity Server sends the user ID, session ID, IP address, and user agent to Sift.
The user ID is a mandatory field, while the other fields are optional. All four parameters can be overridden by including them as additional parameters in the functions.
To prevent Identity Server from sending the optional parameters to Sift, set empty strings to their values.

```javascript
var additionalParams = {
    "$ip": "",
    "$user_agent": "",
    "$session_id": ""
}
```

#### Enable Logging

Including `"loggingEnabled": true` as an additional parameter in the functions activates logging for Sift fraud detection. When used with `getSiftRiskScoreForLogin`, it logs the payload sent to Sift and the risk score returned by Sift, and when applied to `publishLoginEventToSift`, it logs the payload sent to Sift.

#### Enable Sift fraud detection

To enable Sift fraud detection for your application:

1. On the Console, go to **Applications**.
2. Go to the **Login Flow** tab of the application and enable **Conditional Authentication**.
3. Add a conditional authentication script and Click **Update**.

### Examples

#### Workflow Based

Workflows can be configured in the Sift console to define the decisions to be made based on various parameters, including the risk score.
The getSiftWorkflowDecision function returns the decision ID configured in the Sift console.

The following example conditional authentication script is for a scenario where,
- The authentication fails if the decision id is "session_looks_bad_account_takeover".
- Prompts for additional authentication if the decision id is "mfa_account_takeover".
- Publishes a login fail event to Sift, if authentication fails.

```javascript
var additionalParams = {
    "loggingEnabled": true,
    "$user_agent": "",
}
var errorPage = '';
var suspiciousLoginError = {
    'status': 'Login Restricted',
    'statusMsg': 'You login attempt was identified as suspicious.'
};

var onLoginRequest = function (context) {
    executeStep(1, {
        onSuccess: function (context) {
            var workflowDecision = getSiftWorkflowDecision(context, "LOGIN_SUCCESS", additionalParams);
            if (workflowDecision == null) {
                console.log("Error occured while obtaining Sift score.");
            }
            if (workflowDecision == "session_looks_bad_account_takeover") {
                sendError(errorPage, suspiciousLoginError);
            } else if (workflowDecision == "mfa_account_takeover") {
                executeStep(2);
            }
        },
        onFail: function (context) {
            publishLoginEventToSift(context, 'LOGIN_FAILED', additionalParams);
        }
    });
};
```

#### Risk Score Based

The following example conditional authentication script is for a scenario where,
- The authentication fails if the risk score exceeds 0.7.
- Prompts for additional authentication if the risk score is between 0.5 and 0.7.
- Publishes a login fail event to Sift, if authentication fails.

```javascript
var additionalParams = {
    "loggingEnabled": true,
    "$user_agent": "",
}
var errorPage = '';
var suspiciousLoginError = {
    'status': 'Login Restricted',
    'statusMsg': 'You login attempt was identified as suspicious.'
};

var onLoginRequest = function (context) {
    executeStep(1, {
        onSuccess: function (context) {
            var riskScore = getSiftRiskScoreForLogin(context, "LOGIN_SUCCESS", additionalParams);
            if (riskScore == -1) {
                console.log("Error occured while obtaining Sift score.");
            }
            if (riskScore > 0.7) {
                sendError(errorPage, suspiciousLoginError);
            } else if (riskScore > 0.5) {
                executeStep(2);
            }
        },
        onFail: function (context) {
            publishLoginEventToSift(context, 'LOGIN_FAILED', additionalParams);
        }
    });
};
```
