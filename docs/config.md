# Configuring Sift Fraud Detection

Sift uses machine learning and real-time data analysis to detect fraud. You can use Sift fraud detection with WSO2 Identity Server by following the steps below.

## Prerequisites
- You need to have a Sift account. If you do not have an account, create one by visiting the [Sift website](https://sift.com/).

## Install the Sift connector

**Step 1:** Extract the project artifacts
1. Clone the `identity-fraud-sift-int` repository.
2. Build the project by running the ```mvn clean install``` command in the root directory.

Note : The latest project artifacts can also be downloaded from the Connector Store (https://store.wso2.com/connector/identity-fraud-detection-sift). 

**Step 2:** Deploy the Sift connector

1. In the cloned repository, navigate to the `/components/org.wso2.carbon.identity.fraud.detection.sift/target` directory.
2. Copy the `org.wso2.carbon.identity.fraud.detection.sift-<version>-SNAPSHOT.jar` file to the `<IS_HOME>/repository/components/dropins` directory.
3. Restart the WSO2 Identity Server.

## Access the Console UI for the Sift connector

Once the connector is added successfully to WSO2 Identity Server, the Sift connector UI will be accessible from the Console, which enables developers to easily configure Sift for their organization by adding the API key.
To do so,
  1. In the WSO2 Console, go to `Login and Registration` section and click on `Sift Configuration`.

![Configuring Sift in WSO2 Console](../images/wso2console.png)

Add the `API key` you received from Sift.

## Sift Fraud Detection with Conditional Authentication

WSO2 Identity Server offers the following Sift-related functions that can be utilized in your conditional authentication scripts, enabling seamless integration of Sift into the user authentication process.

**`getSiftRiskScoreForLogin()`**

- This function returns the Sift risk score for a given login event, which is a value between 0 and 1. Higher the score, greater the risk.
- In the case of an error, this function returns -1.
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

### Enable Logging


Including `"isLoggingEnabled": true` as an additional parameter in the functions activates logging for Sift fraud detection. When used with `getSiftRiskScoreForLogin`, it logs the risk score returned by Sift, and when applied to `publishLoginEventToSift`, it logs the payload sent to Sift.

### Enable Sift fraud detection

To enable Sift fraud detection for your application:

1. On the Console, go to **Applications**.
2. Go to the **Login Flow** tab of the application and enable **Conditional Authentication**.
3. Add a conditional authentication script and Click **Update**.

The following example conditional authentication script is for a scenario where the authentication fails if the risk score exceeds 0.5.

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
            riskScore = riskScore
            if (riskScore == -1) {
                console.log("Error occured while obtaining Sift score.");
            }
            if (riskScore > 0.7) {
                publishLoginEventToSift(context, "LOGIN_FAILED", additionalParams);
                sendError(errorPage, suspiciousLoginError);
            } else if (riskScore > 0.5) {
                console.log("Success login. Stepping up due to the risk.");
                executeStep(2);
            } 
            else {
                publishLoginEventToSift(context, "LOGIN_SUCCESS", additionalParams);
            }
        }
    });
};
```
