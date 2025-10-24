package org.wso2.carbon.identity.fraud.detection.sift;

import org.apache.commons.lang.StringUtils;
import org.apache.http.HttpEntity;
import org.apache.http.HttpStatus;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.apache.http.util.EntityUtils;
import org.json.JSONObject;
import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.fraud.detection.sift.exception.SiftUnsupportedEventException;
import org.wso2.carbon.identity.fraud.detection.sift.models.SiftFraudDetectorRequestDTO;
import org.wso2.carbon.identity.fraud.detection.sift.util.SiftEventUtil;
import org.wso2.carbon.identity.fraud.detection.sift.util.SiftLoginEventUtil;
import org.wso2.carbon.identity.fraud.detection.sift.util.SiftLogoutEventUtil;
import org.wso2.carbon.identity.fraud.detection.sift.util.SiftUpdatePasswordEventUtil;
import org.wso2.carbon.identity.fraud.detection.sift.util.SiftUserRegistrationEventUtil;
import org.wso2.carbon.identity.fraud.detection.sift.util.SiftVerificationEventUtil;
import org.wso2.carbon.identity.fraud.detection.sift.util.Util;
import org.wso2.carbon.identity.fraud.detectors.core.AbstractIdentityFraudDetector;
import org.wso2.carbon.identity.fraud.detectors.core.IdentityFraudDetector;
import org.wso2.carbon.identity.fraud.detectors.core.exception.IdentityFraudDetectorException;
import org.wso2.carbon.identity.fraud.detectors.core.exception.IdentityFraudDetectorResponseException;
import org.wso2.carbon.identity.fraud.detectors.core.model.FraudDetectorRequestDTO;
import org.wso2.carbon.identity.fraud.detectors.core.model.FraudDetectorResponseDTO;

import java.io.IOException;

public class SiftFraudDetector extends AbstractIdentityFraudDetector implements IdentityFraudDetector {

    @Override
    public String getName() {

        return "SiftFraudDetector";
    }

    @Override
    public boolean canHandle(String tenantDomain) {

        try {
            return StringUtils.isNotEmpty(Util.getSiftApiKey(tenantDomain));
        } catch (FrameworkException e) {
            return false;
        }
    }

    @Override
    public FraudDetectorResponseDTO publishRequest(FraudDetectorRequestDTO fraudDetectorRequestDTO) {

        if (fraudDetectorRequestDTO instanceof SiftFraudDetectorRequestDTO) {
            return super.publishRequest(fraudDetectorRequestDTO);
        }
        return super.publishRequest(convertToSiftRequestDTO(fraudDetectorRequestDTO));
    }

    @Override
    public HttpUriRequest buildRequest(FraudDetectorRequestDTO fraudDetectorRequestDTO)
            throws IdentityFraudDetectorException {

        String payload = SiftEventUtil.buildSiftEventPayload((SiftFraudDetectorRequestDTO) fraudDetectorRequestDTO);
        String siftRequestPath = Util.buildSiftRequestPath((SiftFraudDetectorRequestDTO) fraudDetectorRequestDTO);

        HttpPost request = new HttpPost(siftRequestPath);
        request.addHeader(Constants.CONTENT_TYPE_HEADER, FrameworkConstants.ContentTypes.TYPE_APPLICATION_JSON);
        StringEntity entity = new StringEntity(payload, ContentType.APPLICATION_JSON);
        request.setEntity(entity);
        return request;
    }

    @Override
    public FraudDetectorResponseDTO handleResponse(CloseableHttpResponse closeableHttpResponse,
                                                   FraudDetectorRequestDTO requestDTO)
            throws IdentityFraudDetectorException {

        if (closeableHttpResponse.getStatusLine().getStatusCode() != HttpStatus.SC_OK) {
            throw new IdentityFraudDetectorResponseException("Error occurred while publishing event to Sift. " +
                    "HTTP error code: " + closeableHttpResponse.getStatusLine().getStatusCode());
        }

        return SiftEventUtil.handleResponse(closeableHttpResponse, requestDTO);
    }

    @Override
    public String getMaskedRequestPayload(String payload) throws IdentityFraudDetectorException {

        return Util.getMaskedSiftPayload(new JSONObject(payload));
    }

    private SiftFraudDetectorRequestDTO convertToSiftRequestDTO(FraudDetectorRequestDTO requestDTO) {

        return new SiftFraudDetectorRequestDTO(requestDTO.getEventName(), requestDTO.getProperties());
    }
}
