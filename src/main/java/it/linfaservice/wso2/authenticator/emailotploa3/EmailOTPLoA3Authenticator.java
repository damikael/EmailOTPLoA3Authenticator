/*
* Copyright (c) 2017, AgID - Agenzia per l'Italia Digitale
* Developer: Michele D'Amico - Linfa Service
* All Rights Reserved.
*
* This software is licensed under the Apache License,
* Version 2.0 (the "License"); you may not use this file except
* in compliance with the License.
* You may obtain a copy of the License at
*
*      http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing,
* software distributed under the License is distributed on an
* "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
* KIND, either express or implied.  See the License for the
* specific language governing permissions and limitations
* under the License.
*/
package it.linfaservice.wso2.authenticator.emailotploa3;
 
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.common.model.User;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import it.linfaservice.wso2.authenticator.emailotploa3.internal.EmailOTPLoA3AuthenticatorServiceComponent;
import org.wso2.carbon.identity.application.authentication.framework.AbstractApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.LocalApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.config.ConfigurationFacade;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.exception.InvalidCredentialsException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.user.core.common.AbstractUserStoreManager;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;
 
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

import org.apache.commons.lang.StringUtils;
import org.wso2.carbon.extension.identity.helper.FederatedAuthenticatorUtil;
import org.wso2.carbon.identity.application.authentication.framework.*;
import org.wso2.carbon.identity.application.authentication.framework.exception.*;
import org.wso2.carbon.identity.application.authentication.framework.config.model.StepConfig;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.sso.saml.util.SAMLSSOUtil;
import org.wso2.carbon.identity.application.authenticator.oidc.OpenIDConnectAuthenticator;
import org.wso2.carbon.identity.authenticator.emailotp.EmailOTPAuthenticator;
import org.wso2.carbon.identity.authenticator.emailotp.EmailOTPAuthenticatorConstants;
import java.util.regex.Pattern;
import java.util.regex.Matcher;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;


public class EmailOTPLoA3Authenticator extends EmailOTPAuthenticator implements FederatedApplicationAuthenticator {
 
    private static final long serialVersionUID = 4345351156975223999L;
    private static final Log log = LogFactory.getLog(EmailOTPLoA3Authenticator.class);
 
 
    @Override
    protected void initiateAuthenticationRequest(HttpServletRequest request, HttpServletResponse response, AuthenticationContext context) throws AuthenticationFailedException {

        Map<String, String> params = getAuthenticatorConfig().getParameterMap();
        String LOA2 = (String)params.get("AuthnContextClassRefLoA2");
        String LOA3 = (String)params.get("AuthnContextClassRefLoA3");
        String LOA4 = (String)params.get("AuthnContextClassRefLoA4");

        try {
            String saml = context.getAuthenticationRequest().getRequestQueryParam("SAMLRequest")[0];
            String saml_decoded = SAMLSSOUtil.decode(saml);
            Pattern pattern = Pattern.compile("<saml:AuthnContextClassRef>(.+?)</saml:AuthnContextClassRef>");
            Matcher matcher = pattern.matcher(saml_decoded);
            matcher.find();
            String loa = matcher.group(1);

            log.info("LoA: " + loa);
            context.setProperty("LoA", loa);

            if(loa.equals(LOA2)) {

                AuthenticatedUser authenticatedUser = (AuthenticatedUser) context.getProperty(EmailOTPAuthenticatorConstants.AUTHENTICATED_USER);
                processFirstStepOnly(authenticatedUser, context);


            } else {

                super.initiateAuthenticationRequest(request, response, context);

            }


        } catch (Exception e) {
            throw new AuthenticationFailedException(e.getMessage(), e);
        }
    }

    private void processFirstStepOnly(AuthenticatedUser authenticatedUser, AuthenticationContext context) {
        //the authentication flow happens with basic authentication (First step only).
        StepConfig stepConfig = context.getSequenceConfig().getStepMap().get(context.getCurrentStep() - 1);
        if (stepConfig.getAuthenticatedAutenticator().getApplicationAuthenticator() instanceof LocalApplicationAuthenticator) {
            FederatedAuthenticatorUtil.updateLocalAuthenticatedUserInStepConfig(context, authenticatedUser);
            context.setProperty(EmailOTPAuthenticatorConstants.AUTHENTICATION, EmailOTPAuthenticatorConstants.BASIC);
        } else {
            FederatedAuthenticatorUtil.updateAuthenticatedUserInStepConfig(context, authenticatedUser);
            context.setProperty(EmailOTPAuthenticatorConstants.AUTHENTICATION, EmailOTPAuthenticatorConstants.FEDERETOR);
        }
    }

    protected void processAuthenticationResponse(HttpServletRequest request, HttpServletResponse response, AuthenticationContext context) throws AuthenticationFailedException {
        String loa = (String)context.getProperty("LoA");
        log.info("Response to LoA: " + loa);
        super.processAuthenticationResponse(request, response, context);
    }
 

    @Override
    public String getContextIdentifier(HttpServletRequest request) {
        return request.getParameter("sessionDataKey");
    }

    @Override
    protected boolean retryAuthenticationEnabled() {
        return super.retryAuthenticationEnabled();
    }

    @Override
    public String getFriendlyName() {
        //Set the name to be displayed in local authenticator drop down lsit
        return EmailOTPLoA3AuthenticatorConstants.AUTHENTICATOR_FRIENDLY_NAME;
    }

    @Override
    public boolean canHandle(HttpServletRequest httpServletRequest) {
        return super.canHandle(httpServletRequest);
    }

    @Override
    public String getName() {
        return EmailOTPLoA3AuthenticatorConstants.AUTHENTICATOR_NAME;
    }  
}