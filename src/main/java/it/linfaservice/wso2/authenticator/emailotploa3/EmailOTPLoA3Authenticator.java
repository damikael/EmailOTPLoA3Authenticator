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
 
import it.linfaservice.wso2.authenticator.emailotploa3.internal.EmailOTPLoA3AuthenticatorServiceComponent;
import it.linfaservice.wso2.authenticator.emailotploa3.EmailOTPLoA3AuthenticatorConstants;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.commons.lang.StringUtils;
import org.wso2.carbon.identity.application.common.model.User;
import org.wso2.carbon.identity.core.util.IdentityUtil;
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
import java.io.PrintWriter;

import org.apache.commons.lang.StringUtils;
import org.wso2.carbon.extension.identity.helper.FederatedAuthenticatorUtil;
import org.wso2.carbon.identity.application.authentication.framework.*;
import org.wso2.carbon.identity.application.authentication.framework.exception.*;
import org.wso2.carbon.identity.application.authentication.framework.config.model.SequenceConfig;
import org.wso2.carbon.identity.application.authentication.framework.config.model.StepConfig;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.application.common.model.Claim;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.sso.saml.util.SAMLSSOUtil;
import org.wso2.carbon.identity.application.authenticator.oidc.OpenIDConnectAuthenticator;
import org.wso2.carbon.identity.authenticator.emailotp.EmailOTPAuthenticator;
import org.wso2.carbon.identity.authenticator.emailotp.EmailOTPAuthenticatorConstants;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;
import java.util.regex.Pattern;
import java.util.regex.Matcher;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Enumeration;
import javax.servlet.http.HttpSession;
import javax.servlet.RequestDispatcher;
import javax.servlet.http.Cookie;




public class EmailOTPLoA3Authenticator extends EmailOTPAuthenticator implements FederatedApplicationAuthenticator {
 
    private static final long serialVersionUID = 4345351156975223999L;
    private static final Log log = LogFactory.getLog(EmailOTPLoA3Authenticator.class);
 
 
    @Override
    public AuthenticatorFlowStatus process(HttpServletRequest request, HttpServletResponse response, AuthenticationContext context) throws AuthenticationFailedException, LogoutFailedException {
        log.info("process");
        log.info("Request: ");
        Enumeration e = request.getParameterNames();
        while(e.hasMoreElements()) {
            log.info((String)e.nextElement());
        }

        // if the logout request comes, then no need to go through and complete the flow.
        if (context.isLogoutRequest()) {
            return AuthenticatorFlowStatus.SUCCESS_COMPLETED;
        } else if (StringUtils.isNotEmpty(request.getParameter(EmailOTPAuthenticatorConstants.EMAIL_ADDRESS))) {
            log.info("Requested EMAIL_ADDRESS");
            // if the request comes with EMAIL ADDRESS, it will go through this flow.
            initiateAuthenticationRequest(request, response, context);
            return AuthenticatorFlowStatus.INCOMPLETE;
        } else if (StringUtils.isEmpty(request.getParameter(EmailOTPAuthenticatorConstants.CODE))
                    && StringUtils.isEmpty(request.getParameter(EmailOTPLoA3AuthenticatorConstants.ATTRIBUTESRETURN_CONFIRMED))) {
            log.info("Requested CODE");
            // if the request comes with code, it will go through this flow.
            initiateAuthenticationRequest(request, response, context);
            log.info("Requested CODE - Authenticator: " + context.getProperty(EmailOTPAuthenticatorConstants.AUTHENTICATION));
            if (context.getProperty(EmailOTPAuthenticatorConstants.AUTHENTICATION)
                    .equals(EmailOTPAuthenticatorConstants.AUTHENTICATOR_NAME)) {
                // if the request comes with authentication is EmailOTP, it will go through this flow.
                return AuthenticatorFlowStatus.INCOMPLETE;
            } else {
                // if the request comes with authentication is basic, complete the flow.
                // redirect to page to confirm attributes
                sendToConfirmPage(request, response, context);
                return AuthenticatorFlowStatus.INCOMPLETE;
            }
        } else if (!StringUtils.isEmpty((String)context.getProperty(EmailOTPLoA3AuthenticatorConstants.ATTRIBUTESRETURN_CONFIRMED))) {
            String confirmrequest = (String)context.getProperty(EmailOTPLoA3AuthenticatorConstants.ATTRIBUTESRETURN_CONFIRMED);
            log.info("Requested CONFIRM : " + confirmrequest);
            if (confirmrequest.equals("CONFIRMREQUEST")) {
                log.info("Requested CONFIRM - TOCONFIRM");
                sendToConfirmPage(request, response, context);
                return AuthenticatorFlowStatus.INCOMPLETE;
            } else {
                // CONFIRMPAGE
                Boolean confirm = !StringUtils.isEmpty(request.getParameter("confirm"));
                Boolean annull = !StringUtils.isEmpty(request.getParameter("annulled"));
                Boolean confirmed = (confirm && !annull);

                log.info("Requested CONFIRM : " + confirmed);
                if(confirmed) {
                    log.info("CONFIRMED!");
                    return AuthenticatorFlowStatus.SUCCESS_COMPLETED;
                } else {
                    log.info("NOT CONFIRMED!");
                    sendToErrorPage(request, response, context, "Autorizzazione all'invio dei dati non concessa. Impossibile procedere.");
                    return AuthenticatorFlowStatus.INCOMPLETE;
                }
            }
        
        } else {
            return super.process(request, response, context);
        }
    }


    @Override
    protected void initiateAuthenticationRequest(HttpServletRequest request, HttpServletResponse response, AuthenticationContext context) throws AuthenticationFailedException {
        log.info("initiateAuthenticationRequest");

        Map<String, String> params = getAuthenticatorConfig().getParameterMap();
        String LOA2 = (String)params.get("AuthnContextClassRefLoA2");
        String LOA3 = (String)params.get("AuthnContextClassRefLoA3");
        String LOA4 = (String)params.get("AuthnContextClassRefLoA4");

        try {

            //throw new AuthenticationFailedException("Non è stata fornita l'autorizzazione all'invio dei dati");

            String saml = context.getAuthenticationRequest().getRequestQueryParam("SAMLRequest")[0];
            String saml_decoded = SAMLSSOUtil.decode(saml);
            Pattern pattern = Pattern.compile("<saml:AuthnContextClassRef>(.+?)</saml:AuthnContextClassRef>");
            Matcher matcher = pattern.matcher(saml_decoded);
            matcher.find();
            String loa = matcher.group(1);

            log.info("LoA: " + loa);
            context.setProperty("LoA", loa);

            AuthenticatedUser authenticatedUser = (AuthenticatedUser) context.getProperty(EmailOTPAuthenticatorConstants.AUTHENTICATED_USER);
            saveAuthenticatedUser(authenticatedUser, context);

            if(loa.equals(LOA2)) {
                // it's ok 

            } else {
                // it needs 2FA
                super.initiateAuthenticationRequest(request, response, context);
            }

            String username = context.getSubject().getAuthenticatedSubjectIdentifier();
            SequenceConfig sequenceConfig = context.getSequenceConfig();
            HashMap claimsMap = getUserAttributes(sequenceConfig.getApplicationConfig().getClaimMappings(), username, context);
            HttpSession session = request.getSession();
            session.setAttribute("REQUESTED_CLAIMS", claimsMap);
            context.setProperty(EmailOTPLoA3AuthenticatorConstants.ATTRIBUTESRETURN_CONFIRMED, "CONFIRMREQUEST");

        } catch (Exception e) {
            log.info("EXCEPTION: " + e.toString());
            throw new AuthenticationFailedException(e.getMessage(), e);
        }
    }

    private void saveAuthenticatedUser(AuthenticatedUser authenticatedUser, AuthenticationContext context) {
        log.info("saveAuthenticatedUser");
        
        //the authentication flow happens with basic authentication (First step only).
        StepConfig stepConfig = context.getSequenceConfig().getStepMap().get(context.getCurrentStep() - 1);
        if (stepConfig.getAuthenticatedAutenticator().getApplicationAuthenticator() instanceof LocalApplicationAuthenticator) {
            FederatedAuthenticatorUtil.updateLocalAuthenticatedUserInStepConfig(context, authenticatedUser);
            context.setProperty(EmailOTPAuthenticatorConstants.AUTHENTICATION, EmailOTPAuthenticatorConstants.BASIC);
        } else {
            FederatedAuthenticatorUtil.updateAuthenticatedUserInStepConfig(context, authenticatedUser);
            context.setProperty(EmailOTPAuthenticatorConstants.AUTHENTICATION, EmailOTPAuthenticatorConstants.FEDERETOR);
        }

        String username = context.getSubject().getAuthenticatedSubjectIdentifier();
        log.info("Authenticated User: " + username);
    }


    protected void sendToConfirmPage(HttpServletRequest request, HttpServletResponse response, AuthenticationContext context) throws AuthenticationFailedException { 
        log.info("sendToConfirmPage");   

        Map<String, String> params = getAuthenticatorConfig().getParameterMap();

        String queryParams = FrameworkUtils.getQueryStringWithFrameworkContextId(
                    context.getQueryParams(), context.getCallerSessionKey(),
                    context.getContextIdentifier());

        try {
            String attributesConfirmPage = (String)params.get("AttributesConfirmPage");
            String url = getRedirectURL(attributesConfirmPage, queryParams);
            log.info("Redirect to attributes confirm page: " + url);
            context.setProperty(EmailOTPLoA3AuthenticatorConstants.ATTRIBUTESRETURN_CONFIRMED, "CONFIRMPAGE");

            HttpSession session = request.getSession();
            HashMap claimsMap = (HashMap)session.getAttribute("REQUESTED_CLAIMS");
            Iterator iterator = claimsMap.entrySet().iterator();
            ArrayList claims = new ArrayList();
            while (iterator.hasNext()) {
                Map.Entry pair = (Map.Entry)iterator.next();
                claims.add(pair.getKey() + "=" + pair.getValue());
            }

            response.sendRedirect(url + "&REQUESTED_CLAIMS=" + String.join(",", claims));

        } catch (Exception e) {
            throw new AuthenticationFailedException("Authentication failed!. An IOException was caught while redirecting to confirm page. ", e);
        }
    }

    protected void sendToErrorPage(HttpServletRequest request, HttpServletResponse response, AuthenticationContext context, String errorMsg) throws AuthenticationFailedException { 
        log.info("sendToErrorPage");   

        Map<String, String> params = getAuthenticatorConfig().getParameterMap();

        String queryParams = FrameworkUtils.getQueryStringWithFrameworkContextId(
                    context.getQueryParams(), context.getCallerSessionKey(),
                    context.getContextIdentifier());

        try {
            String errorPage = (String)params.get("ErrorPage");
            String url = getRedirectURL(errorPage, queryParams);
            log.info("Redirect to error page: " + url + "&errorMsg=" + errorMsg);
            response.sendRedirect(url + "&errorMsg=" + errorMsg);

        } catch (Exception e) {
            throw new AuthenticationFailedException("Authentication failed!. An IOException was caught while redirecting to error page. ", e);
        }
    }    

    protected void processAuthenticationResponse(HttpServletRequest request, HttpServletResponse response, AuthenticationContext context) throws AuthenticationFailedException {
        log.info("processAuthenticationResponse");

        String loa = (String)context.getProperty("LoA");
        log.info("Response to LoA: " + loa);
        
        super.processAuthenticationResponse(request, response, context);
    }

    private HashMap getUserAttributes(Map<String, String> map, String username, AuthenticationContext context) {
        HashMap claimsMap = new HashMap<String, String>();
        try {
            log.info("Attributes: " + map.size());
            for (Map.Entry entry : map.entrySet()) {
                String key = (String)entry.getKey();
                String keyDesc = (String)entry.getValue();
                String val = getClaimValueForUsername(username, (String)entry.getValue(), context);
                log.info(key + " = " + val);
                claimsMap.put(key, val);
            }

        } catch(Exception e) {
            log.info("ERROR " + e.getMessage());
        }

        return claimsMap;
    }

    private String getClaimValueForUsername(String username, String claim, AuthenticationContext context) throws Exception {
        UserRealm userRealm;
        String tenantAwareUsername;
        String value;
        try {
            String tenantDomain = MultitenantUtils.getTenantDomain(username);
            int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
            RealmService realmService = IdentityTenantUtil.getRealmService();
            userRealm = realmService.getTenantUserRealm(tenantId);
            tenantAwareUsername = MultitenantUtils.getTenantAwareUsername(username);
            if (userRealm != null) {
                value = userRealm.getUserStoreManager().getUserClaimValue(tenantAwareUsername, claim, null);
            } else {
                throw new Exception("Cannot find the user realm for the given tenant domain : " + tenantDomain);
            }
        } catch (UserStoreException e) {
            throw new Exception("Cannot find the required claim for username : " + username, e);
        }
        return value;
    }    
 
    private String getRedirectURL(String baseURI, String queryParams) {
        String url;
        if (StringUtils.isNotEmpty(queryParams)) {
            url = baseURI + "?" + queryParams + "&" + EmailOTPAuthenticatorConstants.AUTHENTICATORS + getName();
        } else {
            url = baseURI + "?" + EmailOTPAuthenticatorConstants.AUTHENTICATORS + getName();
        }

        return url;
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
    public boolean canHandle(HttpServletRequest request) {
        String attributesReturnConfirmed = request.getParameter(EmailOTPLoA3AuthenticatorConstants.ATTRIBUTESRETURN_CONFIRMED);
        if(StringUtils.isNotEmpty(attributesReturnConfirmed) && attributesReturnConfirmed.equals("true")) {
            return true;
        } else {
            return super.canHandle(request);
        }
    }

    @Override
    public String getName() {
        return EmailOTPLoA3AuthenticatorConstants.AUTHENTICATOR_NAME;
    }  
}