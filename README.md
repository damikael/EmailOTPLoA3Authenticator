# EmailOTPLoA3Authenticator
WSO2 Identity Server (IS) EmailOTP authenticator for SAML LoA3

EmailOTPLoA3 authenticator is an outbound local authenticator for wso2 providing two factor authentication by email for SAML requests with minimum requested **Level of Assurance** equals to 3. It extends the base authenticator **EmailOTPAuthenticator** (https://github.com/wso2-extensions/identity-outbound-auth-email-otp) and introduces the conditional logic to provide 2FA based on AuthnContextClassRef value specified within the SAML request. 


