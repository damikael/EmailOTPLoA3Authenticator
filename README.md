# EmailOTPLoA3Authenticator
WSO2 Identity Server (IS) EmailOTP authenticator for SAML LoA3

EmailOTPLoA3 authenticator is an outbound local authenticator for wso2 providing two factor authentication by email for SAML requests with minimum requested **Level of Assurance** equals to 3. It extends the base authenticator **EmailOTPAuthenticator** (https://github.com/wso2-extensions/identity-outbound-auth-email-otp) and introduces the conditional logic to provide 2FA based on AuthnContextClassRef value specified within the SAML request. 


## Build
- mvn clean install

## Setup
- Configure EmailOTP Authenticator and EmailOTP Provider as explained in https://docs.wso2.com/display/ISCONNECTORS/Configuring+EmailOTP+Authenticator
- Place the file target/it.linfaservice.wso2.authenticator.emailotploa3-1.0.0.jar into the <IS_HOME>/repository/components/dropins directory
- Add the following configuration in the &lt;IS_HOME&gt;/repository/conf/identity/application-authentication.xml file under the &lt;AuthenticatorConfigs&gt; section (Customize values for parameters AuthnContextClassRef *LoA2*, *LoA3*, *LoA4*)
 ```
		<AuthenticatorConfig name="EmailOTPLoA3" enabled="true">
			<Parameter name="EMAILOTPAuthenticationEndpointURL">https://spidtest.linfabox.it:9443/emailotpauthenticationendpoint/emailotp.jsp</Parameter>
			<Parameter name="EmailOTPAuthenticationEndpointErrorPage">https://spidtest.linfabox.it:9443/emailotpauthenticationendpoint/emailotpError.jsp</Parameter>
			<Parameter name="EmailAddressRequestPage">https://spidtest.linfabox.it:9443/emailotpauthenticationendpoint/emailAddress.jsp</Parameter>
			<Parameter name="usecase">local</Parameter>
			<Parameter name="secondaryUserstore">primary</Parameter>
			<Parameter name="EMAILOTPMandatory">false</Parameter>
			<Parameter name="sendOTPToFederatedEmailAttribute">true</Parameter>
			<Parameter name="federatedEmailAttributeKey">email</Parameter>
			<Parameter name="EmailOTPEnableByUserClaim">false</Parameter>
			<Parameter name="CaptureAndUpdateEmailAddress">false</Parameter>
			<Parameter name="showEmailAddressInUI">true</Parameter>
			<Parameter name="AuthnContextClassRefLoA2">LoA2</Parameter>
			<Parameter name="AuthnContextClassRefLoA3">LoA3</Parameter>
			<Parameter name="AuthnContextClassRefLoA4">LoA4</Parameter>
		</AuthenticatorConfig>
  ```
  - Configure Identity Provider and Service Provider for EmailOTPLoA3 as explained for EmailOTP in https://docs.wso2.com/display/ISCONNECTORS/Configuring+EmailOTP+Authenticator
  - Restart WSO2 IS
