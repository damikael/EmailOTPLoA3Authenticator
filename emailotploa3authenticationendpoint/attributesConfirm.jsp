<%--
  ~ Copyright (c) 2017, AgID - Agenzia per l'Italia Digitale - All Rights Reserved.
  ~ Developer: Michele D'Amico - Linfa Service
  ~
  ~ This file is licensed to you under the Apache License,
  ~ Version 2.0 (the "License"); you may not use this file except
  ~ in compliance with the License.
  ~ You may obtain a copy of the License at
  ~
  ~ http://www.apache.org/licenses/LICENSE-2.0
  ~
  ~ Unless required by applicable law or agreed to in writing,
  ~ software distributed under the License is distributed on an
  ~ "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
  ~ KIND, either express or implied.  See the License for the
  ~ specific language governing permissions and limitations
  ~ under the License.
  --%>

<%@ page session="true" %>
<%@ page import="java.util.Enumeration" %>
<%@ page import="javax.servlet.http.HttpSession" %>
<%@ page import="org.owasp.encoder.Encode" %>

    <html>
    <head>
        <meta charset="utf-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>WSO2 Identity Server</title>

        <link rel="icon" href="images/favicon.png" type="image/x-icon"/>
        <link href="libs/bootstrap_3.3.5/css/bootstrap.min.css" rel="stylesheet">
        <link href="css/Roboto.css" rel="stylesheet">
        <link href="css/custom-common.css" rel="stylesheet">
    </head>

    <body>

    <!-- header -->
    <header class="header header-default">
        <div class="container-fluid"><br></div>
        <div class="container-fluid">
            <div class="pull-left brand float-remove-xs text-center-xs">
                <a href="#">
                    <img src="images/logo-inverse.svg" alt="wso2" title="wso2" class="logo">

                    <h1><em>Identity Server</em></h1>
                </a>
            </div>
        </div>
    </header>

 <!-- page content -->
    <div class="container-fluid body-wrapper">

        <div class="row">
            <div class="col-md-12">

                <!-- content -->
                <div class="container col-xs-10 col-sm-6 col-md-6 col-lg-4 col-centered wr-content wr-login col-centered">
                    <div>
                        <h3 class="wr-title blue-bg padding-double white boarder-bottom-blue margin-none">
                            Conferma invio dati&nbsp;&nbsp;</h3>

                    </div>
                    <div class="boarder-all ">
                        <div class="clearfix"></div>
                        <div class="padding-double login-form">
                            <form id="confirm_form" name="confirm_form" action="/samlsso"  method="POST">
                                <input id="tocommonauth" name="tocommonauth" type="hidden" value="true">
                                <div id="loginTable1" class="identity-box">
                                    <div class="row">
                                        <div class="span6">
                                             <!-- Confirm data -->
                                             <div class="control-group">
                                                <p>Saranno inviati al servizio i seguenti dati:</p>
                                                <p>
                                                    <%
                                                        String[] claims = request.getParameter("REQUESTED_CLAIMS").split(",");
                                                        for(int i=0; i<claims.length; i++) {     
                                                        String attrib = (String) claims[i];
                                                        String attribName = attrib.split("=")[0];
                                                        String attribValue = attrib.split("=")[1];
                                                    %>
                                                    <br/><%= attribName %> : <b><%= attribValue %></b>
                                                    
                                                    <%
                                                    }
                                                    %>

                                                </p>
                                             </div>
                                             <input type="hidden" name="EmailOTPLoA3_ARCONFIRMED" value="true" />
                                             <input type="hidden" name="sessionDataKey"
                                                value='<%=Encode.forHtmlAttribute(request.getParameter("sessionDataKey"))%>'/>
                                             <br><div>
                                                  <input type="submit" name="confirm" id="confirm" value="Conferma" class="btn btn-primary">
                                                  <input type="submit" name="cancel" id="cancel" value="Annulla" class="btn btn-primary">
                                             </div>
                                        </div>
                                    </div>
                                </div>
                            </form>

                           <div class="clearfix"></div>
                        </div>
                    </div>
                    <!-- /content -->
                </div>
            </div>
            <!-- /content/body -->
        </div>
    </div>


    <script src="libs/jquery_1.11.3/jquery-1.11.3.js"></script>
    <script src="libs/bootstrap_3.3.5/js/bootstrap.min.js"></script>

    </body>
    </html>
</fmt:bundle>
