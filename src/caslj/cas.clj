(ns caslj.cas
  "fns related to the CAS protocol defined at http://www.jasig.org/cas/protocol/.
The fns are defined in document order and are metadata-annotated with related section(s)."

  (:use compojure.core)
  (:require [compojure.route :as route]))

;; CAS Protocol
;;
;;   Original Text: http://www.jasig.org/cas/protocol/
;;   Version: 1.0
;;
;; 1. Introduction
;;
;;   This is the official specification of the CAS 1.0 and 2.0 protocols. It is subject to change.
;;
;; 1.1. Conventions & Definitions
;;
;;   The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
;;   "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this
;;   document are to be interpreted as described in RFC 2119.
;;
;;   * "Client" refers to the end user and/or the web browser.
;;   * "Server" refers to the Central Authentication Service server.
;;   * "Service" refers to the application the client is trying to access.
;;   * "Back-end service" refers to the application a service is trying to
;;   access on behalf of a client. This can also be referred to as the "target
;;   service."
;;   * <LF> is a bare line feed (ASCII value 0x0a).
;;
;; 2. CAS URIs
;;
;; CAS is an HTTP-based protocol that requires each of its components to be
;; accessible through specific URIs. This section will discuss each of the
;; URIs.
;;
(defroutes cas-server

           ;; 2.1. /login as credential requester
           ;;
           ;; The /login URI operates with two behaviors: as a credential
           ;; requestor, and as a credential acceptor. It responds to
           ;; credentials by acting as a credential acceptor and otherwise acts
           ;; as a credential requestor.
           ;;
           ;; If the client has already established a single sign-on session
           ;; with CAS, the web browser presents to CAS a secure cookie
           ;; containing a string identifying a ticket-granting ticket. This
           ;; cookie is called the ticket-granting cookie. If the
           ;; ticket-granting cookie keys to a valid ticket-granting ticket,
           ;; CAS may issue a service ticket provided all the other conditions
           ;; in this specification are met. See Section 3.6 for more
           ;; information on ticket-granting cookies.
           ;;
           (GET "/login"

                ;; 2.1.1. parameters
                ;;
                ;;   The following HTTP request parameters may be passed to
                ;;   /login while it is acting as a credential requestor. They
                ;;   are all case-sensitive, and they all MUST be handled by
                ;;   /login.
                ;;
                [

                 ;;  * service [OPTIONAL] - the identifier of the application
                 ;;  the client is trying to access. In almost all cases, this
                 ;;  will be the URL of the application. Note that as an HTTP
                 ;;  request parameter, this URL value MUST be URL-encoded as
                 ;;  described in Section 2.2 of RFC 1738[4]. If a service is
                 ;;  not specified and a single sign-on session does not yet
                 ;;  exist, CAS SHOULD request credentials from the user to
                 ;;  initiate a single sign-on session. If a service is not
                 ;;  specified and a single sign-on session already exists, CAS
                 ;;  SHOULD display a message notifying the client that it is
                 ;;  already logged in.
                 ;;
                 service

                 ;;  * renew [OPTIONAL] - if this parameter is set, single
                 ;;  sign-on will be bypassed. In this case, CAS will require
                 ;;  the client to present credentials regardless of the
                 ;;  existence of a single sign-on session with CAS. This
                 ;;  parameter is not compatible with the "gateway" parameter.
                 ;;  Services redirecting to the /login URI and login form
                 ;;  views posting to the /login URI SHOULD NOT set both the
                 ;;  "renew" and "gateway" request parameters. Behavior is
                 ;;  undefined if both are set. It is RECOMMENDED that CAS
                 ;;  implementations ignore the "gateway" parameter if "renew"
                 ;;  is set. It is RECOMMENDED that when the renew parameter is
                 ;;  set its value be "true".
                 ;;
                 renew

                 ;;  * gateway [OPTIONAL] - if this parameter is set, CAS will
                 ;;  not ask the client for credentials. If the client has a
                 ;;  pre-existing single sign-on session with CAS, or if a
                 ;;  single sign-on session can be established through
                 ;;  non-interactive means (i.e. trust authentication), CAS MAY
                 ;;  redirect the client to the URL specified by the "service"
                 ;;  parameter, appending a valid service ticket. (CAS also MAY
                 ;;  interpose an advisory page informing the client that a CAS
                 ;;  authentication has taken place.) If the client does not
                 ;;  have a single sign-on session with CAS, and a
                 ;;  non-interactive authentication cannot be established, CAS
                 ;;  MUST redirect the client to the URL specified by the
                 ;;  "service" parameter with no "ticket" parameter appended to
                 ;;  the URL. If the "service" parameter is not specified and
                 ;;  "gateway" is set, the behavior of CAS is undefined. It is
                 ;;  RECOMMENDED that in this case, CAS request credentials as
                 ;;  if neither parameter was specified. This parameter is not
                 ;;  compatible with the "renew" parameter. Behavior is
                 ;;  undefined if both are set. It is RECOMMENDED that when the
                 ;;  gateway parameter is set its value be "true".
                 gateway]

                ;; 2.1.2. URL examples of /login
                ;;   Simple login example:
                ;;
                ;;     https://server/cas/login?service=http%3A%2F%2Fwww.service.com
                ;;
                ;;   Don't prompt for username/password:
                ;;
                ;;     https://server/cas/login?service=http%3A%2F%2Fwww.service.com&gateway=true
                ;;
                ;;   Always prompt for username/password:
                ;;
                ;;     https://server/cas/login?service=http%3A%2F%2Fwww.service.com&renew=true
                ;;
                ;; 2.1.3. response for username/password authentication
                ;;
                ;;   When /login behaves as a credential requestor, the
                ;;   response will vary depending on the type of credentials it
                ;;   is requesting. In most cases, CAS will respond by
                ;;   displaying a login screen requesting a username and
                ;;   password. This page MUST include a form with the
                ;;   parameters, "username", "password", and "lt". The form MAY
                ;;   also include the parameter, "warn". If "service" was
                ;;   specified to /login, "service" MUST also be a parameter of
                ;;   the form, containing the value originally passed to
                ;;   /login. These parameters are discussed in detail in
                ;;   Section 2.2.1. The form MUST be submitted through the HTTP
                ;;   POST method to /login which will then act as a credential
                ;;   acceptor, discussed in Section 2.2.
                ;;
                ;; 2.1.4. response for trust authentication
                ;;
                ;;   Trust authentication accommodates consideration of
                ;;   arbitrary aspects of the request as a basis for
                ;;   authentication. The appropriate user experience for trust
                ;;   authentication will be highly deployer-specific in
                ;;   consideration of local policy and of the logistics of the
                ;;   particular authentication mechanism implemented.
                ;;
                ;;   When /login behaves as a credential requestor for trust
                ;;   authentication, its behavior will be determined by the
                ;;   type of credentials it will be receiving. If the
                ;;   credentials are valid, CAS MAY transparently redirect the
                ;;   user to the service. Alternately, CAS MAY display a
                ;;   warning that credentials were presented and allow the
                ;;   client to confirm that it wants to use those credentials.
                ;;   It is RECOMMENDED that CAS implementations allow the
                ;;   deployer to choose the preferred behavior. If the
                ;;   credentials are invalid or non-existent, it is RECOMMENDED
                ;;   that CAS display to the client the reason authentication
                ;;   failed, and possibly present the user with alternate means
                ;;   of authentication (e.g. username/password authentication).
                ;;
                ;; 2.1.5. response for single sign-on authentication
                ;;
                ;;   If the client has already established a single sign-on
                ;;   session with CAS, the client will have presented its HTTP
                ;;   session cookie to /login and behavior will be handled as
                ;;   in Section 2.2.4. However, if the "renew" parameter is
                ;;   set, the behavior will be handled as in Section 2.1.3 or
                ;;   2.1.4.
                ;;
                "not implemented")

           ;; 2.2. /login as credential acceptor
           ;;
           ;;   When a set of accepted credentials are passed to /login, /login
           ;;   acts as a credential acceptor and its behavior is defined in
           ;;   this section.
           ;;
           (POST "/login"

                 [
                  ;; 2.2.1. parameters common to all types of authentication
                  ;;
                  ;;   The following HTTP request parameters MAY be passed to
                  ;;   /login while it is acting as a credential acceptor. They
                  ;;   are all case-sensitive and they all MUST be handled by
                  ;;   /login.
                  ;;
                  ;;   * service [OPTIONAL] - the URL of the application the
                  ;;   client is trying to access. CAS MUST redirect the client
                  ;;   to this URL upon successful authentication. This is
                  ;;   discussed in detail in Section 2.2.4.
                  ;;
                  service

                  ;;   * warn [OPTIONAL] - if this parameter is set, single
                  ;;   sign-on MUST NOT be transparent. The client MUST be
                  ;;   prompted before being authenticated to another service.
                  ;;
                  warn

                  ;; 2.2.2. parameters for username/password authentication
                  ;;
                  ;;   In addition to the OPTIONAL parameters specified in
                  ;;   Section 2.2.1, the following HTTP request parameters
                  ;;   MUST be passed to /login while it is acting as a
                  ;;   credential acceptor for username/password
                  ;;   authentication. They are all case-sensitive.
                  ;;
                  ;;   * username [REQUIRED] - the username of the client that
                  ;;   is trying to log in
                  ;;
                  username

                  ;;   * password [REQUIRED] - the password of the client that
                  ;;   is trying to log in
                  ;;
                  password

                  ;;   * lt [REQUIRED] - a login ticket. This is provided as
                  ;;   part of the login form discussed in Section 2.1.3. The
                  ;;   login ticket itself is discussed in Section 3.5.
                  ;;
                  lt

                  ;; 2.2.3. parameters for trust authentication
                  ;;
                  ;;   There are no REQUIRED HTTP request parameters for trust
                  ;;   authentication. Trust authentication may be based on any
                  ;;   aspect of the HTTP request.
                  ;;
                  ]

                 ;; 2.2.4. response
                 ;;
                 ;;   One of the following responses MUST be provided by /login
                 ;;   when it is operating as a credential acceptor.
                 ;;
                 ;;   * successful login: redirect the client to the URL
                 ;;   specified by the "service" parameter in a manner that
                 ;;   will not cause the client's credentials to be forwarded
                 ;;   to the service. This redirection MUST result in the
                 ;;   client issuing a GET request to the service. The request
                 ;;   MUST include a valid service ticket, passed as the HTTP
                 ;;   request parameter, "ticket". See Appendix B for more
                 ;;   information. If "service" was not specified, CAS MUST
                 ;;   display a message notifying the client that it has
                 ;;   successfully initiated a single sign-on session.
                 ;;   * failed login: return to /login as a credential
                 ;;   requestor. It is RECOMMENDED in this case that the CAS
                 ;;   server display an error message be displayed to the user
                 ;;   describing why login failed (e.g. bad password, locked
                 ;;   account, etc.), and if appropriate, provide an
                 ;;   opportunity for the user to attempt to login again.
                 ;;
                 "not implemented")

           ;; 2.3. /logout
           ;;
           ;;   /logout destroys a client's single sign-on CAS session. The
           ;;   ticket-granting cookie (Section 3.6) is destroyed, and subsequent
           ;;   requests to /login will not obtain service tickets until the user
           ;;   again presents primary credentials (and thereby establishes a new
           ;;   single sign-on session).
           ;;
           (ANY "/logout"

                ;; 2.3.1. parameters
                ;;
                ;;   The following HTTP request parameter MAY be specified to
                ;;   /logout. It is case sensitive and SHOULD be handled by
                ;;   /logout.
                ;;
                ;;   * url [OPTIONAL] - if "url" is specified, the URL
                ;;   specified by "url" SHOULD be on the logout page with
                ;;   descriptive text. For example, "The application you just
                ;;   logged out of has provided a link it would like you to
                ;;   follow. Please click here to access
                ;;   http://www.go-back.edu."
                ;;
                [url]

                ;; 2.3.2. response
                ;;
                ;;   /logout MUST display a page stating that the user has been
                ;;   logged out. If the "url" request parameter is implemented,
                ;;   /logout SHOULD also provide a link to the provided URL as
                ;;   described in Section 2.3.1.
                ;;
                (str "You have been logged out. "
                     (when url
                       (str "The application you just logged out of has "
                            "provided a link it would like you to follow.
                            Please <a href=\"" url "\">click here to access "
                            url "</a>."))))

           ;; 2.4. /validate [CAS 1.0]
           ;;
           ;;   /validate checks the validity of a service ticket./validate is
           ;;   part of the CAS 1.0 protocol and thus does not handle
           ;;   proxy authentication. CAS MUST respond with a ticket
           ;;   validation failure response when a proxy ticket is passed
           ;;   to /validate.
           ;;
           (ANY "/validate"

                ;; 2.4.1. parameters
                ;;
                ;;   The following HTTP request parameters MAY be specified to
                ;;   /validate. They are case sensitive and MUST all be handled
                ;;   by /validate.
                ;;
                [
                 ;;  * service [REQUIRED] - the identifier of the service for
                 ;;  which the ticket was issued, as discussed in Section
                 ;;  2.2.1.
                 ;;
                 service

                 ;;  * ticket [REQUIRED] - the service ticket issued by /login.
                 ;;  Service tickets are described in Section 3.1.
                 ;;
                 ticket

                 ;;  * renew [OPTIONAL] - if this parameter is set, ticket
                 ;;  validation will only succeed if the service ticket was
                 ;;  issued from the presentation of the user's primary
                 ;;  credentials. It will fail if the ticket was issued from a
                 ;;  single sign-on session.
                 ;;
                 renew]

                ;; 2.4.2. response
                ;;
                ;;   /validate will return one of the following two responses:
                ;;
                (if (valid-ticket? ticket) ; FIXME: pseudo-code

                    ;;   On ticket validation success:
                    ;;
                    ;;     yes<LF>
                    ;;     username<LF>
                    ;;
                    (str "yes" \newline "username") ; TODO: replace with actual username

                    ;;   On ticket validation failure:
                    ;;
                    ;;     no<LF>
                    ;;     <LF>
                    ;;
                    (str "no" \newline \newline))

                ;; 2.4.3. URL examples of /validate
                ;;
                ;;   Simple validation attempt:
                ;;
                ;;     https://server/cas/validate?service=http%3A%2F%2Fwww.service.com&ticket=ST-1856339-aA5Yuvrxzpv8Tau1cYQ7
                ;;
                ;;   Ensure service ticket was issued by presentation of
                ;;   primary credentials:
                ;;
                ;;     https://server/cas/validate?service=http%3A%2F%2Fwww.service.com&ticket=ST-1856339-aA5Yuvrxzpv8Tau1cYQ7&renew=true
                )

           ;; 2.5. /serviceValidate [CAS 2.0]
           ;;
           ;;   /serviceValidate checks the validity of a service ticket and
           ;;   returns an XML-fragment response. /serviceValidate MUST also
           ;;   generate and issue proxy-granting tickets when requested.
           ;;   /serviceValidate MUST NOT return a successful authentication if
           ;;   it receives a proxy ticket. It is RECOMMENDED that if
           ;;   /serviceValidate receives a proxy ticket, the error message in
           ;;   the XML response SHOULD explain that validation failed because
           ;;   a proxy ticket was passed to /serviceValidate.
           ;;
           (ANY "/serviceValidate"

                ;; 2.5.1. parameters
                ;;
                ;;   The following HTTP request parameters MAY be specified to
                ;;   /serviceValidate. They are case sensitive and MUST all be
                ;;   handled by /serviceValidate.
                ;;
                [
                 ;;  * service [REQUIRED] - the identifier of the service for
                 ;;  which the ticket was issued, as discussed in Section
                 ;;  2.2.1.
                 ;;
                 service

                 ;;  * ticket [REQUIRED] - the service ticket issued by /login.
                 ;;  Service tickets are described in Section 3.1.
                 ;;
                 ticket

                 ;;  * pgtUrl [OPTIONAL] - the URL of the proxy callback.
                 ;;  Discussed in Section 2.5.4.
                 ;;
                 pgtUrl

                 ;;  * renew [OPTIONAL] - if this parameter is set, ticket
                 ;;  validation will only succeed if the service ticket was
                 ;;  issued from the presentation of the user's primary
                 ;;  credentials. It will fail if the ticket was issued from a
                 ;;  single sign-on session.
                 ;;
                 renew]

                ;; 2.5.2. response
                ;;   /serviceValidate will return an XML-formatted CAS
                ;;   serviceResponse as described in the XML schema in Appendix
                ;;   A. Below are example responses:
                ;;
                ;;   On ticket validation success:
                ;;
                ;;     <cas:serviceResponse xmlns:cas='http://www.yale.edu/tp/cas'>
                ;;         <cas:authenticationSuccess>
                ;;             <cas:user>username</cas:user>
                ;;                 <cas:proxyGrantingTicket>PGTIOU-84678-8a9d...
                ;;             </cas:proxyGrantingTicket>
                ;;         </cas:authenticationSuccess>
                ;;     </cas:serviceResponse>
                ;;
                ;;   On ticket validation failure:
                ;;
                ;;     <cas:serviceResponse xmlns:cas='http://www.yale.edu/tp/cas'>
                ;;         <cas:authenticationFailure code="INVALID_TICKET">
                ;;             Ticket ST-1856339-aA5Yuvrxzpv8Tau1cYQ7 not recognized
                ;;         </cas:authenticationFailure>
                ;;     </cas:serviceResponse>
                ;;
                "not implemented"

                ;; 2.5.3. error codes
                ;;
                ;;   The following values MAY be used as the "code" attribute
                ;;   of authentication failure responses. The following is the
                ;;   minimum set of error codes that all CAS servers MUST
                ;;   implement. Implementations MAY include others.
                ;;
                ;;   * INVALID_REQUEST - not all of the required request
                ;;   parameters were present
                ;;   * INVALID_TICKET - the ticket provided was not valid, or
                ;;   the ticket did not come from an initial login and "renew"
                ;;   was set on validation. The body of the
                ;;   <cas:authenticationFailure> block of the XML response
                ;;   SHOULD describe the exact details.
                ;;   * INVALID_SERVICE - the ticket provided was valid, but the
                ;;   service specified did not match the service associated
                ;;   with the ticket. CAS MUST invalidate the ticket and
                ;;   disallow future validation of that same ticket.
                ;;   * INTERNAL_ERROR - an internal error occurred during
                ;;   ticket validation
                ;;
                ;;   For all error codes, it is RECOMMENDED that CAS provide a
                ;;   more detailed message as the body of the
                ;;   <cas:authenticationFailure> block of the XML response.
                ;;
                ;; 2.5.4. proxy callback
                ;;
                ;;   If a service wishes to proxy a client's authentication to
                ;;   a back-end service, it must acquire a proxy-granting
                ;;   ticket. Acquisition of this ticket is handled through a
                ;;   proxy callback URL. This URL will uniquely and securely
                ;;   identify the back-end service that is proxying the
                ;;   client's authentication. The back-end service can then
                ;;   decide whether or not to accept the credentials based on
                ;;   the back-end service's identifying callback URL.
                ;;
                ;;   The proxy callback mechanism works as follows:
                ;;
                ;;   1. The service that is requesting a proxy-granting ticket
                ;;   specifies upon initial service ticket or proxy ticket
                ;;   validation the HTTP request parameter "pgtUrl" to
                ;;   /serviceValidate (or /proxyValidate). This is a callback
                ;;   URL of the service to which CAS will connect to verify the
                ;;   service's identity. This URL MUST be HTTPS, and CAS MUST
                ;;   verify both that the SSL certificate is valid and that its
                ;;   name matches that of the service. If the certificate fails
                ;;   validation, no proxy-granting ticket will be issued, and
                ;;   the CAS service response as described in Section 2.5.2
                ;;   MUST NOT contain a <proxyGrantingTicket> block. At this
                ;;   point, the issuance of a proxy-granting ticket is halted,
                ;;   but service ticket validation will continue, returning
                ;;   success or failure as appropriate. If certificate
                ;;   validation is successful, issuance of a proxy-granting
                ;;   ticket proceeds as in step 2.
                ;;
                ;;   2. CAS uses an HTTP GET request to pass the HTTP request
                ;;   parameters "pgtId" and "pgtIou" to the pgtUrl. These
                ;;   entities are discussed in Sections 3.3 and 3.4,
                ;;   respectively.
                ;;
                ;;   3. If the HTTP GET returns an HTTP status code of 200
                ;;   (OK), CAS MUST respond to the /serviceValidate (or
                ;;   /proxyValidate) request with a service response (Section
                ;;   2.5.2) containing the proxy-granting ticket IOU (Section
                ;;   3.4) within the <cas:proxyGrantingTicket> block. If the
                ;;   HTTP GET returns any other status code, excepting HTTP 3xx
                ;;   redirects, CAS MUST respond to the /serviceValidate (or
                ;;   /proxyValidate) request with a service response that MUST
                ;;   NOT contain a <cas:proxyGrantingTicket> block. CAS MAY
                ;;   follow any HTTP redirects issued by the pgtUrl. However,
                ;;   the identifying callback URL provided upon validation in
                ;;   the <proxy> block MUST be the same URL that was initially
                ;;   passed to /serviceValidate (or /proxyValidate) as the
                ;;   "pgtUrl" parameter.
                ;;
                ;;   4. The service, having received a proxy-granting ticket
                ;;   IOU in the CAS response, and both a proxy-granting ticket
                ;;   and a proxy-granting ticket IOU from the proxy callback,
                ;;   will use the proxy-granting ticket IOU to correlate the
                ;;   proxy-granting ticket with the validation response. The
                ;;   service will then use the proxy-granting ticket for the
                ;;   acquisition of proxy tickets as described in Section 2.7.
                ;;
                ;; 2.5.5. URL examples of /serviceValidate
                ;;
                ;;   Simple validation attempt:
                ;;
                ;;   https://server/cas/serviceValidate?service=http%3A%2F%2Fwww.service.com&ticket=ST-1856339-aA5Yuvrxzpv8Tau1cYQ7
                ;;
                ;;   Ensure service ticket was issued by presentation of
                ;;   primary credentials:
                ;;
                ;;   https://server/cas/serviceValidate?service=http%3A%2F%2Fwww.service.com&ticket=ST-1856339-aA5Yuvrxzpv8Tau1cYQ7&renew=true
                ;;
                ;;   Pass in a callback URL for proxying:
                ;;
                ;;   https://server/cas/serviceValidate?service=http%3A%2F%2Fwww.service.com&ticket=ST-1856339-aA5Yuvrxzpv8Tau1cYQ7&pgtUrl=https://my-server/myProxyCallback
                )

           ;; 2.6. /proxyValidate [CAS 2.0]
           ;;
           ;;   /proxyValidate MUST perform the same validation tasks as
           ;;   /serviceValidate and additionally validate proxy tickets.
           ;;   /proxyValidate MUST be capable of validating both service
           ;;   tickets and proxy tickets.
           ;;
           (ANY "/proxyValidate"

                ;; 2.6.1. parameters
                ;;
                ;;  /proxyValidate has the same parameter requirements as
                ;;  /serviceValidate. See Section 2.5.1.
                ;;
                [service ticket pgtUrl renew]

                ;; 2.6.2. response
                ;;
                ;;   /proxyValidate will return an XML-formatted CAS
                ;;   serviceResponse as described in the XML schema in Appendix
                ;;   A. Below are example responses:
                ;;
                ;;   On ticket validation success:
                ;;
                ;;     <cas:serviceResponse xmlns:cas='http://www.yale.edu/tp/cas'>
                ;;         <cas:authenticationSuccess>
                ;;             <cas:user>username</cas:user>
                ;;             <cas:proxyGrantingTicket>PGTIOU-84678-8a9d...</cas:proxyGrantingTicket>
                ;;             <cas:proxies>
                ;;                 <cas:proxy>https://proxy2/pgtUrl</cas:proxy>
                ;;                 <cas:proxy>https://proxy1/pgtUrl</cas:proxy>
                ;;             </cas:proxies>
                ;;         </cas:authenticationSuccess>
                ;;     </cas:serviceResponse>
                ;;
                ;;   Note that when authentication has proceeded through
                ;;   multiple proxies, the order in which the proxies were
                ;;   traversed MUST be reflected in the <cas:proxies> block.
                ;;   The most recently-visited proxy MUST be the first proxy
                ;;   listed, and all the other proxies MUST be shifted down as
                ;;   new proxies are added. In the above example, the service
                ;;   identified by https://proxy1/pgtUrl was visited first, and
                ;;   that service proxied authentication to the service
                ;;   identified by https://proxy2/pgtUrl.
                ;;
                ;;   On ticket validation failure:
                ;;
                ;;     <cas:serviceResponse xmlns:cas='http://www.yale.edu/tp/cas'>
                ;;         <cas:authenticationFailure code="INVALID_TICKET">
                ;;             ticket PT-1856376-1HMgO86Z2ZKeByc5XdYD not recognized
                ;;         </cas:authenticationFailure>
                ;;     </cas:serviceResponse>
                ;;
                "not implemented"

                ;; 2.6.3 URL examples of /proxyValidate
                ;;
                ;;  /proxyValidate accepts the same parameters as
                ;;  /serviceValidate. See Section 2.5.5 for use examples,
                ;;  substituting "proxyValidate" for "serviceValidate".
                ;;
                )

           ;; 2.7. /proxy [CAS 2.0]
           ;;
           ;;   /proxy provides proxy tickets to services that have acquired
           ;;   proxy-granting tickets and will be proxying authentication to
           ;;   back-end services.
           ;;
           (ANY "/proxy"

                ;; 2.7.1. parameters
                ;;
                ;;   The following HTTP request parameters MUST be specified to
                ;;   /proxy. They are both case-sensitive.
                ;;
                [
                 ;;  * pgt [REQUIRED] - the proxy-granting ticket acquired by
                 ;;  the service during service ticket or proxy ticket
                 ;;  validation
                 ;;
                 pgt

                 ;;  * targetService [REQUIRED] - the service identifier of the
                 ;;  back-end service. Note that not all back-end services are
                 ;;  web services so this service identifier will not always be
                 ;;  a URL. However, the service identifier specified here MUST
                 ;;  match the "service" parameter specified to /proxyValidate
                 ;;  upon validation of the proxy ticket.
                 ;;
                 targetService]

                ;; 2.7.2. response
                ;;
                ;;   /proxy will return an XML-formatted CAS serviceResponse as
                ;;   described in the XML schema in Appendix A. Below are
                ;;   example responses:
                ;;
                ;;   On request success:
                ;;
                ;;     <cas:serviceResponse xmlns:cas='http://www.yale.edu/tp/cas'>
                ;;         <cas:proxySuccess>
                ;;             <cas:proxyTicket>PT-1856392-b98xZrQN4p90ASrw96c8</cas:proxyTicket>
                ;;         </cas:proxySuccess>
                ;;     </cas:serviceResponse>
                ;;
                ;;   On request failure:
                ;;
                ;;     <cas:serviceResponse xmlns:cas='http://www.yale.edu/tp/cas'>
                ;;         <cas:proxyFailure code="INVALID_REQUEST">
                ;;             'pgt' and 'targetService' parameters are both required
                ;;         </cas:proxyFailure>
                ;;     </cas:serviceResponse>
                ;;
                "not implemented"

                ;; 2.7.3. error codes
                ;;
                ;;   The following values MAY be used as the "code" attribute
                ;;   of authentication failure responses. The following is the
                ;;   minimum set of error codes that all CAS servers MUST
                ;;   implement. Implementations MAY include others.
                ;;
                ;;   * INVALID_REQUEST - not all of the required request
                ;;   parameters were present
                ;;   * BAD_PGT - the pgt provided was invalid
                ;;   * INTERNAL_ERROR - an internal error occurred during
                ;;   ticket validation
                ;;
                ;;   For all error codes, it is RECOMMENDED that CAS provide a
                ;;   more detailed message as the body of the
                ;;   <cas:authenticationFailure> block of the XML response.
                ;;
                ;; 2.7.4. URL example of /proxy
                ;;
                ;;   Simple proxy request:
                ;;
                ;;     https://server/cas/proxy?targetService=http%3A%2F%2Fwww.service.com&pgt=PGT-490649-W81Y9Sa2vTM7hda7xNTkezTbVge4CUsybAr
                ;;
                )

;; 3. CAS Entities
;;
(defn- gen-uuid [] (str (java.util.UUID/randomUUID)))
(defn- gen-ticket [prefix] (str prefix (gen-uuid)))

; FIXME: implement me
(defn valid-token? [& args] true)

;; 3.1. service ticket
;;
;;   A service ticket is an opaque string that is used by the client as a
;;   credential to obtain access to a service. The service ticket is obtained
;;   from CAS upon a client's presentation of credentials and a service
;;   identifier to /login as described in Section 2.2.
;;
;; 3.1.1. service ticket properties
;;
;;   * Service tickets are only valid for the service identifier that was
;;   specified to /login when they were generated. The service identifier
;;   SHOULD NOT be part of the service ticket.
;;   * Service tickets MUST only be valid for one ticket validation attempt.
;;   Whether or not validation was successful, CAS MUST then invalidate the
;;   ticket, causing all future validation attempts of that same ticket to
;;   fail.
;;   * CAS SHOULD expire unvalidated service tickets in a reasonable period of
;;   time after they are issued. If a service presents for validation an
;;   expired service ticket, CAS MUST respond with a validation failure
;;   response. It is RECOMMENDED that the validation response include a
;;   descriptive message explaining why validation failed. It is RECOMMENDED
;;   that the duration a service ticket is valid before it expires be no longer
;;   than five minutes. Local security and CAS usage considerations MAY
;;   determine the optimal lifespan of unvalidated service tickets.
;;   * Service tickets MUST contain adequate secure random data so that a
;;   ticket is not guessable.
;;   * Service tickets MUST begin with the characters, "ST-".
;;   * Services MUST be able to accept service tickets of up to 32 characters
;;   in length. It is RECOMMENDED that services support service tickets of up
;;   to 256 characters in length.
;;
(defn gen-service-ticket [] (gen-ticket "ST-"))

;; 3.2. proxy ticket
;;
;;   A proxy ticket is an opaque string that a service uses as a credential to
;;   obtain access to a back-end service on behalf of a client. Proxy tickets
;;   are obtained from CAS upon a service's presentation of a valid
;;   proxy-granting ticket (Section 3.3), and a service identifier for the
;;   back-end service to which it is connecting.
;;
;; 3.2.1. proxy ticket properties
;;
;;   * Proxy tickets are only valid for the service identifier specified to
;;   /proxy when they were generated. The service identifier SHOULD NOT be part
;;   of the proxy ticket.
;;   * Proxy tickets MUST only be valid for one ticket validation attempt.
;;   Whether or not validation was successful, CAS MUST then invalidate the
;;   ticket, causing all future validation attempts of that same ticket to
;;   fail.
;;   * CAS SHOULD expire unvalidated proxy tickets in a reasonable period of
;;   time after they are issued. If a service presents for validation an
;;   expired proxy ticket, CAS MUST respond with a validation failure response.
;;   It is RECOMMENDED that the validation response include a descriptive
;;   message explaining why validation failed. It is RECOMMENDED that the
;;   duration a proxy ticket is valid before it expires be no longer than five
;;   minutes. Local security and CAS usage considerations MAY determine the
;;   * Proxy tickets MUST contain adequate secure random data so that a ticket
;;   is not guessable.
;;   * Proxy tickets SHOULD begin with the characters, "PT-". Proxy tickets
;;   MUST begin with either the characters, "ST-" or "PT-".
;;   * Back-end services MUST be able to accept proxy tickets of up to 32
;;   characters in length. It is RECOMMENDED that back-end services support
;;   proxy tickets of up to 256 characters in length.
;;
(defn gen-proxy-ticket [] (gen-ticket "PT-"))

;; 3.3. proxy-granting ticket
;;
;;   A proxy-granting ticket is an opaque string that is used by a service to
;;   obtain proxy tickets for obtaining access to a back-end service on behalf
;;   of a client. Proxy-granting tickets are obtained from CAS upon validation
;;   of a service ticket or a proxy ticket. Proxy-granting ticket issuance is
;;   described fully in Section 2.5.4.
;;
;; 3.3.1. proxy-granting ticket properties
;;
;;   * Proxy-granting tickets MAY be used by services to obtain multiple proxy
;;   tickets. Proxy-granting tickets are not one-time-use tickets.
;;   * Proxy-granting tickets MUST expire when the client whose authentication
;;   is being proxied logs out of CAS.
;;   * Proxy-granting tickets MUST contain adequate secure random data so that
;;   a ticket is not guessable in a reasonable period of time through
;;   brute-force attacks.
;;   * Proxy-granting tickets SHOULD begin with the characters, "PGT-".
;;   * Services MUST be able to handle proxy-granting tickets of up to 64
;;   characters in length. It is RECOMMENDED that services support
;;   proxy-granting tickets of up to 256 characters in length.
;;
(defn gen-proxy-granting-ticket [] (gen-ticket "PGT-"))

;; 3.4. proxy-granting ticket IOU
;;
;;   A proxy-granting ticket IOU is an opaque string that is placed in the
;;   response provided by /serviceValidate and /proxyValidate used to correlate
;;   a service ticket or proxy ticket validation with a particular
;;   proxy-granting ticket. See Section 2.5.4 for a full description of this
;;   process.
;;
;; 3.4.1. proxy-granting ticket IOU properties
;;
;;   * Proxy-granting ticket IOUs SHOULD NOT contain any reference to their
;;   associated proxy-granting tickets. Given a particular PGTIOU, it MUST NOT
;;   be possible to derive its corresponding PGT through algorithmic methods in
;;   a reasonable period of time.
;;   * Proxy-granting ticket IOUs MUST contain adequate secure random data so
;;   that a ticket is not guessable in a reasonable period of time through
;;   brute-force attacks.
;;   * Proxy-granting ticket IOUs SHOULD begin with the characters, "PGTIOU-".
;;   * Services MUST be able to handle PGTIOUs of up to 64 characters in
;;   length. It is RECOMMENDED that services support PGTIOUs of up to 256
;;   characters in length.
;;
(defn gen-proxy-granting-ticket-IOU [] (gen-ticket "PGTIOU-"))

;; 3.5. login ticket
;;
;;   A login ticket is a string that is provided by /login as a credential
;;   requestor and passed to /login as a credential acceptor for
;;   username/password authentication. Its purpose is to prevent the replaying
;;   of credentials due to bugs in web browsers.
;;
;; 3.5.1. login ticket properties
;;
;;   * Login tickets issued by /login MUST be probabilistically unique.
;;   * Login tickets MUST only be valid for one authentication attempt. Whether
;;   or not authentication was successful, CAS MUST then invalidate the login
;;   ticket, causing all future authentication attempts with that instance of
;;   that login ticket to fail.
;;   * Login tickets SHOULD begin with the characters, "LT-".
;;
(defn gen-login-ticket [] (gen-ticket "LT-"))

;; 3.6. ticket-granting cookie
;;
;;   A ticket-granting cookie is an HTTP cookie set by CAS upon the
;;   establishment of a single sign-on session. This cookie maintains login
;;   state for the client, and while it is valid, the client can present it to
;;   CAS in lieu of primary credentials. Services can opt out of single sign-on
;;   through the "renew" parameter described in Sections 2.1.1, 2.4.1, and
;;   2.5.1.
;;
;; 3.6.1. ticket-granting cookie properties
;;
;;   * Ticket-granting cookies MUST be set to expire at the end of the client's
;;   browser session.
;;   * CAS MUST set the cookie path to be as restrictive as possible. For
;;   example, if the CAS server is set up under the path /cas, the cookie path
;;   MUST be set to /cas.
;;   * The value of ticket-granting cookies MUST contain adequate secure random
;;   data so that a ticket-granting cookie is not guessable in a reasonable
;;   period of time.
;;   * The value of ticket-granting cookies SHOULD begin with the characters,
;;   "TGC-".
;;
(defn gen-ticket-granting-cookie [] (gen-ticket "TGC-"))

;; 3.7. ticket and ticket-granting cookie character set
;;
;;   In addition to the above requirements, all CAS tickets and the value of
;;   the ticket-granting cookie MUST contain only characters from the set {A-Z,
;;   a-z, 0-9, and the hyphen character '-'}.
;;
(let [orig-gen-ticket gen-ticket
      bad-chars #"[^A-Za-z0-9-]+"]

  ; wrap original implementation in case it changes to have unsafe chars
  (defn- gen-ticket [prefix]
    (clojure.string/replace (orig-gen-ticket prefix) bad-chars "")))

