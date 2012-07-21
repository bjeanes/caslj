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
;; 1.1. Conventions & Definitions

;; 2. CAS URIs
(defroutes cas-server

           ;; 2.1. /login as credential requester
           (GET "/login"

                ;; 2.1.1. parameters
                [service renew gateway]

                ;; 2.1.2. URL examples of /login

                ;; 2.1.3. response for username/password authentication
                ;; 2.1.4. response for trust authentication
                ;; 2.1.5. response for single sign-on authentication
                "not implemented")

           ;; 2.2. /login as credential acceptor
           (POST "/login"

                 [
                  ;; 2.2.1. parameters common to all types of authentication
                  service warn

                  ;; 2.2.2. parameters for username/password authentication
                  username password

                  ;; 2.2.3. parameters for trust authentication
                  ;; <none>
                  ]

                 ;; 2.2.4. response
                 "not implemented")

           ;; 2.3. /logout
           (ANY "/logout"

                ;; 2.3.1. parameters
                [url]

                ;; 2.3.2. response
                (str "You have been logged out."
                     (when url " Click <a href=\"" url "\">here</a> to return")))

           ;; 2.4. /validate [CAS 1.0]
           (ANY "/validate"

                ;; 2.4.1. parameters
                [service ticket renew]

                ;; 2.4.2. response
                (if (valid? ticket) ; FIXME: pseudo-code
                  (str "yes" \newline "username") ; TODO: replace with actual username
                  (str "no" \newline \newline))

                ;; 2.4.3. URL examples of /validate
                )


           ;; 2.5. /serviceValidate [CAS 2.0]
           (ANY "/serviceValidate"

                ;; 2.5.1. parameters
                [service ticket pgtUrl renew]

                ;; 2.5.2. response
                "not implemented"

                ;; 2.5.3. error codes
                ;; 2.5.4. proxy callback
                ;; 2.5.5. URL examples of /serviceValidate
                )

           ;; 2.6. /proxyValidate [CAS 2.0]
           (ANY "/proxyValidate"

                ;; 2.6.1. parameters
                [service ticket pgtUrl renew]

                ;; 2.6.2. response
                "not implemented"

                ;; 2.6.3 URL examples of /proxyValidate
                )

           ;; 2.7. /proxy [CAS 2.0]
           (ANY "/proxy"

                ;; 2.7.1. parameters
                [pgt targetService]

                ;; 2.7.2. response
                "not implemented"

                ;; 2.7.3. error codes
                ;; 2.7.4. URL example of /proxy
                ))

;; 3. CAS Entities
;;
(defn- gen-uuid [] (str (java.util.UUID/randomUUID)))
(defn- gen-ticket [prefix] (str prefix "-" (gen-uuid)))

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
(defn gen-service-ticket [] (gen-ticket "ST"))

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
(defn gen-proxy-ticket [] (gen-ticket "PT"))

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
(defn gen-proxy-granting-ticket [] (gen-ticket "PGT"))

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
(defn gen-proxy-granting-ticket-IOU [] (gen-ticket "PGTIOU"))

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
(defn gen-login-ticket [] (gen-ticket "LT"))

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
(defn gen-ticket-granting-cookie [] (gen-ticket "TGC"))

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

