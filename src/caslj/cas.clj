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
                "")

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
                 "")

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
                ;; 2.4.2. response
                ;; 2.4.3. URL examples of /validate
                "")

           ;; 2.5. /serviceValidate [CAS 2.0]
           (ANY "/serviceValidate"
                ;; 2.5.1. parameters
                ;; 2.5.2. response
                ;; 2.5.3. error codes
                ;; 2.5.4. proxy callback
                ;; 2.5.5. URL examples of /serviceValidate
                "")

           ;; 2.6. /proxyValidate [CAS 2.0]
           (ANY "/proxyValidate"
                ;; 2.6.1. parameters
                ;; 2.6.2. response
                ;; 2.6.3 URL examples of /proxyValidate
                "")

           ;; 2.7. /proxy [CAS 2.0]
           (ANY "/proxy"
                ;; 2.7.1. parameters
                ;; 2.7.2. response
                ;; 2.7.3. error codes
                ;; 2.7.4. URL example of /proxy
                ""))

;; 3. CAS Entities
;; 3.1. service ticket
;; 3.1.1. service ticket properties
;; 3.2. proxy ticket
;; 3.2.1. proxy ticket properties
;; 3.3. proxy-granting ticket
;; 3.3.1. proxy-granting ticket properties
;; 3.4. proxy-granting ticket IOU
;; 3.4.1. proxy-granting ticket IOU properties
;; 3.5. login ticket
;; 3.5.1. login ticket properties
;; 3.6. ticket-granting cookie
;; 3.6.1. ticket-granting cookie properties
;; 3.7. ticket and ticket-granting cookie character set
