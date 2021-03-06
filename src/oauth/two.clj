(ns oauth.two
  (:require [schema.core :as s]
            [ring.util.codec :as codec]
            [clojure.walk :as walk]
            [clojure.string :as str]))

;; -----------------------------------------------------------------------------
;; Schema

(def ^:private Map
  "Hash-map of keyword or string to any value"
  {(s/cond-pre s/Keyword s/Str) s/Any})

(def ^:private RequestMethod
  "Valid HTTP request methods"
  (s/enum :delete :get :head :patch :post :put :trace))

(def ^:private Request
  "A clj-http compatible request map that is also OAuth 1.0 compatible."
  {(s/optional-key :body)    s/Str
   (s/optional-key :headers) {s/Str s/Str}
   :request-method           RequestMethod
   :url                      s/Str})

(def Scope
  #{s/Str})

(def ClientConfig
  {(s/optional-key :redirect-uri) s/Str
   (s/optional-key :scope)        Scope
   :access-uri                    s/Str
   :authorize-uri                 s/Str
   :id                            s/Str
   :secret                        s/Str})

(def AuthorizationParams
  {(s/optional-key :redirect-uri) s/Str
   (s/optional-key :scope)        Scope
   (s/optional-key :state)        s/Str
   (s/cond-pre s/Keyword s/Str)   s/Any})

(def TokenRequestParams
  {(s/optional-key :redirect-uri) s/Str
   :code                          s/Str})

;; -----------------------------------------------------------------------------
;; Client

(defrecord Client [access-uri authorize-uri id secret redirect-uri scope])

(s/defn make-client :- Client
  [config :- ClientConfig]
  (map->Client config))

;; -----------------------------------------------------------------------------
;; Utils

(defn- filter-vals
  [m]
  (into {} (filter val m)))

(def ^:private form-encode
  (comp codec/form-encode filter-vals))

;; -----------------------------------------------------------------------------
;; Authorization URL

(s/defn join-scope :- (s/maybe s/Str)
  [scope :- (s/maybe Scope)]
  (some->> scope sort (str/join " ")))

(s/defn authorization-url :- s/Str
  ([client]        (authorization-url client {}     {}))
  ([client params] (authorization-url client params {}))
  ([client :- Client params :- AuthorizationParams more :- (s/maybe Map)]
   (str (:authorize-uri client)
        "?"
        (form-encode
         (merge
          more
          {"client_id"     (:id client)
           "redirect_uri"  (or (:redirect-uri params) (:redirect-uri client))
           "response_type" "code"
           "scope"         (join-scope (or (:scope params) (:scope client)))
           "state"         (:state params)})))))

;; -----------------------------------------------------------------------------
;; Access token request

(s/defn basic-auth
  [id secret]
  (codec/base64-encode (.getBytes ^String (str id ":" secret))))

(s/defn access-token-request :- Request
  [client :- Client params :- TokenRequestParams]
  (assert (:code params))
  {:request-method :post
   :url (:access-uri client)
   :headers
   (filter-vals
    {"authorization" (when-let [{:keys [id secret]} client]
                       (str "Basic " (basic-auth id secret)))
     "content-type"  "application/x-www-form-urlencoded"})
   :body
   (form-encode
    {"client_id"    (:id client)
     "code"         (:code params)
     "grant_type"   "authorization_code"
     "redirect_uri" (or (:redirect-uri params) (:redirect-uri client))})})
