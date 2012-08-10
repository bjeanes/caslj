(defproject caslj "0.1.0-SNAPSHOT"
            :description "CAS server pronounced 'Castle'"
            :url "http://example.com/FIXME"
            :license {:name "Eclipse Public License"
            :url "http://www.eclipse.org/legal/epl-v10.html"}
            :dependencies [[org.clojure/clojure "1.4.0"]
                           [ring "1.1.1"]
                           [compojure "1.1.1"]
                           [trammel "0.7.0"]]
            :profiles {:dev {:dependencies [[ring-mock "0.1.3"]]}}
            :main caslj.main)
