# -*- encoding : utf-8 -*-
control "KEYC-01-000055" do
  title "Keycloak must be configured to send audit records to a centralized audit server."
  desc  "
    Information stored in one location is vulnerable to accidental or incidental deletion or alteration.
    
    Off-loading is a common process in information systems with limited audit storage capacity.
  "
  desc  "rationale", ""
  desc  "check", "
    Verify Keycloak is configured to send audit records to a centralized audit server.
    
    If Keycloak is not configured to send audit records to a centralized audit server, this is a finding.
    
    To confirm this setting is configured using the Keycloak admin CLI, after logging in with a privileged account, which can be done by running:
    
    kcadm.sh config credentials --server [server location] --realm master --user [username] --password [password]
    
    then run the following command:
    
    kcadm.sh get events/config -r [YOUR REALM] 
    
    If the results are not as follows, then it is a finding.
    
    \"eventsEnabled\" : true, 
    \"eventsListeners\" : [ \"jboss-logging\" ],
    \"enabledEventTypes\" : [ APPROPRIATE EVENT TYPES ],
    
    Then check keycloak configuration file, conf/keycloak.conf. If the file does not contain the following key-value pairs, it is a finding. 
    
    spi-events-listener-jboss-logging-success-level=info 
    spi-events-listener-jboss-logging-error-level=error
    
    Then check quarkus configuration file, conf/quarkus.properties. If the file does not contain the following key-value pairs, it is a finding. 
    
    quarkus.log.syslog.enable=true
    quarkus.log.syslog.endpoint=[APPROPRIATE ENDPOINT]
    quarkus.log.syslog.protocol=[APPROPRIATE PROTOCOL]
    
    Then check that the log service is enabled on the system with the following command: 
     
    systemctl is-enabled rsyslog  
     
    If the command above returns \"disabled\", this is a finding. 
     
    Check that the log service is properly running and active on the system with the following command: 
     
    systemctl is-active rsyslog  
     
    If the command above returns \"inactive\", this is a finding.
  "
  desc  "fix", "
    Configure Keycloak to send audit records to a centralized audit server.
    
    To configure this setting using the Keycloak admin CLI, do the following from a privileged account:
    
    kcadm.sh update events/config -r [your realm] -s eventsEnabled=true -s eventsListeners=[\"jboss-logging\"] -s adminEventsEnabled=true -s adminEventsDetailsEnabled=true
    
    Then create or update keycloak configuration file, conf/keycloak.conf:
    
    spi-events-listener-jboss-logging-success-level=info 
    spi-events-listener-jboss-logging-error-level=error
    
    Then create or update quarkus configuration file, conf/quarkus.properties: 
    
    quarkus.log.syslog.enable=true
    quarkus.log.syslog.endpoint=[APPROPRIATE ENDPOINT]
    quarkus.log.syslog.protocol=[APPROPRIATE PROTOCOL]
     
    Then install the log service (if the log service is not already installed) on system with the following command: 
     
    sudo apt-get install rsyslog 
     
    Enable the log service with the following command: 
     
    sudo systemctl enable --now rsyslog
  "
  impact 0.5
  tag severity: "medium"
  tag gtitle: "SRG-APP-000358-AAA-000280"
  tag gid: nil
  tag rid: nil
  tag stig_id: "KEYC-01-000055"
  tag cci: ["CCI-001851"]
  tag nist: ["AU-4 (1)"]
end