# -*- encoding : utf-8 -*-
control "KEYC-01-000019" do
  title "Keycloak must be configured to queue audit records locally until communication is restored when any audit processing failure occurs."
  desc  "
    It is critical that when Keycloak are at risk of failing to process audit logs as required, it take action to mitigate the failure. Audit processing failures include software/hardware errors, failures in the audit capturing mechanisms, and audit storage capacity being reached or exceeded. Responses to audit failure depend upon the nature of the failure mode. 
    
    For Keycloak, availability is an overriding concern, and so both of the following approved actions in response to an audit failure must be met:
    
    (i) If the failure was caused by the lack of audit record storage capacity, Keycloak must continue generating audit records if possible (automatically restarting the audit service if necessary), overwriting the oldest audit records in a first-in-first-out manner.
    (ii) If audit records are sent to a centralized collection server and communication with this server is lost or the server fails, Keycloak must queue audit records locally until communication is restored or until the audit records are retrieved manually. Upon restoration of the connection to the centralized collection server, action should be taken to synchronize the local audit data with the collection server.
  "
  desc  "rationale", ""
  desc  "check", "
    Verify Keyclok are configured to queue audit records locally when any audit processing failure occurs. The queuing must continue until communication is restored or until the audit records are retrieved manually. Some specific implementations may further require automatically restarting the audit service to synchronize the local audit data with the collection server.
    
    If Keyclok are not configured to queue audit records locally until communication is restored when any audit processing failure occurs, this is a finding.
    
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
    
    Then verify that the log service queues audit records locally until communication is restored with the following lines: 
    
    sudo grep -i '$ActionQueueType' /etc/rsyslog.conf /etc/rsyslog.d/*.conf 
    
    sudo grep -i '$ActionQueueFileName' /etc/rsyslog.conf /etc/rsyslog.d/*.conf 
    
    sudo grep -i '$ActionResumeRetryCount' /etc/rsyslog.conf /etc/rsyslog.d/*.conf 
    
    sudo grep -i '$ActionQueueSaveOnShutdown' /etc/rsyslog.conf /etc/rsyslog.d/*.conf 
    
    If there are no outputs for the above commands, or if the resulting lines are commented out, or if value of '$ActionResumeRetry' is not '-1', or if value of '$ActionQueueSaveOnShutdown' is not 'on', this is a finding. 
  "
  desc  "fix", "
    Configure Keyclok to queue audit records locally until communication is restored when any audit processing failure occurs. Some specific implementations may further require automatically restarting the audit service to synchronize the local audit data with the collection server. In some cases, AAA Services may require the audit records to be retrieved manually in the event of audit failure.
    
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
    
    Then use the following configuration in /etc/rsyslog.conf or create a file with the following content in the /etc/rsyslog.d/ directory
    
    $ActionQueueType LinkedList
    
    $ActionQueueFileName example_fwd
    
    $ActionResumeRetryCount -1
    
    $ActionQueueSaveOnShutdown on
  "
  impact 0.5
  tag severity: "medium"
  tag gtitle: "SRG-APP-000109-AAA-000310"
  tag gid: nil
  tag rid: nil
  tag stig_id: "KEYC-01-000019"
  tag cci: ["CCI-000140"]
  tag nist: ["AU-5 b"]
end