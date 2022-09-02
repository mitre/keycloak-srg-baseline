# -*- encoding : utf-8 -*-
control "KEYC-01-000012" do
  title "Keycloak configuration audit records must identify when (date and time) the events occurred."
  desc  "
    Without establishing when events occurred, it is impossible to establish, correlate, and investigate the events relating to an incident.
    
    In order to compile an accurate risk assessment, and provide forensic analysis, it is essential for security personnel to know when events occurred (date and time). 
    
    Associating event types with detected events in the application and audit logs provides a means of investigating an attack; recognizing resource utilization or capacity thresholds; or identifying an improperly configured application.
  "
  desc  "rationale", ""
  desc  "check", "
    Verify Keycloak configuration audit records identify the date and time events occurred.
    
    If Keycloak configuration audit records do not identify when the events occurred, this is a finding.
    
    To confirm this setting is configured using the Keycloak admin CLI, after logging in with a privileged account, which can be done by running:
    
    kcadm.sh config credentials --server [server location] --realm master --user [username] --password [password]
    
    then run the following command:
    
    kcadm.sh get events/config -r [YOUR REALM] 
    
    If the results are not as follows, then it is a finding.
    
    \"eventsEnabled\" : true, 
    \"eventsListeners\" : [ \"jboss-logging\" ],
    \"enabledEventTypes\" : [ APPROPRIATE EVENT TYPES ],
    \"adminEventsEnabled\" : true,
    \"adminEventsDetailsEnabled\" : true
    
    Then run the command: 
    
    kcadm.sh get events -r [YOUR REALM]
    
    If the individual event from the resulting event lists does not contain the following key-value pair, then it is a finding. 
    
    \"time\" : [Time of the event]
    
    Then check keycloak configuration file, keycloak.conf. If the file does not contain the following key-value pair, it is a finding. 
    
    log-console-format=\"'%d{[APPROPRIATE DATE/TIME FORMATTING]} [OTHER FORMATTING SYMBOLS]'\"
    
    Note: Enabling 'events', 'adminEvents' and 'adminEventsDetails', along with configuring 'eventsListeners' and 'enabledEventTypes',  configures Keycloak to audit login events, account creations, account updates, account deletions, and admin actions.
  "
  desc  "fix", "
    Configure Keycloak audit records to identify when the events occurred by specifying the date and time.
    
    To configure this setting using the Keycloak admin CLI, do the following from a privileged account:
    
    kcadm.sh update events/config -r [your realm] -s eventsEnabled=true -s 'eventsListeners=[\"jboss-logging\"] -s adminEventsEnabled=true -s adminEventsDetailsEnabled=true
    
    Then create or update Keycloak logging format with the following line in your keycloak configuration file, keycloak.conf:
    
    log-console-format=\"'%d{yyyy-MM-dd HH:mm:ss,SSS} [OTHER FORMATTING SYMBOLS]'\"
    
    Note: Enabling 'events', 'adminEvents' and 'adminEventsDetails', along with configuring 'eventsListeners' and 'enabledEventTypes',  configures Keycloak to audit login events, account creations, account updates, account deletions, and admin actions.
  "
  impact 0.5
  tag severity: "medium"
  tag gtitle: "SRG-APP-000096-AAA-000230"
  tag gid: nil
  tag rid: nil
  tag stig_id: "KEYC-01-000012"
  tag cci: ["CCI-000131"]
  tag nist: ["AU-3"]
end