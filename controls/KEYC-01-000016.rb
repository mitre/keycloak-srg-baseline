# -*- encoding : utf-8 -*-
control "KEYC-01-000016" do
  title "Keycloak configuration audit records must identify any individual user or process associated with the event."
  desc  "
    Without information that establishes the identity of the subjects (i.e., users or processes acting on behalf of users) associated with the events, security personnel cannot determine responsibility for the potentially harmful event.
    
    Event identifiers (if authenticated or otherwise known) include, but are not limited to, user database tables, primary key values, user names, or process identifiers.
  "
  desc  "rationale", ""
  desc  "check", "
    Verify Keycloak configuration audit records identify any individual user associated with the event. When a system process rather than an individual user causes the event, the process must be identified in the audit record.
    
    If Keycloak configuration audit records do not identify any individual user or process associated with the event, this is a finding.
    
    To check if Keycloak is configured to audit this setting, run the following commands from a privileged account on the Keycloak admin CLI:
    
    kcadm.sh get events/config -r [your realm] | grep 'eventsEnabled'
    
    kcadm.sh get events/config -r [your realm] | grep 'eventsListeners'
    
    If the results are not as follows, then it is a finding.
    
    \"eventsEnabled\" : true,
    \"eventsListeners\" : [ \"jboss-logging\" ]
    
    Note: To view any individual user or process associated with the event: 
      1) For login events: Navigate on GUI to 'Events' -> 'Login Events', and view event identifiers in 'Details' 
      2) For admin events: Navigate on GUI to 'Events' -> 'Admin Events', and view event identifiers in 'Details' -> 'Auth' 
      
  "
  desc  "fix", "
    Configure Keycloak configuration audit records to identify any individual user associated with the event. When events are caused by a system process rather than an individual user, that process must be identified in the audit record.
    
    To configure this setting using the Keycloak admin CLI, do the following from a privileged account:
    
    kcadm.sh update events/config -r [your realm] -s eventsEnabled=true -s 'eventsListeners=[\"jboss-logging\"]'
  "
  impact 0.5
  tag severity: "medium"
  tag gtitle: "SRG-APP-000100-AAA-000270"
  tag gid: nil
  tag rid: nil
  tag stig_id: "KEYC-01-000016"
  tag cci: ["CCI-001487"]
  tag nist: ["AU-3"]
end