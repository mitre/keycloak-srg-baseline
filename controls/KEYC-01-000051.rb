# -*- encoding : utf-8 -*-
control "KEYC-01-000051" do
  title "Keycloak must be configured to automatically audit account enabling actions."
  desc  "Once an attacker establishes access to an application, the attacker often attempts to create a persistent method of reestablishing access. One way to accomplish this is for the attacker to simply enable a new or disabled account. Automatically auditing account enabling actions provides logging that can be used for forensic purposes."
  desc  "rationale", ""
  desc  "check", "
    If Keycloak rely on directory services for user account management, this is not applicable and the connected directory services must perform this function. 
    
    Verify Keycloak are configured to automatically audit account enabling actions.
    
    If Keycloak are not configured to automatically audit account enabling actions, this is a finding.
    
    To check if Keycloak is configured to audit account creation, you can run the following commands from a privileged account on the Keycloak admin CLI:
    
    kcadm.sh get events/config -r [your realm] | grep adminEvents
    
    If the results are not as follows, then it is a finding.
    
    \"adminEventsEnabled\" : true,
    \"adminEventsDetailsEnabled\" : true
    
  "
  desc  "fix", "
    Configure Keycloak to automatically audit account enabling actions.
    
    To configure this setting using the Keycloak admin CLI, do the following from a privileged account:
    First, find the current configuration: 
    
    kcadm.sh get events/config -r [your realm] | grep adminEvents
    
    Next, update the configuration:
    
    kcadm.sh update events/config -r [your realm] -s adminEventsEnabled=true -s adminEventsDetailsEnabled=true
  "
  impact 0.5
  tag severity: "medium"
  tag gtitle: "SRG-APP-000319-AAA-000170"
  tag gid: nil
  tag rid: nil
  tag stig_id: "KEYC-01-000051"
  tag cci: ["CCI-002130"]
  tag nist: ["AC-2 (4)"]
end