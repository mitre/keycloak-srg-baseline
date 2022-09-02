# -*- encoding : utf-8 -*-
control "KEYC-01-000005" do
  title "Keycloak must be configured to automatically audit account creation."
  desc  "Once an attacker establishes access to a system, the attacker often attempts to create a persistent method of reestablishing access. One way to accomplish this is for the attacker to simply create a new account. Auditing of account creation is one method for mitigating this risk. A comprehensive account management process will ensure an audit trail documents the creation of user accounts and, as required, notifies administrators and/or managers. Such a process greatly reduces the risk that accounts will be surreptitiously created and provides logging that can be used for forensic purposes."
  desc  "rationale", ""
  desc  "check", "
    If Keycloak relies on directory services for user account management, this is not applicable and the connected directory services must perform this function. 
    
    Verify Keycloak is configured to automatically audit account creation.
    
    If Keycloak is not configured to automatically audit account creation, this is a finding.
    
    To check if Keycloak is configured to audit account creation, log into the Keycloak admin CLI with a privileged account:
    
    kcadm.sh config credentials --server [server location] --realm master --user [username] --password [password]
    
    Then run the following command: 
    
    kcadm.sh get events/config -r [YOUR REALM] 
    
    If the results are not as follows, then it is a finding.
    
    \"eventsEnabled\" : true, 
    \"eventsListeners\" : [ \"jboss-logging\" ],
    \"enabledEventTypes\" : [ list with REGISTER concatenated ]
    \"adminEventsEnabled\" : true,
    \"adminEventsDetailsEnabled\" : true
    
    Note: Enabling 'events', 'adminEvents' and 'adminEventsDetails', along with configuring 'eventsListeners' and 'enabledEventTypes',  configures Keycloak to audit login events, account creations, account updates, account deletions, and admin actions.
  "
  desc  "fix", "
    Configure Keycloak to automatically audit account creation.
    
    To configure this setting using the Keycloak admin CLI, do the following from a privileged account:
    
    First, find the current enabled event types: 
    
    kcadm.sh get events/config -r [your realm] | grep enabledEventTypes 
    
    Then update the configuration: 
    
    kcadm.sh update events/config -r [your realm] -s adminEventsEnabled=true -s adminEventsDetailsEnabled=true -s eventsEnabled=true -s 'eventsListeners=[\"jboss-logging\"] -s enabledEventTypes=\"[full list with REGISTER concatenated]\"
    
    Note: Enabling 'events', 'adminEvents' and 'adminEventsDetails', along with configuring 'eventsListeners' and 'enabledEventTypes',  configures Keycloak to audit login events, account creations, account updates, account deletions, and admin actions.
  "
  impact 0.5
  tag severity: "medium"
  tag gtitle: "SRG-APP-000026-AAA-000090"
  tag gid: nil
  tag rid: nil
  tag stig_id: "KEYC-01-000005"
  tag cci: ["CCI-000018"]
  tag nist: ["AC-2 (4)"]

  eventsEnabled = '"eventsEnabled" : true'
  eventsListeners = '"eventsListeners" : [ "jboss-logging" ]'
  enabledEventTypes = '"enabledEventTypes" : [ "SEND_RESET_PASSWORD", "UPDATE_CONSENT_ERROR", "GRANT_CONSENT", "VERIFY_PROFILE_ERROR", "REMOVE_TOTP", "REVOKE_GRANT", "UPDATE_TOTP", "LOGIN_ERROR", "CLIENT_LOGIN", "RESET_PASSWORD_ERROR", "IMPERSONATE_ERROR", "CODE_TO_TOKEN_ERROR", "CUSTOM_REQUIRED_ACTION", "OAUTH2_DEVICE_CODE_TO_TOKEN_ERROR", "RESTART_AUTHENTICATION", "IMPERSONATE", "UPDATE_PROFILE_ERROR", "LOGIN", "OAUTH2_DEVICE_VERIFY_USER_CODE", "UPDATE_PASSWORD_ERROR", "CLIENT_INITIATED_ACCOUNT_LINKING", "TOKEN_EXCHANGE", "AUTHREQID_TO_TOKEN", "LOGOUT", "REGISTER", "DELETE_ACCOUNT_ERROR", "CLIENT_REGISTER", "IDENTITY_PROVIDER_LINK_ACCOUNT", "DELETE_ACCOUNT", "UPDATE_PASSWORD", "CLIENT_DELETE", "FEDERATED_IDENTITY_LINK_ERROR", "IDENTITY_PROVIDER_FIRST_LOGIN", "CLIENT_DELETE_ERROR", "VERIFY_EMAIL", "CLIENT_LOGIN_ERROR", "RESTART_AUTHENTICATION_ERROR", "EXECUTE_ACTIONS", "REMOVE_FEDERATED_IDENTITY_ERROR", "TOKEN_EXCHANGE_ERROR", "PERMISSION_TOKEN", "SEND_IDENTITY_PROVIDER_LINK_ERROR", "EXECUTE_ACTION_TOKEN_ERROR", "SEND_VERIFY_EMAIL", "OAUTH2_DEVICE_AUTH", "EXECUTE_ACTIONS_ERROR", "REMOVE_FEDERATED_IDENTITY", "OAUTH2_DEVICE_CODE_TO_TOKEN", "IDENTITY_PROVIDER_POST_LOGIN", "IDENTITY_PROVIDER_LINK_ACCOUNT_ERROR", "OAUTH2_DEVICE_VERIFY_USER_CODE_ERROR", "UPDATE_EMAIL", "REGISTER_ERROR", "REVOKE_GRANT_ERROR", "EXECUTE_ACTION_TOKEN", "LOGOUT_ERROR", "UPDATE_EMAIL_ERROR", "CLIENT_UPDATE_ERROR", "AUTHREQID_TO_TOKEN_ERROR", "UPDATE_PROFILE", "CLIENT_REGISTER_ERROR", "FEDERATED_IDENTITY_LINK", "SEND_IDENTITY_PROVIDER_LINK", "SEND_VERIFY_EMAIL_ERROR", "RESET_PASSWORD", "CLIENT_INITIATED_ACCOUNT_LINKING_ERROR", "OAUTH2_DEVICE_AUTH_ERROR", "UPDATE_CONSENT", "REMOVE_TOTP_ERROR", "VERIFY_EMAIL_ERROR", "SEND_RESET_PASSWORD_ERROR", "CLIENT_UPDATE", "CUSTOM_REQUIRED_ACTION_ERROR", "IDENTITY_PROVIDER_POST_LOGIN_ERROR", "UPDATE_TOTP_ERROR", "CODE_TO_TOKEN", "VERIFY_PROFILE", "GRANT_CONSENT_ERROR", "IDENTITY_PROVIDER_FIRST_LOGIN_ERROR" ]'
  adminEventsEnabled = '"adminEventsEnabled" : true'
  adminEventsDetailsEnabled = '"adminEventsDetailsEnabled" : true'

  describe command('/opt/keycloak/bin/kcadm.sh get events/config -r demo') do
    its('stdout') { should include eventsEnabled }
    its('stdout') { should include eventsListeners }
    its('stdout') { should include enabledEventTypes }
    its('stdout') { should include adminEventsEnabled }
    its('stdout') { should include adminEventsDetailsEnabled }
  end
end