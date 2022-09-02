# -*- encoding : utf-8 -*-
control "KEYC-01-000043" do
  title "Keycloak must be configured to map the authenticated identity to the user account for PKI-based authentication."
  desc  "Without mapping the certificate used to authenticate to the user account, the ability to determine the identity of the individual user or group will not be available for forensic analysis."
  desc  "rationale", ""
  desc  "check", "
    If Keycloak rely on directory services for user account management, this is not applicable and the connected directory services must perform this function.
    
    Verify Keycloak are configured to map the authenticated identity to the user account for PKI-based authentication.
    
    If Keycloak are not configured to map the authenticated identity to the user account, this is a finding.
    
    To confirm this setting is configured using the Keycloak admin CLI, after logging in with a privileged account, which can be done by running:
    
    kcadm.sh config credentials --server [server location] --realm master --user [username] --password [password]
    
    then run the following command:
    
    kcadm.sh get authentication/flows -r [YOUR REALM] 
    
    Then list executions for browser flows (including default and custom browser flows): 
    
    kcadm.sh get authentication/flows/[FLOW_ALIAS]/executions -r [YOUR REALM] 
    
    If the result does not contain any executions containing the following key-value pair, it is a finding.
    
    \"providerId\" : \"auth-x509-client-username-form\"
    
    Then get the configuration for the above execution with following command: 
    
    kcadm.sh get authentication/config/[EXECUTION's authenticationConfig ATTRIBUTE] -r [YOUR REALM]
    
    If the result contains neither of below two cases, this is a finding. 
    
    \"x509-cert-auth.mapper-selection\": \"Username or Email\"
    
    OR:
    
    \"x509-cert-auth.mapper-selection\": \"Custom Attribute Mapper\"
    \"x509-cert-auth.mapper-selection.user-attribute-name\" : \"Certificate Serial Number and IssuerDN\",
  "
  desc  "fix", "
    Configure Keycloak to map the authenticated identity to the user account for PKI-based authentication.
    
    There are two cases. 
    
    Case 1: There does not exist an execution with providerId \"auth-509-client-username-form\", use the following commands:  
    
    kcadm.sh create authentication/flows/browser/copy -s \"providerId\"=\"basic_flow\"
    kcadm.sh get authentication/flows 
    kcadm.sh update authentication/flows/[id] -s \"alias\"=[APPROPRIATE FLOW ALIAS]
    kcadm.sh create authentication/flows/[ALIAS]/executions/execution -s \"provider\"=\"auth-x509-client-username-form\"
    kcadm.sh get authentication/flows/[FLOW_ALIAS]/executions -r [YOUR REALM] 
    kcadm.sh create \"authentication/executions/[X509 EXECUTION's id ATTRIBUTE]/config\" -r [YOUR REALM] -b '{\"config\":{[APPROPRIATE X509 SETTING],\"x509-cert-auth.mapper-selection\":\"Username or Email\"}}'
    
    
    Case 2: There exist an execution with providerId \"auth-509-client-username-form\", but appropriate settings are not set. Use the following commands:
    
    kcadm.sh get authentication/flows -r [YOUR REALM] 
    
    Then list executions for browser flows (including default and custom browser flows): 
    kcadm.sh get authentication/flows/[FLOW_ALIAS]/executions -r [YOUR REALM] 
    
    Then update the configuration for the above execution with following command: 
    kcadm.sh update \"authentication/config/[EXECUTION's authenticationConfig ATTRIBUTE]\" -r [YOUR REALM] -b '{\"id\":[id],\"alias\":[APPROPRIATE ALIAS],\"config\":{[APPROPRIATE X509 SETTING],\"x509-cert-auth.mapper-selection\":\"Username or Email\"}}'
    
  "
  impact 0.5
  tag severity: "medium"
  tag gtitle: "SRG-APP-000177-AAA-000600"
  tag gid: nil
  tag rid: nil
  tag stig_id: "KEYC-01-000043"
  tag cci: ["CCI-000187"]
  tag nist: ["IA-5 (2) (c)"]
end