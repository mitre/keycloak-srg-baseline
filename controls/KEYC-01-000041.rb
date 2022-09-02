# -*- encoding : utf-8 -*-
control "KEYC-01-000041" do
  title "Keycloak must be configured to not accept certificates that have been revoked for PKI-based authentication."
  desc  "
    Without path validation, an informed trust decision by the relying party cannot be made when presented with any certificate not already explicitly trusted.
    
    A trust anchor is an authoritative entity represented via a public key and associated data. It is used in the context of public key infrastructures, X.509 digital certificates, and DNSSEC. 
    
    When there is a chain of trust, usually the top entity to be trusted becomes the trust anchor; it can be, for example, a Certification Authority (CA). A certification path starts with the subject certificate and proceeds through a number of intermediate certificates up to a trusted root certificate, typically issued by a trusted CA. 
    
    This requirement verifies that a certification path to an accepted trust anchor is used to for certificate validation and that the path includes status information. Path validation is necessary for a relying party to make an informed trust decision when presented with any certificate not already explicitly trusted. Status information for certification paths includes certificate revocation lists or online certificate status protocol responses.
  "
  desc  "rationale", ""
  desc  "check", "
    Verify Keycloak are configured to reflect certificates that have been revoked for PKI-based authentication.
    
    If Keycloak are not configured to reject certificates that have been revoked, this is a finding.
    
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
    
    If the result does not contain the following key-value pair, this is a finding. 
    
    \"x509-cert-auth.timestamp-validation-enabled\" : \"true\"
  "
  desc  "fix", "
    Configure Keycloak to not accept certificates that have been revoked for PKI-based 
    
    There are two cases. 
    
    Case 1: There does not exist an execution with providerId \"auth-509-client-username-form\", use the following commands:  
    
    kcadm.sh create authentication/flows/browser/copy -s \"providerId\"=\"basic_flow\"
    kcadm.sh get authentication/flows 
    kcadm.sh update authentication/flows/[NEW FLOW's id] -s \"alias\"=[APPROPRIATE FLOW ALIAS]
    kcadm.sh create authentication/flows/[FLOW_ALIAS]/executions/execution -s \"provider\"=\"auth-x509-client-username-form\"
    kcadm.sh get authentication/flows/[FLOW_ALIAS]/executions -r [YOUR REALM] 
    kcadm.sh create \"authentication/executions/[X509 EXECUTION's id ATTRIBUTE]/config\" -r [YOUR REALM] -b '{\"config\":{[APPROPRIATE X509 SETTING],\"x509-cert-auth.timestamp-validation-enabled\":\"true\"}}'
    
    
    Case 2: There exist an execution with providerId \"auth-509-client-username-form\", but appropriate settings are not set. Use the following commands:
    
    kcadm.sh get authentication/flows -r [YOUR REALM] 
    
    Then list executions for browser flows (including default and custom browser flows): 
    kcadm.sh get authentication/flows/[FLOW_ALIAS]/executions -r [YOUR REALM] 
    
    Then update the configuration for the above execution with following command: 
    kcadm.sh update \"authentication/config/[EXECUTION's authenticationConfig ATTRIBUTE]\" -r [YOUR REALM] -b '{\"id\":[id],\"alias\":[APPROPRIATE EXECUTION ALIAS],\"config\":{[APPROPRIATE X509 SETTING],\"x509-cert-auth.timestamp-validation-enabled\":\"true\"}}'
  "
  impact 0.7
  tag severity: "high"
  tag gtitle: "SRG-APP-000175-AAA-000580"
  tag gid: nil
  tag rid: nil
  tag stig_id: "KEYC-01-000041"
  tag cci: ["CCI-000185"]
  tag nist: ["IA-5 (2) (a)"]
end