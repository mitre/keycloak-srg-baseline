# -*- encoding : utf-8 -*-
control "KEYC-01-000023" do
  title "Keycloak must be configured to use protocols that encrypt credentials when authenticating clients, as defined in the PPSM CAL and vulnerability assessments."
  desc  "Authentication protection of the client credentials (specifically the password or shared secret) prevents unauthorized access to resources. The RADIUS protocol encrypts the password field in the access-request packet, from the client to the Keycloak. The remainder of the packet is unencrypted. Other information, such as username, authorized services, and accounting, can be captured by a third-party. TACACS+ encrypts the entire body of the packet but leaves a standard TACACS+ header. Within the header is a field that indicates whether the body is encrypted or not. Other protocols have similar protections. When unencrypted credentials are passed, adversaries can gain access to resources."
  desc  "rationale", ""
  desc  "check", "
    Verify Keycloak are configured to use protocols that encrypt credentials when authenticating clients. Both the RADIUS and TACACS+ protocols are acceptable when configured to perform encryption. For any protocol implemented, the PPSM CAL and vulnerability assessments must be reviewed to ensure the protocols are properly configured.
    
    If Keycloak are not configured to use protocols that encrypt credentials when authenticating clients, as defined in the PPSM CAL and vulnerability assessments, this is a finding.
    
    To confirm this setting is configured using the Keycloak admin CLI, after logging in with a privileged account, which can be done by running:
    
    kcadm.sh config credentials --server [server location] --realm master --user [username] --password [password]
    
    then run the following command:
    
    kcadm.sh get realms/[YOUR REALM] | grep 'hashAlgorithm'
    
    If the command returns with an empty string or null this is a finding.
    
    Then check keycloak configuration file, keycloak.conf. If the file does not contain the following key-value pairs, it is a finding. 
    
    cache=ispn 
    cache-stack=[APPROPRIATE TRANSPORTATION STACK]
  "
  desc  "fix", "
    Configure Keycloak to use protocols that encrypt credentials when authenticating clients. Both the RADIUS and TACACS+ protocols are acceptable when configured to perform encryption. For any protocol implemented, the PPSM CAL and vulnerability assessments must be reviewed to ensure the protocols are properly configured.
    
    To configure this settings using the Keycloak admin CLI, do the following from a privileged account:
    First, find the current setting for hash algorithms: 
    
    kcadm.sh get realms/[YOUR REALM] | grep 'hashAlgorithm'
    
    Next, concatenate the string 'hashAlgorithm(pbkdf2-sha256)' to the current setting or update the setting if it is already set. If there is no password policy set, you can set it for the first time using the same process.
    
    kcadm.sh update realms/[YOUR REALM] -s 'passwordPolicy=\"[content from current password policy] and hashAlgorithm(pbkdf2-sha256)\"'
    
    Then create or update Keycloak settings with the following lines in your keycloak configuration file, keycloak.conf:
    
    cache=ispn 
    cache-stack=tcp
  "
  impact 0.7
  tag severity: "high"
  tag gtitle: "SRG-APP-000142-AAA-000020"
  tag gid: nil
  tag rid: nil
  tag stig_id: "KEYC-01-000023"
  tag cci: ["CCI-000382"]
  tag nist: ["CM-7 b"]
end