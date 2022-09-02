# -*- encoding : utf-8 -*-
control "KEYC-01-000036" do
  title "Keycloak must be configured to encrypt locally stored credentials using a FIPS-validated cryptographic module."
  desc  "
    Passwords need to be protected at all times, and encryption is the standard method for protecting passwords. If passwords are not encrypted, they can be plainly read (i.e., clear text) and easily compromised.
    
    Keycloak must enforce cryptographic representations of passwords when storing passwords in databases, configuration files, and log files. Passwords must be protected at all times; using a strong one-way hashing encryption algorithm with a salt is the standard method for providing a means to validate a password without having to store the actual password.
    
    Performance and time required to access are factors that must be considered, and the one-way hash is the most feasible means of securing the password and providing an acceptable measure of password security. If passwords are stored in clear text, they can be plainly read and easily compromised.
  "
  desc  "rationale", ""
  desc  "check", "
    Where passwords are used, verify Keycloak are configured to encrypt locally stored credentials using a FIPS-validated cryptographic module. Keycloak may leverage the capability of an operating system or purpose-built module for this purpose. 
    
    Confirm that databases, configuration files, and log files have encrypted representations for all passwords, and that no password strings are readable/discernable. Potential locations include the local file system where configurations and events are stored, or in a related database table.
    
    Review Keycloak configuration for use of the MD5 algorithm to create password hashes.
    
    If Keycloak are not configured to encrypt locally stored credentials using a FIPS-validated cryptographic module, this is a finding.
    
    If Keycloak are configured to use MD5 to create password hashes, this is a finding.
    
    To confirm this setting is configured using the Keycloak admin CLI, after logging in with a privileged account, which can be done by running:
    
    kcadm.sh config credentials --server [server location] --realm master --user [username] --password [password]
    
    then run the following command:
    
    kcadm.sh get realms/[YOUR REALM] | grep 'hashAlgorithm'
    
    If configured correctly, this command should return password policy information that uses FIPS compliant cryptographic module.
    If the command returns with an empty string or null, or the cryptographic module does not meet FIPS compilance, this is a finding.
    
    Note: FIPS-validated cryptographic modules are listed on the NIST Cryptographic Module Validation Program's (CMVP) validation list.
  "
  desc  "fix", "
    Configure Keycloak to encrypt locally stored credentials using a FIPS-validated cryptographic module.
    
    Configure all associated databases, configuration files, and audit files to use only encrypted representations for all passwords and so that no password strings are readable/discernable.
    
    To configure this settings using the Keycloak admin CLI, do the following from a privileged account:
    First, find the current setting for hash algorithms: 
    
    kcadm.sh get realms/[YOUR REALM] | grep 'hashAlgorithm'
    
    Next, concatenate the string 'hashAlgorithm(pbkdf2-sha256)' to the current setting or update the setting if it is already set. If there is no password policy set, you can set it for the first time using the same process.
    Finally, update the password policy in corresponding to the current settings with requirement of FIPS compliant cryptographic module
    
    kcadm.sh update realms/[YOUR REALM] -s 'passwordPolicy=\"[content from current password policy] and hashAlgorithm(pbkdf2-sha256)\"'
  "
  impact 0.7
  tag severity: "high"
  tag gtitle: "SRG-APP-000171-AAA-000510"
  tag gid: nil
  tag rid: nil
  tag stig_id: "KEYC-01-000036"
  tag cci: ["CCI-000196"]
  tag nist: ["IA-5 (1) (c)"]
end