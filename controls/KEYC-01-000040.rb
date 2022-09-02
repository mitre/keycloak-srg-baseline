# -*- encoding : utf-8 -*-
control "KEYC-01-000040" do
  title "Keycloak must be configured to only accept certificates issued by a DoD-approved Certificate Authority for PKI-based authentication."
  desc  "
    Without path validation, an informed trust decision by the relying party cannot be made when presented with any certificate not already explicitly trusted.
    
    A trust anchor is an authoritative entity represented via a public key and associated data. It is used in the context of public key infrastructures, X.509 digital certificates, and DNSSEC. 
    
    When there is a chain of trust, usually the top entity to be trusted becomes the trust anchor; it can be, for example, a Certification Authority (CA). A certification path starts with the subject certificate and proceeds through a number of intermediate certificates up to a trusted root certificate, typically issued by a trusted CA. 
    
    This requirement verifies that a certification path to an accepted trust anchor is used to for certificate validation and that the path includes status information. Path validation is necessary for a relying party to make an informed trust decision when presented with any certificate not already explicitly trusted. Status information for certification paths includes certificate revocation lists or online certificate status protocol responses.
  "
  desc  "rationale", ""
  desc  "check", "
    Verify Keycloak are configured to only accept certificates issued by a DoD-approved Certificate Authority for PKI-based authentication.
    
    If Keycloak are not configured to only accept certificates issued by a DoD-approved Certificate Authority, this is a finding.
    
    Check keycloak configuration file, conf/keycloak.conf. If the file does not contain the following key-value pairs, it is a finding. 
    
    hostname-strict-https=true
    https-client-auth=required
    
    spi-truststore-file-file=[PATH TO TRUST STORE FILE]
    spi-truststore-file-password=[APPROPRIATE PASSWORD]
    spi-truststore-file-hostname-verification-policy=[APPROPRIATE POLICY]
    
    Then verify that the certificate used in truststore is issued by a valid DoD certificate authority with following command: 
    
    openssl x509 -in [PATH TO TRUST STORE FILE] -text | grep -i \"issuer\" 
    
    If there is any issuer present in the certificate that is not a DoD approved certificate authority, this is a finding.
  "
  desc  "fix", "
    Configure Keycloak to only accept certificates issued by a DoD-approved Certificate Authority for PKI-based authentication.
    
    Create or update Keycloak configuration with the following lines in your keycloak configuration file, conf/keycloak.conf:
    
    hostname-strict-https=true
    https-client-auth=required
    
    spi-truststore-file-file=[PATH TO TRUST STORE FILE]
    spi-truststore-file-password=[APPROPRIATE PASSWORD]
    spi-truststore-file-hostname-verification-policy=[APPROPRIATE POLICY]
    
    Then inspect the certificates used in truststore with following command: 
    
    openssl x509 -in [PATH TO TRUST STORE FILE] -text | grep -i \"issuer\" 
    
    If there is any issuer present in the certificate that is not a DoD approved certificate authority, remove the certificates that have a CA that is non-DoD approved, and import DoD CA-approved certificates.
  "
  impact 0.7
  tag severity: "high"
  tag gtitle: "SRG-APP-000175-AAA-000570"
  tag gid: nil
  tag rid: nil
  tag stig_id: "KEYC-01-000040"
  tag cci: ["CCI-000185"]
  tag nist: ["IA-5 (2) (a)"]
end