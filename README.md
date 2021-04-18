View this file RAW for better explanation.

# openxpki-setup-script
Edited the provided sampleconfig to allow for complete first-run additional configurations.

This script should get your instance of OpenXPKI up and running in a few minutes but you will still need to configure the deeper settings in the individual
Realm/ files.

According to notes from the developers, each Root can have only 1 Intermediate.

CORRECT USE (per developer)
#########################################
Root (REALM01) -> Intermediate01 (issuer) -> Signed certificate 01
#########################################

For multiple Intermediates for the same ROOT,
Copy Root Certificate to new realm, rename it to your naming scheme for the realm, and create intermediate and scep for that realm using the script.

This is how you have multiple, seperate Intermediate (Issuing) certificates.
