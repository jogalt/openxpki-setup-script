View this file RAW for better explanation.

# openxpki-setup-script
Edited the provided sampleconfig to allow for complete first-run additional configurations.

This script should get your instance of OpenXPKI up and running in a few minutes but you will still need to configure the deeper settings in the individual
Realm/ files.

According to notes from the developers, each Root can have only 1 Intermediate.

CORRECT USE (per developer)
#########################################
Root (REALM01
  Intermediate01 (issuer)
    Signed certificate 01
#########################################

INCORRECT USE (per developer)
#########################################
               Root
  Intermediate01  Intermediate02
      Cert01          Cert02
#########################################

If you want to have multiple Intermediate (Issuer) certificates, you need to create multiple Realms.

Realm01              Realm02
  Intermediate01       Intermediate02
    Cert01               Cert02
