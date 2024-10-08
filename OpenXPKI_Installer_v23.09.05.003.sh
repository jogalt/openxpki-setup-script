#!/bin/bash

#Used to output echo the content of datbase configs for external DBs
exe() { sudo "\$ ${@/eval/}" ; "$@" ; }

#
# Check for Sudo Perms
#
echo -e "\nChecking for Root Privileges..."
if [[ "$EUID" = 0 ]]; then
    echo -e "Running script as root.\n"
else
    sudo -k # Ask for password
    if sudo true; then
        echo "Correct Password"
    else
        echo "Wrong Password"
        exit 1
    fi
fi

# Grab the IP address
ipAddr=`hostname -I`
# Grab the hostname for reference
FQDN=`hostname -f`
# Capitalize hostname
UFQDN="${FQDN^^}"

# Global Variables
BASE_DIR="/etc/openxpki"
### Add a switch somewhere that will edit relevant files for BASE_DIR
OPENXPKI_CONFIG="${BASE_DIR}/config.d/system/server.yaml"
CONF_DIR="${BASE_DIR}/config.d"

check_installed () {
#
# basic openxpki settings
#
if [ -f "${OPENXPKI_CONFIG}" ]
then
   eval `egrep '^user:|^group:' "${OPENXPKI_CONFIG}" | sed -e 's/:  */=/g'`
else
   echo "ERROR: It seems that OpenXPKI is not installed at the default location (${BASE_DIR})!" >&2
   echo "Please install OpenXPKI or set BASE to the new PATH!" >&2
   exit 1
fi
}
#
# Notes to user who's executing script
#
echo "This script, when run on a new system or when repopulating an empty certificate directory"
echo "will create a Root certificate, Intermediate (Issuing) Certificate, SCEP certificate, RAToken Certificate"
echo "and a self-signed DataVault certificate which encrypts everything else, like a wrapper."
echo "If you wish to use your pre-existing or company certificates, they need to be pre-loaded"
echo "in the certificate directory where this script will search for them. If you want to start from"
echo "scratch or if you want to test the output, leave the directory empty."
echo -e "\nThe directory is/will be    ${BASE_DIR}/ca/realm/    where realm is the name you will define"
echo "in the following questions. "

#
# Basic questions to populate the script with.
#
question_realm () {
echo -e "\n\n\nI'm going to ask some questions to facilitate an easier setup."
echo -e "This is how the realm and subsequent certificates will be defined."
echo -e "This script is not error checking, please be deliberate with your input"
echo -e "as bad input will cause the script to fail, with little to no information.\n"
echo -e "What is the base name of your organization? E.g. Google, Facebook, Amazon, Cisco"
read input_realm
# Converting to Lowercase to standardize folder layout
REALM="${input_realm,,}"
}

question_ou () {
echo -e "What is the Organizational Unit (OU) for the PKI Server? Press Enter for the default: PKI\n"
read input_ou

# Check for empty or not and set.
if [ -z "$input_ou" ]; then
    OrgU="PKI"
else
    OrgU="${input_ou^^}"
fi
}

question_rootVer () {
# For tracking purposes, ask user what number Root Certificate this is.
echo "What is the number/version of the Root certificate? If this is the first time you're making"
echo "a Root certificate, press Enter and it will automatically be '01', else, enter a number."
read input_rootCertVer

# Check for empty or not and set.
if [ -z "$input_rootCertVer" ]; then
    rootVer="01"
else
    rootVer="$input_rootCertVer"
fi
}

question_interVer () {
# For tracking purposes, ask user what number Intermediate this Root is issuing.
echo "What is the number/version of the Intermediate (Issuer) certificate? If this is the first time you're making"
echo "an Intermediate (Issuer) certificate, press Enter and it will automatically be '01', else, enter a number."
read input_interVer
# Check for empty or not and set.
if [ -z "$input_interVer" ]; then
    interVer="01"
else
    interVer="$input_interVer"
fi
}

question_scepVer () {
# For tracking purposes, ask user what number SCEP Certificate is being issued.
echo "What is the number/version of the SCEP certificate? If this is the first time you're making"
echo "a SCEP certificate, press Enter and it will automatically be '01', else, enter a number."
read input_scepVer
# Check for empty or not and set.
if [ -z "$input_scepVer" ]; then
    scepVer="01"
else
    scepVer="$input_scepVer"
fi
}

question_ratokenVer () {
# For tracking purposes, ask user what number RATOKEN Certificate is being issued.
echo "What is the number/version of the RAToken certificate? If this is the first time you're making"
echo "a RATOKEN certificate, press Enter and it will automatically be '01', else, enter a number."
read input_ratokenVer
# Check for empty or not and set.
if [ -z "$input_ratokenVer" ]; then
    ratokenVer="01"
else
    ratokenVer="$input_ratokenVer"
fi
}

question_webVer () {
echo "What version of Web Certificate are you issuing for THIS server? Default is: 01."
read input_webVer
# Check for empty or not and set.
if [ -z "$input_webVer" ]; then
    webVer="01"
else
    webVer="$input_webVer"
fi
}

question_country () {
## Future error checking for Country code and State code as these could cause invalid certificates.
echo -e "What's your two-letter country code? Default is: US\n"
read input_country
if [ -z "$input_country" ]; then
    COUNTRY="US"
else
    COUNTRY="${input_country^^}"
fi
}

question_state () {
## State or Area Code
echo -e "What's your two-letter State or equivalent code? Defaul is: DC\n"
read input_state
if [ -z "$input_state" ]; then
    STATE="VA"
else
    STATE="${input_state^^}"
fi
}

question_locality () {
# Locality Code
echo -e "What's your locality? This can be the city, town, village etc.. Default is: WB\n"
read input_locality
if [ -z "$input_locality" ]; then
    LOCALITY="WB"
else
    LOCALITY="${input_locality^}"
fi
}

create_argon () {
unset password;
while IFS= read -r -s -n1 pass; do
  if [[ -z $pass ]]; then
     echo
     break
  else
     echo -n '*'
     password+=$pass
  fi
done
salt=`openssl rand 24 | base64`
pass2=`echo $password | argon2 $salt -id -k 32768 -t 3 -p 1 -l 16 -e`
}


question_email () {
# Email
echo -e "What's your email address or distro for the root certs?\n"
read input_email
if [ -z "$input_email" ]; then
    v_EMAIL="admin@"
else
    v_EMAIL="${input_email^}"
fi
}
#################################################
### source: Github User Pirasakat             ###
### https://gist.github.com/pirasakat/4076262 ###
#################################################
# reverse host name
function reverse_hostname () {
  local ret
  while [ $# -gt 0 ]; do
    ret="${1}.${ret}"
    shift
  done
  echo "${ret}" | sed 's/.$//'
}

rinput=${UFQDN}

# Execution
for line in $rinput; do
  oldifs="${IFS}"
  IFS="."
  # need to feed host name without dot delimiter.
  reversed=$(reverse_hostname ${line})
  IFS="${oldifs}"
  RUFQDN="${reversed}"
done
############################################
############################################

# Split Reversed FQDN and concatenate with DC for inclusion in Certificate Subjects
DCFQDN="DC=${RUFQDN//.//DC=}"

confirm_input () {
# Inform user of variables
echo "The following values will be used in the Cert creation process"
echo "Realm: '${REALM^^}'"
echo "Country: '${COUNTRY}'"
echo "State: '${STATE}'"
echo "Locality: '${LOCALITY}'"
echo "Email Address: '${v_EMAIL}'"
echo "Root Version: '${rootVer}'"
echo "Issuer Version: '${interVer}'"
echo "Scep Version: '${scepVer}'"
echo "RAToken Version: '${ratokenVer}'"
echo "Web Certificate Verson: '${webVer}'"
echo "Domain Component: '${DCFQDN}'"
echo -e "Fully Qualified Domain Name: '${FQDN}'\n"
echo "This script gives you the opportunity to define passwords for each certificate"
echo "or use a global password (less secure)."
echo "For production environments, it's recommended to have passwords for each certificate"
echo "and this script will automagically put them in the correct locations for you."
echo -e "If you want  1  password for all certificates, enter it now. Else, press Enter.\n"
read input_password
# For automated testing we want to have this set to root
# unset this to get random passwords (put into the .pass files)
}

make_password() {

    PASSWORD_FILE=$1;
    touch "${PASSWORD_FILE}"
    chown $user:root "${PASSWORD_FILE}"
    chmod 640 "${PASSWORD_FILE}"
    if [ -z "$KEY_PASSWORD" ]; then
        dd if=/dev/urandom bs=50 count=1 2>/dev/null | base64 >"${PASSWORD_FILE}"
    else
        echo -n "$KEY_PASSWORD" > "${PASSWORD_FILE}"
    fi;

}

define_certificates() {
#
# CA and certificate settings
#
REQUEST_SUFFIX='csr'
KEY_SUFFIX='key'
PEM_SUFFIX='pem'
CERTIFICATE_SUFFIX='crt'
REVOCATION_SUFFIX='crl'
PASS_SUFFIX='pass'
BACKUP_SUFFIX='~'

echo -e "The following will be the configuration for your certificates.\n"
# root CA selfsigned (in production use company's root certificate)
ROOT_CA="${REALM^^}_Root_CA_${rootVer}"
ROOT_CA_REQUEST="${SSL_REALM}/${ROOT_CA}.${REQUEST_SUFFIX}"
ROOT_CA_KEY="${SSL_REALM}/${ROOT_CA}.${KEY_SUFFIX}"
ROOT_CA_PEM="${SSL_REALM}/${ROOT_CA}.${PEM_SUFFIX}"
ROOT_CA_KEY_PASSWORD="${SSL_REALM}/${ROOT_CA}.${PASS_SUFFIX}"
ROOT_CA_CERTIFICATE="${SSL_REALM}/${ROOT_CA}.${CERTIFICATE_SUFFIX}"
#ROOT_CA_choiceRoot="${SSL_REALM}/${choiceRoot}"
ROOT_CA_SUBJECT="/emailAddress=${v_EMAIL}/C=${COUNTRY^^}/ST=${STATE^^}/L=${LOCALITY^^}/O=${REALM^^}/OU=${OrgU^^}/${DCFQDN}/CN=${REALM^^} Root CA ${rootVer}"
ROOT_CA_SERVER_FQDN="${FQDN}"
  # Show user the expected output.
  if [ $import_xpki_Root == "1" ]; then
  echo "${ROOT_CA_SUBJECT}"
  fi

# Intermediate (issuing) CA signed by root CA above
ISSUING_CA="${REALM^^}_Intermediate_CA_${interVer}"
ISSUING_CA_REQUEST="${SSL_REALM}/${ISSUING_CA}.${REQUEST_SUFFIX}"
ISSUING_CA_KEY="${SSL_REALM}/${ISSUING_CA}.${KEY_SUFFIX}"
ISSUING_CA_PEM="${SSL_REALM}/${ISSUING_CA}.${PEM_SUFFIX}"
ISSUING_CA_KEY_PASSWORD="${SSL_REALM}/${ISSUING_CA}.${PASS_SUFFIX}"
ISSUING_CA_CERTIFICATE="${SSL_REALM}/${ISSUING_CA}.${CERTIFICATE_SUFFIX}"
ISSUING_CA_SUBJECT="/emailAddress=${v_EMAIL}/C=${COUNTRY^^}/ST=${STATE^^}/L=${LOCALITY^^}/O=${REALM^^}/OU=${OrgU^^}/${DCFQDN}/CN=${REALM^^} Intermediate CA ${interVer}"
  # Show user the expected output.
  if [ $import_xpki_Inter == "1" ]; then
  echo "${ISSUING_CA_SUBJECT}"
  fi

# SCEP registration authority certificate signed by root CA above
SCEP="${REALM^^}_SCEP_RA_${scepVer}"
SCEP_REQUEST="${SSL_REALM}/${SCEP}.${REQUEST_SUFFIX}"
SCEP_KEY="${SSL_REALM}/${SCEP}.${KEY_SUFFIX}"
SCEP_PEM="${SSL_REALM}/${SCEP}.${PEM_SUFFIX}"
SCEP_KEY_PASSWORD="${SSL_REALM}/${SCEP}.${PASS_SUFFIX}"
SCEP_CERTIFICATE="${SSL_REALM}/${SCEP}.${CERTIFICATE_SUFFIX}"
SCEP_SUBJECT="/emailAddress=${v_EMAIL}/C=${COUNTRY^^}/ST=${STATE^^}/L=${LOCALITY^^}/O=${REALM^^}/OU=${OrgU^^}/${DCFQDN}/CN=${FQDN}:${REALM,,}-SCEP-RA-${scepVer}"
  # Show user the expected output.
  if [ $import_xpki_Scep == "1" ]; then
  echo "${SCEP_SUBJECT}"
  fi

# Registration Authority certificate signed by root CA above
RATOKEN="${REALM^^}_RATOKEN_RA_${ratokenVer}"
RATOKEN_REQUEST="${SSL_REALM}/${RATOKEN}.${REQUEST_SUFFIX}"
RATOKEN_KEY="${SSL_REALM}/${RATOKEN}.${KEY_SUFFIX}"
RATOKEN_PEM="${SSL_REALM}/${RATOKEN}.${PEM_SUFFIX}"
RATOKEN_KEY_PASSWORD="${SSL_REALM}/${RATOKEN}.${PASS_SUFFIX}"
RATOKEN_CERTIFICATE="${SSL_REALM}/${RATOKEN}.${CERTIFICATE_SUFFIX}"
RATOKEN_SUBJECT="/emailAddress=${v_EMAIL}/C=${COUNTRY^^}/ST=${STATE^^}/L=${LOCALITY^^}/O=${REALM^^}/OU=${OrgU^^}/${DCFQDN}/CN=${FQDN}:${REALM,,}-RATOKEN-RA-${ratokenVer}"
  # Show user the expected output.
  if [ $import_xpki_Ratoken == "1" ]; then
  echo "${RATOKEN_SUBJECT}"
  fi

# Apache WEB certificate signed by root CA above
WEB="${REALM^^}_WebUI_${webVer}"
WEB_REQUEST="${SSL_REALM}/${WEB}.${REQUEST_SUFFIX}"
WEB_KEY="${SSL_REALM}/${WEB}.${KEY_SUFFIX}"
WEB_PEM="${SSL_REALM}/${WEB}.${PEM_SUFFIX}"
WEB_KEY_PASSWORD="${SSL_REALM}/${WEB}.${PASS_SUFFIX}"
WEB_CERTIFICATE="${SSL_REALM}/${WEB}.${CERTIFICATE_SUFFIX}"
WEB_SUBJECT="/emailAddress=${v_EMAIL}/C=${COUNTRY^^}/ST=${STATE^^}/L=${LOCALITY^^}/O=${REALM^^}/OU=${OrgU^^}/${DCFQDN}/CN=${FQDN}"
WEB_SERVER_FQDN="`hostname -f`"
WEB_SERVER_FQDN="`hostname -f`"
  # Show user the expected output.
  if [ $import_xpki_Web == "1" ]; then
  echo "${WEB_SUBJECT}"
  fi

# data vault certificate selfsigned
DATAVAULT="${REALM^^}_DataVault"
DATAVAULT_REQUEST="${SSL_REALM}/${DATAVAULT}.${REQUEST_SUFFIX}"
DATAVAULT_KEY="${SSL_REALM}/${DATAVAULT}.${KEY_SUFFIX}"
DATAVAULT_PEM="${SSL_REALM}/${DATAVAULT}.${PEM_SUFFIX}"
DATAVAULT_KEY_PASSWORD="${SSL_REALM}/${DATAVAULT}.${PASS_SUFFIX}"
DATAVAULT_CERTIFICATE="${SSL_REALM}/${DATAVAULT}.${CERTIFICATE_SUFFIX}"
DATAVAULT_SUBJECT="/emailAddress=${v_EMAIL}/C=${COUNTRY^^}/ST=${STATE^^}/L=${LOCALITY^^}/O=${REALM^^}/OU=${OrgU^^}/${DCFQDN}/CN=${REALM^^} Internal DataVault"
  # Show user the expected output.
  if [ $import_xpki_DV == "1" ]; then
  echo "${DATAVAULT_SUBJECT}"
  fi
DomainName=`hostname -d`
# Define Root and Intermediate authorityInfoAccess and crlDistributionPoints
ROOT_CA_CERTIFICATE_URI="URI"':''http://'"${FQDN}"'/download/'"${ROOT_CA}"'.cer'
ROOT_CA_REVOCATION_URI="URI"':''http://'"${FQDN}"'/download/'"${ROOT_CA}"'.crl'
ROOT_CA_OCSP_URI="URI"':''http://'ocsp."${DomainName}"''
ISSUING_CERTIFICATE_URI="URI"':''http://'"${FQDN}"'/download/'"${ISSUING_CA}"'.cer'
ISSUING_REVOCATION_URI="URI"':''http://'"${FQDN}"'/download/'"${ISSUING_CA}"'.crl'
}

confirm_run () {
# Prompt for confirmation
echo -e "\nYour FQDN for this Server is: ${FQDN}  This will be used during the script."
echo -e "Change your FQDN before executing this script if you want something else."
echo -e "\nThe above lines are how your Certificates will be configured. "
echo -e "If you're happy with this configuration, Enter Y or y, else Enter N.\n"
read input_confirmGo
  if [ "${input_confirmGo,,}" != "y" ]; then
      echo -e "\nYou've chosen to end the script."
      exit 1
  fi
}

populate_files () {
echo "Continuing with configuration!"
echo "Checking if Realm Config Directory exists."

# Make a new realm folder
KEY_PASSWORD="${input_password}"
SSL_REALM="${BASE_DIR}/ca/${REALM}"
REALM_CONF="${BASE_DIR}/config.d/system/realms.yaml"
if [ ! -d "${BASE_DIR}/config.d/realm/${REALM}" ]; then
  echo "Making Configuration Directory"
  mkdir ${BASE_DIR}/config.d/realm/${REALM}

  # Copy realm.tpl contents to new Realm folder
  echo "Copying Files from the Realm.Tpl directory."
  cp -R ${BASE_DIR}/config.d/realm.tpl/* ${BASE_DIR}/config.d/realm/${REALM}
fi
    # If Realm does not exist, we'll add it to the Realm Yaml.
    # This avoids re-adding it after everytime the script runs.
    # Add new realm to the Realms config.
if grep -Fq "$REALM" ${REALM_CONF}; then
  echo "It appears your Realm is alreddy in configured in:"
  echo "${BASE_DIR}/config.d/system/realms.yaml"
else
echo "
${REALM}:
   label: ${REALM} CA
   baseurl: https://`hostname -f`/${REALM}/
" >> "${REALM_CONF}"
fi
}

define_openssl () {
#
# openssl.conf
#
##Dev
BITS="8192"
DVBITS="16384"
RABITS="4096"
SCEPBITS="4096"
##Prod
#BITS="8192"
#DVBITS="16384" # Customizing Datavault bits for experimenting
DAYS="397" # 397 days, Setting to 397 since apple said they wouldn't support over 398 days
RDAYS="9875" # 25 years for root
IDAYS="7300" # 20 years for issuing
SDAYS="365" # 1 years for scep
WDAYS="397" # 3 years web
DDAYS="$RDAYS" # 20 years datavault (same a root)
SDATE="$input_SDATE" # Need the correct format # incorporate with if statements
EDATE="$input_EDATE" # Need the correct format # incorporate with if statements

openssl rand -writerand .rnd
# creation neccessary directories and files
echo -n "Creating configuration for openssl ($OPENSSL_CONF) .. "
test -d "${SSL_REALM}" || mkdir -m 755 -p "${SSL_REALM}" && chown ${user}:root "${SSL_REALM}"
OPENSSL_DIR="${SSL_REALM}/.openssl"
test -d "${OPENSSL_DIR}" || mkdir -m 700 "${OPENSSL_DIR}" && chown root:root "${OPENSSL_DIR}"
cd "${OPENSSL_DIR}";

OPENSSL_CONF="${OPENSSL_DIR}/openssl.cnf"

touch "${OPENSSL_DIR}/index.txt"
touch "${OPENSSL_DIR}/index.txt.attr"
touch "${OPENSSL_DIR}/serial"
echo $(date +%Y%m%d%H%M)"0001" > "${OPENSSL_DIR}/crlnumber"
echo $(date +%Y%m%d%H%M)"0001" >> "${OPENSSL_DIR}/serial"

echo "
HOME                    = .
RANDFILE                = \$ENV::HOME/.rnd

[ ca ]
default_ca              = CA_default

[ req ]
default_bits            = ${BITS}
distinguished_name      = req_distinguished_name

[ CA_default ]
dir                     = ${OPENSSL_DIR}
certs                   = ${OPENSSL_DIR}/certs
crldir                  = ${OPENSSL_DIR}/
database                = ${OPENSSL_DIR}/index.txt
new_certs_dir           = ${OPENSSL_DIR}/
serial                  = ${OPENSSL_DIR}/serial
crlnumber               = ${OPENSSL_DIR}/crlnumber
crl                     = ${OPENSSL_DIR}/crl.pem
private_key             = ${OPENSSL_DIR}/cakey.pem
RANDFILE                = ${OPENSSL_DIR}/.rand
default_md              = sha512
preserve                = no
policy                  = policy_match
default_days            = ${DAYS}
email_in_dn             = no
countryName_default     = "${COUNTRY}"
stateOrProvinceName_default     = "${STATE}"
0.organizationName_default      = "${REALM}"
0.organizationUnitName_default  = "${OrgU}"

[ policy_match ]
countryName             = match
stateOrProvinceName     = supplied
localityName            = supplied
organizationName        = optional
organizationalUnitName	= supplied
commonName              = supplied
emailAddress	       	= supplied

[ req_distinguished_name ]
countryName             = Country Name (2 letter code)
countryName_default     = "${COUNTRY}"

stateOrProvinceName     = State or Province Name (full name)
stateOrProvinceName_default	= "${STATE}"

localityName            = Locality Name (eg, city)
0.localityName_default  = "${LOCALITY}"

0.organizationName      = Organization Name (eg, company)
0.organizationName_default   = "${REALM}"

0.organizationUnitName  = Organization Unit Name (eg, section)
0.organizationUnitName_default  = "${OrgU}"

commonName              = Common Name (eg, YOUR name)
commonName_max          = 64

emailAddress            = Email Address
emailAddress_max        = 64

[ v3_ca_reqexts ]
subjectKeyIdentifier    = hash
keyUsage                = digitalSignature, keyCertSign, cRLSign

[ v3_datavault_reqexts ]
subjectKeyIdentifier    = hash
keyUsage                = keyEncipherment
extendedKeyUsage        = emailProtection

[ v3_scep_reqexts ]
subjectKeyIdentifier    = hash

[ v3_web_reqexts ]
subjectKeyIdentifier    = hash
keyUsage                = critical, digitalSignature, keyEncipherment
extendedKeyUsage        = serverAuth, clientAuth

[ v3_ca_extensions ]
subjectKeyIdentifier    = hash
keyUsage                = digitalSignature, keyCertSign, cRLSign
basicConstraints        = critical,CA:TRUE
authorityKeyIdentifier  = keyid:always,issuer

[ v3_issuing_extensions ]
subjectKeyIdentifier    = hash
keyUsage                = digitalSignature, keyCertSign, cRLSign
basicConstraints        = critical,CA:TRUE
authorityKeyIdentifier  = keyid:always,issuer:always
crlDistributionPoints	= "${ROOT_CA_REVOCATION_URI}"
authorityInfoAccess     = caIssuers;"${ROOT_CA_CERTIFICATE_URI}"
authorityInfoAccess     = OCSP;"${ROOT_CA_OCSP_URI}"

[ v3_datavault_extensions ]
subjectKeyIdentifier    = hash
keyUsage                = keyEncipherment
extendedKeyUsage        = emailProtection
basicConstraints        = CA:FALSE
authorityKeyIdentifier  = keyid:always,issuer

[ v3_scep_extensions ]
subjectKeyIdentifier    = hash
basicConstraints        = CA:FALSE
authorityKeyIdentifier  = keyid,issuer

[ v3_ratoken_extensions ]
subjectKeyIdentifier    = hash
basicConstraints        = CA:FALSE
keyUsage                = critical, digitalSignature, keyEncipherment
extendedKeyUsage        = cmcRA, serverAuth

[ v3_web_extensions ]
subjectKeyIdentifier    = hash
keyUsage                = critical, digitalSignature, keyEncipherment
extendedKeyUsage        = serverAuth, clientAuth
basicConstraints        = critical,CA:FALSE
subjectAltName          = DNS:"${FQDN}"
crlDistributionPoints   = "${ISSUING_REVOCATION_URI}"
authorityInfoAccess	    = caIssuers;"${ISSUING_CERTIFICATE_URI}"
authorityInfoAccess     = OCSP;"${ROOT_CA_OCSP_URI}"
" > "${OPENSSL_CONF}"

echo "Done."
echo "Looking for keys directory for the encrypted, private keys: ${BASE_DIR}/local/keys/"
if [ ! -d "${BASE_DIR}/config.d/realm/${REALM}" ]
then
    echo "Making "${REALM}" Configuration Directory"
    mkdir ${BASE_DIR}/config.d/realm/${REALM}
    # Copy democa contents to new Realm folder
    echo "Copying Files from the DEMOCA directory."
    cp -R ${BASE_DIR}/config.d/realm.tpl/* ${BASE_DIR}/config.d/realm/${REALM}
fi
if [ ! -d "${BASE_DIR}/local/keys/${REALM}" ]
then
    echo -e "\nMaking Local Keys REALM directory\n"
    mkdir -p ${BASE_DIR}/local/keys/${REALM}/
fi
}
# Certificate generation functions
gen_RootCA() {
if [ ! -e "${ROOT_CA_CERTIFICATE}" ]
then
   echo "Did not find a "${REALM}" Root CA "${rootVer}" certificate file."
   echo -n "Creating a self-signed "${REALM}" Root CA "${rootVer}" .. "
   test -f "${ROOT_CA_KEY}" && \
    mv "${ROOT_CA_KEY}" "${ROOT_CA_KEY}${BACKUP_SUFFIX}"
   test -f "${ROOT_CA_KEY_PASSWORD}" && \
    mv "${ROOT_CA_KEY_PASSWORD}" "${ROOT_CA_KEY_PASSWORD}${BACKUP_SUFFIX}"
   make_password "${ROOT_CA_KEY_PASSWORD}"
   openssl req -verbose -config "${OPENSSL_CONF}" -extensions v3_ca_extensions -batch -x509 -sha512 -newkey rsa:$BITS -days ${RDAYS} -passout file:"${ROOT_CA_KEY_PASSWORD}" -keyout "${ROOT_CA_KEY}" -subj "${ROOT_CA_SUBJECT}" -out "${ROOT_CA_CERTIFICATE}"
   echo "Putting the certificate commands into certificateCommands.txt"
   echo "Putting the certificate commands into certificateCommands.txt" >> ${BASE_DIR}/ca/"${REALM}"/certificateCommands.txt
   echo "openssl req -verbose -config "${OPENSSL_CONF}" -extensions v3_ca_extensions -batch -x509 -sha512 -newkey rsa:$BITS -days ${RDAYS} -passout file:"${ROOT_CA_KEY_PASSWORD}" -keyout "${ROOT_CA_KEY}" -subj "${ROOT_CA_SUBJECT}" -out "${ROOT_CA_CERTIFICATE}"" >> ${BASE_DIR}/ca/"${REALM}"/certificateCommands.txt
   echo "Done."
fi;
}

gen_InterCA() {
# Intermediate certificate (issuing)
if [ ! -e "${ISSUING_CA_KEY}" ]
then
   echo "Did not find existing Intermediate (Issuing) CA key file."
   echo -n "Creating a "${REALM^}" Intermediate CA request .. "
   test -f "${ISSUING_CA_REQUEST}" && mv "${ISSUING_CA_REQUEST}" "${ISSUING_CA_REQUEST}${BACKUP_SUFFIX}"
   make_password "${ISSUING_CA_KEY_PASSWORD}"
   openssl req -verbose -config "${OPENSSL_CONF}" -subj "/CN='${ISSUING_CA_CERTIFICATE}'" -reqexts v3_ca_reqexts -batch -newkey rsa:$BITS -passout file:"${ISSUING_CA_KEY_PASSWORD}" -keyout "${ISSUING_CA_KEY}" -subj "${ISSUING_CA_SUBJECT}" -out "${ISSUING_CA_REQUEST}"
   echo -e "\nIntermediate CSR" >> ${BASE_DIR}/ca/"${REALM}"/certificateCommands.txt
   echo "openssl req -verbose -config "${OPENSSL_CONF}" -subj "/CN=${ISSUING_CA_CERTIFICATE}" -reqexts v3_ca_reqexts -batch -newkey rsa:$BITS -passout file:"${ISSUING_CA_KEY_PASSWORD}" -keyout "${ISSUING_CA_KEY}" -subj "${ISSUING_CA_SUBJECT}" -out "${ISSUING_CA_REQUEST}"" >> ${BASE_DIR}/ca/"${REALM}"/certificateCommands.txt
   echo "done."
   echo "Generated Inter CSR"
   directory="${BASE_DIR}/ca/"${REALM}"/"
   if ls ${BASE_DIR}/ca/${REALM}/*[Rr][Oo][Oo][Tt]*.crt &> /dev/null
   then
      # Begin Selection Process
      PS3="Select the Root Certificate you wish to sign with: "
      	select choiceRoot in `ls $directory | grep -i Root | egrep -i 'crt'`
      	do
      	echo "Selected certificate: $choiceRoot"
      	break
      	done
      echo -n "Signing "${REALM^}" Intermediate Certificate with "${choiceRoot}" .. "
      test -f "${ISSUING_CA_CERTIFICATE}" && \
	mv "${ISSUING_CA_CERTIFICATE}" "${ISSUING_CA_CERTIFICATE}${BACKUP_SUFFIX}"
	echo -e "\nSigning Intermediate with Root." >> ${BASE_DIR}/ca/"${REALM}"/certificateCommands.txt
	ROOT_CA_KEY="${SSL_REALM}/`basename "${SSL_REALM}/${choiceRoot}" "."${CERTIFICATE_SUFFIX}`"."${KEY_SUFFIX}"
	ROOT_CA_KEY_PASSWORD="${SSL_REALM}/`basename "${SSL_REALM}/${choiceRoot}" "."${CERTIFICATE_SUFFIX}`"."${PASS_SUFFIX}"
	ROOT_CA_CERTIFICATE="${SSL_REALM}/${choiceRoot}"
	echo "ROOT_CA_CERTIFICATE="${SSL_REALM}/${choiceRoot}""
	echo "openssl ca -create_serial -config "${OPENSSL_CONF}" -extensions v3_issuing_extensions -batch -days ${IDAYS} -in "${ISSUING_CA_REQUEST}" -cert "${ROOT_CA_CERTIFICATE}" -passin file:"${ROOT_CA_KEY_PASSWORD}" -keyfile "${ROOT_CA_KEY}" -out "${ISSUING_CA_CERTIFICATE}"" >> ${BASE_DIR}/ca/"${REALM}"/certificateCommands.txt
        openssl ca -create_serial -config "${OPENSSL_CONF}" -extensions v3_issuing_extensions -batch -days ${IDAYS} -in "${ISSUING_CA_REQUEST}" -cert "${ROOT_CA_CERTIFICATE}" -passin file:"${ROOT_CA_KEY_PASSWORD}" -keyfile "${ROOT_CA_KEY}" -out "${ISSUING_CA_CERTIFICATE}"
        echo "Done."
   else
      echo "No '${ROOT_CA_KEY}' key file!"
      echo "Please sign generated request with the company's Root CA key."
      exit 0
   fi
else
   if [ ! -e "${ISSUING_CA_CERTIFICATE}" ]
   then
      echo "No '${ISSUING_CA_CERTIFICATE}' certificate file!"
      if [ ! -e "${ROOT_CA_KEY}" ]
      then
         echo "No '${ROOT_CA_KEY}' key file!"
         echo "Please sign generated request with your company's Root CA key"
         exit 0
      else
         echo -n "Signing issuing certificate with own root CA .. " >> ${BASE_DIR}/ca/"${REALM}"/certificateCommands.txt
	 echo -n "openssl ca -create_serial -config "${OPENSSL_CONF}" -extensions v3_issuing_extensions -batch -days ${IDAYS} -in "${ISSUING_CA_REQUEST}" -cert "${ROOT_CA_CERTIFICATE}" -passin file:"${ROOT_CA_KEY_PASSWORD}" -keyfile "${ROOT_CA_KEY}" -out "${ISSUING_CA_CERTIFICATE}"" >> ${BASE_DIR}/ca/"${REALM}"/certificateCommands.txt
         openssl ca -create_serial -config "${OPENSSL_CONF}" -extensions v3_issuing_extensions -batch -days ${IDAYS} -in "${ISSUING_CA_REQUEST}" -cert "${ROOT_CA_CERTIFICATE}" -passin file:"${ROOT_CA_KEY_PASSWORD}" -keyfile "${ROOT_CA_KEY}" -out "${ISSUING_CA_CERTIFICATE}"
         # Add CRL generation for Intermediate cert right here. Verify the sequence, but also cp the CRL to /var/www/download directory, change perms and grant 755. 
	 # Be sure to echo the output to cert commands file.
         echo "done."
      fi
   fi
fi;
}

gen_RatokenCert() {
# ratoken certificate
if [ ! -e "${RATOKEN_KEY}" ]
then
   echo "Did not find existing "${REALM}" RATOKEN "${ratokenVer}" certificate file."
   echo -n "Creating a "${REALM}" RATOKEN "${ratokenVer}" request .. "
   test -f "${RATOKEN_REQUEST}" && mv "${RATOKEN_REQUEST}" "${RATOKEN_REQUEST}${BACKUP_SUFFIX}"
   make_password "${RATOKEN_KEY_PASSWORD}"
   echo -e "\nRATOKEN Request" >> ${BASE_DIR}/ca/"${REALM}"/certificateCommands.txt
   echo -e "openssl req -verbose -config "${OPENSSL_CONF}" -reqexts v3_ratoken_extensions -batch -newkey rsa:$BITS -passout file:"${RATOKEN_KEY_PASSWORD}" -keyout "${RATOKEN_KEY}" -subj "${RATOKEN_SUBJECT}" -out "${RATOKEN_REQUEST}"" >> ${BASE_DIR}/ca/"${REALM}"/certificateCommands.txt
   openssl req -verbose -config "${OPENSSL_CONF}" -reqexts v3_ratoken_extensions -batch -newkey rsa:$RABITS -passout file:"${RATOKEN_KEY_PASSWORD}" -keyout "${RATOKEN_KEY}" -subj "${RATOKEN_SUBJECT}" -out "${RATOKEN_REQUEST}"
   echo "done."
	directory="${BASE_DIR}/ca/"${REALM}"/"
	if ls ${BASE_DIR}/ca/${REALM}/*[Ii][Nn][Tt][Ee][Rr]*.crt &> /dev/null
   	then
      	# Begin Selection Process
      	PS3="Select the Intermediate (Issuing) Certificate you wish to sign with: "
       	 select choiceInter in `ls $directory | grep -i [Ii][Nn][Tt][Ee][Rr][Mm]* | egrep -i 'crt'`
       	 do
       	 echo "Selected certificate: $choiceInter"
       	 break
       	 done #4321
      	echo -n "Signing "${REALM}" Ratoken Certificate with "${choiceInter}" .. "
	## UFTO
        ISSUING_CA_KEY="${SSL_REALM}/`basename "${SSL_REALM}/${choiceInter}" "."${CERTIFICATE_SUFFIX}`"."${KEY_SUFFIX}"
        ISSUING_CA_KEY_PASSWORD="${SSL_REALM}/`basename "${SSL_REALM}/${choiceInter}" "."${CERTIFICATE_SUFFIX}`"."${PASS_SUFFIX}"
        ISSUING_CA_CERTIFICATE="${SSL_REALM}/${choiceInter}"
        echo -e "\nSigning Ratoken with Intermediate" >> ${BASE_DIR}/ca/"${REALM}"/certificateCommands.txt
	echo "openssl ca -create_serial -config "${OPENSSL_CONF}" -extensions v3_ratoken_extensions -batch -days ${SDAYS} -in "${RATOKEN_REQUEST}" -cert "${ISSUING_CA_CERTIFICATE}" -passin file:"${ISSUING_CA_KEY_PASSWORD}" -keyfile "${ISSUING_CA_KEY}" -out "${RATOKEN_CERTIFICATE}"" >> ${BASE_DIR}/ca/"${REALM}"/certificateCommands.txt
	openssl ca -create_serial -config "${OPENSSL_CONF}" -extensions v3_ratoken_extensions -batch -days ${SDAYS} -in "${RATOKEN_REQUEST}" -cert "${ISSUING_CA_CERTIFICATE}" -passin file:"${ISSUING_CA_KEY_PASSWORD}" -keyfile "${ISSUING_CA_KEY}" -out "${RATOKEN_CERTIFICATE}"
	echo "done."
	fi
fi;
}

gen_ScepCert() {
# scep certificate
if [ ! -e "${SCEP_KEY}" ]
then
   echo "Did not find existing "${REALM}" SCEP "${scepVer}" certificate file."
   echo -n "Creating a "${REALM}" SCEP "${scepVer}" request .. "
   test -f "${SCEP_REQUEST}" && mv "${SCEP_REQUEST}" "${SCEP_REQUEST}${BACKUP_SUFFIX}"
   make_password "${SCEP_KEY_PASSWORD}"
   echo -e "\nSCEP Request" >> ${BASE_DIR}/ca/"${REALM}"/certificateCommands.txt
   echo -e "openssl req -verbose -config "${OPENSSL_CONF}" -reqexts v3_scep_reqexts -batch -newkey rsa:$BITS -passout file:"${SCEP_KEY_PASSWORD}" -keyout "${SCEP_KEY}" -subj "${SCEP_SUBJECT}" -out "${SCEP_REQUEST}"" >> ${BASE_DIR}/ca/"${REALM}"/certificateCommands.txt
   openssl req -verbose -config "${OPENSSL_CONF}" -reqexts v3_scep_reqexts -batch -newkey rsa:$SCEPBITS -passout file:"${SCEP_KEY_PASSWORD}" -keyout "${SCEP_KEY}" -subj "${SCEP_SUBJECT}" -out "${SCEP_REQUEST}"
   echo "done."
	directory="${BASE_DIR}/ca/"${REALM}"/"
	if ls ${BASE_DIR}/ca/${REALM}/*[Ii][Nn][Tt][Ee][Rr]*.crt &> /dev/null
   	then
      	# Begin Selection Process
      	PS3="Select the Intermediate (Issuing) Certificate you wish to sign with: "
       	 select choiceInter in `ls $directory | grep -i [Ii][Nn][Tt][Ee][Rr][Mm]* | egrep -i 'crt'`
       	 do
       	 echo "Selected certificate: $choiceInter"
       	 break
       	 done #4321
      	echo -n "Signing "${REALM}" Scep Certificate with "${choiceInter}" .. "
	## UFTO
        ISSUING_CA_KEY="${SSL_REALM}/`basename "${SSL_REALM}/${choiceInter}" "."${CERTIFICATE_SUFFIX}`"."${KEY_SUFFIX}"
        ISSUING_CA_KEY_PASSWORD="${SSL_REALM}/`basename "${SSL_REALM}/${choiceInter}" "."${CERTIFICATE_SUFFIX}`"."${PASS_SUFFIX}"
        ISSUING_CA_CERTIFICATE="${SSL_REALM}/${choiceInter}"
        echo -e "\nSigning Scep with Intermediate" >> ${BASE_DIR}/ca/"${REALM}"/certificateCommands.txt
	echo "openssl ca -create_serial -config "${OPENSSL_CONF}" -extensions v3_scep_extensions -batch -days ${SDAYS} -in "${SCEP_REQUEST}" -cert "${ISSUING_CA_CERTIFICATE}" -passin file:"${ISSUING_CA_KEY_PASSWORD}" -keyfile "${ISSUING_CA_KEY}" -out "${SCEP_CERTIFICATE}"" >> ${BASE_DIR}/ca/"${REALM}"/certificateCommands.txt
	openssl ca -create_serial -config "${OPENSSL_CONF}" -extensions v3_scep_extensions -batch -days ${SDAYS} -in "${SCEP_REQUEST}" -cert "${ISSUING_CA_CERTIFICATE}" -passin file:"${ISSUING_CA_KEY_PASSWORD}" -keyfile "${ISSUING_CA_KEY}" -out "${SCEP_CERTIFICATE}"
	echo "done."
	fi
fi;
}

gen_DatavaultCert() {
# Data Vault is only used internally, use self signed
if [ ! -e "${DATAVAULT_KEY}" ]
then
   echo "Did not find existing DataVault certificate file."
   echo -n "Creating a self signed DataVault certificate .. "
   test -f "${DATAVAULT_CERTIFICATE}" && mv "${DATAVAULT_CERTIFICATE}" "${DATAVAULT_CERTIFICATE}${BACKUP_SUFFIX}"
   make_password "${DATAVAULT_KEY_PASSWORD}"
   echo -e "\nCreating self-signed Datavault Certificate" >> ${BASE_DIR}/ca/"${REALM}"/certificateCommands.txt
   echo "openssl req -verbose -config "${OPENSSL_CONF}" -extensions v3_datavault_extensions -batch -x509 -newkey rsa:$DVBITS -days ${DDAYS} -passout file:"${DATAVAULT_KEY_PASSWORD}" -keyout "${DATAVAULT_KEY}" -subj "${DATAVAULT_SUBJECT}" -out "${DATAVAULT_CERTIFICATE}"" >> ${BASE_DIR}/ca/"${REALM}"/certificateCommands.txt
   openssl req -verbose -config "${OPENSSL_CONF}" -extensions v3_datavault_extensions -batch -x509 -newkey rsa:$DVBITS -days ${DDAYS} -passout file:"${DATAVAULT_KEY_PASSWORD}" -keyout "${DATAVAULT_KEY}" -subj "${DATAVAULT_SUBJECT}" -out "${DATAVAULT_CERTIFICATE}"
   echo "done."
fi;
}

gen_WebCert() {
# web certificate
if [ ! -e "${WEB_KEY}" ]
then
   echo "Did not find existing "${REALM}" WEB certificate file."
   echo -n "Creating a Web request .. "
   test -f "${WEB_REQUEST}" && mv "${WEB_REQUEST}" "${WEB_REQUEST}${BACKUP_SUFFIX}"
   make_password "${WEB_KEY_PASSWORD}"
   echo -e "\nGenerating Web Certificate Request" >> ${BASE_DIR}/ca/"${REALM}"/certificateCommands.txt
   echo "openssl req -verbose -config "${OPENSSL_CONF}" -reqexts v3_web_reqexts -batch -newkey rsa:$BITS -passout file:"${WEB_KEY_PASSWORD}" -keyout "${WEB_KEY}" -subj "${WEB_SUBJECT}" -out "${WEB_REQUEST}"" >> ${BASE_DIR}/ca/"${REALM}"/certificateCommands.txt
   openssl req -verbose -config "${OPENSSL_CONF}" -reqexts v3_web_reqexts -batch -newkey rsa:$BITS -passout file:"${WEB_KEY_PASSWORD}" -keyout "${WEB_KEY}" -subj "${WEB_SUBJECT}" -out "${WEB_REQUEST}"
	directory="${BASE_DIR}/ca/"${REALM}"/"
        if ls ${BASE_DIR}/ca/${REALM}/*[Ii][Nn][Tt][Ee][Rr]*.crt &> /dev/null
        then
        # Begin Selection Process
        PS3="Select the Intermediate (Issuing) Certificate you wish to sign with: "
         select choiceInter in `ls $directory | grep -i [Ii][Nn][Tt][Ee][Rr][Mm]* | egrep -i 'crt'`
         do
         echo "Selected certificate: $choiceInter"
         break
         done #4321

        echo -n "Signing "${REALM}" Web Certificate with "${choiceInter}" .. "
   echo "Web request has been generated."
   ISSUING_CA_KEY="${SSL_REALM}/`basename "${SSL_REALM}/${choiceInter}" "."${CERTIFICATE_SUFFIX}`"."${KEY_SUFFIX}"
   ISSUING_CA_KEY_PASSWORD="${SSL_REALM}/`basename "${SSL_REALM}/${choiceInter}" "."${CERTIFICATE_SUFFIX}`"."${PASS_SUFFIX}"
   ISSUING_CA_CERTIFICATE="${SSL_REALM}/${choiceInter}"
   directory="${BASE_DIR}/ca/"${REALM}"/"
   if ls ${BASE_DIR}/ca/${REALM}/*[Rr][Oo][Oo][Tt]*.crt &> /dev/null
   then
      # Begin Selection Process
      PS3="Select the Root Certificate that signed ${choiceInter}: "
        select choiceRoot in `ls $directory | grep -i Root | egrep -i 'crt'`
        do
        echo "Selected certificate: $choiceRoot"
        break
        done
      echo -n "Signing "${REALM^}" Web Certificate with "${choiceRoot}" .. "
#      test -f "${ISSUING_CA_CERTIFICATE}" && \
#        mv "${ISSUING_CA_CERTIFICATE}" "${ISSUING_CA_CERTIFICATE}${BACKUP_SUFFIX}"
#       echo -e "\nSigning Intermediate with Root." >> ${BASE_DIR}/ca/"${REALM}"/certificateCommands.txt
        ROOT_CA_KEY="${SSL_REALM}/`basename "${SSL_REALM}/${choiceRoot}" "."${CERTIFICATE_SUFFIX}`"."${KEY_SUFFIX}"
        ROOT_CA_KEY_PASSWORD="${SSL_REALM}/`basename "${SSL_REALM}/${choiceRoot}" "."${CERTIFICATE_SUFFIX}`"."${PASS_SUFFIX}"
        ROOT_CA_CERTIFICATE="${SSL_REALM}/${choiceRoot}"
   fi
   echo -n "Signing "${REALM}" Web Certificate with Intermediate CA .. "
   echo -e "\nSigning Web Certificate Request with Intermediate." >> ${BASE_DIR}/ca/"${REALM}"/certificateCommands.txt
   echo -e "openssl ca -create_serial -config "${OPENSSL_CONF}" -extensions v3_web_extensions -batch -days ${WDAYS} -in "${WEB_REQUEST}" -cert "${ISSUING_CA_CERTIFICATE}" -passin file:"${ISSUING_CA_KEY_PASSWORD}" -keyfile "${ISSUING_CA_KEY}" -out "${WEB_CERTIFICATE}"" >> ${BASE_DIR}/ca/"${REALM}"/certificateCommands.txt
   openssl ca -create_serial -config "${OPENSSL_CONF}" -extensions v3_web_extensions -batch -days ${WDAYS} -in "${WEB_REQUEST}" -cert "${ISSUING_CA_CERTIFICATE}" -passin file:"${ISSUING_CA_KEY_PASSWORD}" -keyfile "${ISSUING_CA_KEY}" -out "${WEB_CERTIFICATE}"
   echo "Web Certificate has been signed."
   fi
fi;
}

###### Installer Function ######
function_OpenXinstaller () {
echo "Insalling GnuPG for package signature validation"
apt install argon2 gnupg* -y
echo "GnuPG installed."
echo "Done"
echo "Retrieving OpenXPKI package key and verifying."
# This seems to be broken on a hardened box
# wget https://packages.openxpki.org/v3/debian/Release.key -O - 2>/dev/null | tee Release.key | gpg2 -o /usr/share/keyrings/openxpki.pgp --dearmor
#wget -O- https://packages.openxpki.org/v3/debian/Release.key | gpg --dearmor | tee /usr/share/keyrings/openxpki.pgp > /dev/null 2>&1 
#wget https://packages.openxpki.org/v3/debian/Release.key -O - | apt-key add -
apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 8F7B8EC1D616E831
#
echo "Adding OpenXPKI to sources."
#echo -e "Types: deb\nURIs: https://packages.openxpki.org/v3/bookworm/\nSuites: bookworm\nComponents: release\nSigned-By: /usr/share/keyrings/openxpki.pgp" > /etc/apt/sources.list.d/openxpki.sources
echo -e "Types: deb\nURIs: https://packages.openxpki.org/v3/bookworm/\nSuites: bookworm\nComponents: release\n" > /etc/apt/sources.list.d/openxpki.sources
apt update -y
PS3="Do you want to install MySQL, MariaDB or use an External Database?   "
input_db_external=0
input_db_external_auto=0
select db in MariaDB External_MariaDB_Manual External_MariaDB_Automatic Exit; do

    case $db in
      MariaDB)
        apt install mariadb-server libdbd-mariadb-perl libdbd-mysql-perl -y
        echo "Selected MariaDB as your DB Server."
		input_db_external=0
		db_type="MariaDB2"
        break
        ;;
	  External_MariaDB_Manual)
	    apt install mariadb-client libdbd-mariadb-perl libdbd-mysql-perl -y
	    echo "Configure your external DB with the following parameters."
	    echo ""
		input_db_external=1
		input_db_external_auto=0
		db_type="MariaDB2"
	    break
	    ;;
      External_MariaDB_Automatic)
	    apt install mariadb-client libdbd-mariadb-perl libdbd-mysql-perl -y
	    echo "Configure your external DB with the following parameters."
	    echo ""
		input_db_external=1
		input_db_external_auto=1
		db_type="MariaDB2"
	    break
	    ;;
      Exit)
        echo "You've chose to end the installer."
        exit 1
        ;;
      *)
        echo "Invalid Selection."
    esac
done
echo -e "\nInstalling and enablig Apache mods"
apt install apache2 libapache2-mod-fcgid -y
a2enmod fcgid

##Install OpenXPKI dependencies
echo "Beginning OpenXPKI installation."
apt install libopenxpki-perl openxpki-cgi-session-driver openxpki-i18n -y

# Run the server out of /opt to prep for rhel environment
mkdir -p /opt/openxpki
cp -r /etc/openxpki/* /opt/openxpki
chown -R openxpki:openxpki /opt/openxpki

echo "Showing installed OpenXPKI version."
openxpkiadm version --config "${CONF_DIR}"
sleep 3

echo ""
echo "The details will be placed into the file:  ${BASE_DIR}/config.d/system/database.yaml"
echo ""

if [ $input_db_external == "0" ]; then
  echo "Please enter your root password."
  read -s input_rootpw_1
  echo "Please verify your root password."
  read -s input_rootpw_2
  while [ $input_rootpw_1 != $input_rootpw_2 ]
  do
    echo "Please enter your root password."
    read -s input_rootpw_1
    echo "Please verify your root password. If they don't match, you'll enter them again."
    read -s input_rootpw_2
  done
ROOT_PW="${input_rootpw_2}"
  while [ "${confirm_db}" != "y" ]
  do
input_db_name="openxpki"
input_db_user="openxpki"
#    echo -e "What's the password for the database?\n"
#    read input_db_pass
input_db_pass=`openssl rand 50 | base64`
    echo -e "Your database will be configured with the following settings:\n"
    echo "Database name: ""${input_db_name}"
    echo "Database user: ""${input_db_user}"
    echo "Database pass: ""Viewable in the database.yaml file."
    echo -e "Do you accept these settings? Y | y\n"
    read confirm_db
    if [ "${confirm_db,,}" != "y" ]; then
      echo "Please re-enter your settings"
      else
      echo "Settings will be applied."
    fi
done

# Define DB Directory
DATABASE_DIR="${BASE_DIR}/config.d/system/database.yaml"

# Harden initial mariadb installation
echo "Beginning MariaDB Secure installation..."
mariadb -u root -p"${ROOT_PW}" -e "SET PASSWORD FOR root@localhost = PASSWORD('"${ROOT_PW}"');FLUSH PRIVILEGES;"
echo "Removing Anonymous user."
mariadb -u root -p"${ROOT_PW}" -e "DELETE FROM mysql.user WHERE User='';"
mariadb -u root -p"${ROOT_PW}" -e "DROP USER IF EXISTS ''@'localhost'"
mariadb -u root -p"${ROOT_PW}" -e "DROP USER IF EXISTS ''@'$(hostname)'"
echo "Dropped anonymous user."
mariadb -u root -p"${ROOT_PW}" -e "DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1');"
echo "Disable remote Root Authentication."
mariadb -u root -p"${ROOT_PW}" -e "DROP DATABASE IF EXISTS test"
echo "Dropping test DB"
mariadb -u root -p"${ROOT_PW}" -e "FLUSH PRIVILEGES;"

# Create initial pki database
echo -e "Initializing Database...\n"
mariadb -u root -p"${ROOT_PW}" -e "CREATE DATABASE IF NOT EXISTS "${input_db_name}" CHARSET utf8;"
echo "Database: ""${input_db_name}"  "created."
mariadb -u root -p"${ROOT_PW}" -e "CREATE USER IF NOT EXISTS '"${input_db_user}"'@'localhost' IDENTIFIED BY '"${input_db_pass}"';"
echo "User: ""${input_db_user}"  "created."
echo "Granting permissions on ""${input_db_name}" "to: ""${input_db_user}"
mariadb -u root -p"${ROOT_PW}" -e "GRANT ALL PRIVILEGES ON "${input_db_name}".* TO '"${input_db_user}"'@'localhost';"

#Create database schema
echo "Copying database template to Server."
cat /usr/share/doc/libopenxpki-perl/examples/schema-mariadb.sql | mariadb -u root -p"${ROOT_PW}" --database  "${input_db_name}"

#Store credentials in /etc/openxpki/config.d/system/database.yaml
sed -i "s^name:.*^name: ${input_db_name}^g" ${DATABASE_DIR}
sed -i "s^user:.*^user: ${input_db_user}^g" ${DATABASE_DIR}
sed -i "s^passwd:.*^passwd: ${input_db_pass}^g" ${DATABASE_DIR}
sed -i "s^type:.*^type: ${db_type}^g" ${DATABASE_DIR}

#Create cgi session credentials
cgi_session_db_user="openxpki_cgiSession_user"
cgi_session_db_pass=`openssl rand 50 | base64`

#Create cgi session credentials for DB
echo ""
echo "Making additional db login user for the webui CGI session"
echo "This is a limited user that interacts with the cgiSession and helps prevent"
echo "Your admin database credentials potentially being exposed."
echo ""
echo "CREATE USER ${cgi_session_db_user}"
mariadb -u root -p"${ROOT_PW}" -e "CREATE USER IF NOT EXISTS "${cgi_session_db_user}"@'localhost' IDENTIFIED BY '"${cgi_session_db_pass}"';"

# Grant privileges to cgi user for frontend
echo "Granting SELECT, INSERT, UPDATE, DELETE ON on ""${input_db_name}".frontend_session "to: ""${cgi_session_db_user}"
mariadb -u root -p"${ROOT_PW}" -e "GRANT SELECT, INSERT, UPDATE, DELETE ON "${input_db_name}".frontend_session TO "${cgi_session_db_user}"@'localhost';"
mariadb -u root -p"${ROOT_PW}" -e "FLUSH PRIVILEGES;"

fi

if [ $input_db_external == "1" ] && [ $input_db_external_auto == "0" ]; then
    
	debug=
    debug=echo
	
	#Create credentials for external DB and show the user what to configure.
    DATABASE_DIR="${BASE_DIR}/config.d/system/database.yaml"
	echo ""
	echo "Are you connecting to a Galera Cluster? Yes or No"
	read input_db_galera_yn
	if [ ${input_db_galera_yn,,} == "yes" ]
	then
		sed -i 's|START WITH 0 INCREMENT BY 1|START WITH 0 INCREMENT BY 0|g' /usr/share/doc/libopenxpki-perl/examples/schema-mariadb.sql
		# This was a useless check added into the package. Will eventually be removed and this won't be necessary.
		# https://github.com/openxpki/openxpki/issues/894
		sed -i 's|unless ($major >= 10 and $minor >= 3);|unless ($major >= 0 and $minor >= 0);|'g  /usr/share/perl5/OpenXPKI/Server/Database/Driver/MariaDB2.pm
	fi
	input_db_name="openxpki"
    input_db_user="openxpki"
	input_db_pass=`openssl rand 50 | base64`
	cgi_session_db_user="openxpki_cgiSession_user"
    cgi_session_db_pass=`openssl rand 50 | base64`
	ROOT_PW="Enter_Root_Pass"
	echo "Enter the IP or hostname of the remote database."
	read input_db_external_IP
	echo "Enter the port of the remote database"
	read input_db_external_Port
	echo "Run these commands on your external database to prepare for operations."
	echo ""
	$debug mariadb -u root -p"${ROOT_PW}" -e "CREATE DATABASE IF NOT EXISTS "${input_db_name}" CHARSET utf8;"
	echo ""
	$debug mariadb -u root -p"${ROOT_PW}" -e "CREATE USER IF NOT EXISTS '"${input_db_user}"'@'%' IDENTIFIED BY '"${input_db_pass}"';"
	echo ""
	$debug mariadb -u root -p"${ROOT_PW}" -e "GRANT ALL PRIVILEGES ON "${input_db_name}".* TO '"${input_db_user}"'@'%';"
	echo ""
	echo "Type: 'Continue' after you've created the database."
	echo ""
	read input_db_continue
	while [ $input_db_continue != "Continue" ]
	do
		echo "Type: 'Continue' after you've created the database."
		read input_db_continue
	done
	cat /usr/share/doc/libopenxpki-perl/examples/schema-mariadb.sql | mariadb -u "${input_db_name}" -p"${input_db_pass}" -h "${input_db_external_IP}" --database  "${input_db_name}"
	
	#Store credentials in /etc/openxpki/config.d/system/database.yaml
    sed -i "s|name:.*|name: ${input_db_name}|g" ${DATABASE_DIR}
    sed -i "s|#host:.*|host: ${input_db_external_IP}|g" ${DATABASE_DIR}
	sed -i "s|#port:.*|port: ${input_db_external_Port}|g" ${DATABASE_DIR}
	sed -i "s|user:.*|user: ${input_db_user}|g" ${DATABASE_DIR}
    sed -i "s|passwd:.*|passwd: ${input_db_pass}|g" ${DATABASE_DIR}
	sed -i "s|type:.*|type: ${db_type}|g" ${DATABASE_DIR}
	
	#Create cgi session credentials for DB
    echo ""
    echo "Making additional db login user for the webui CGI session"
    echo "This is a limited user that interacts with the cgiSession and helps prevent"
    echo "Your admin database credentials potentially being exposed."
    echo ""
    echo "CREATE USER ${cgi_session_db_user}"
    $debug mariadb -u root -p"${ROOT_PW}" -e "CREATE USER IF NOT EXISTS "${cgi_session_db_user}"@'%' IDENTIFIED BY '"${cgi_session_db_pass}"';"

    # Grant privileges to cgi user for frontend
    echo "Grant SELECT, INSERT, UPDATE, DELETE ON on ""${input_db_name}".frontend_session "to: ""${cgi_session_db_user}"
	$debug mariadb -u root -p"${ROOT_PW}" -e "GRANT SELECT, INSERT, UPDATE, DELETE ON "${input_db_name}".frontend_session TO "${cgi_session_db_user}"@'%';"
    $debug mariadb -u root -p"${ROOT_PW}" -e "FLUSH PRIVILEGES;"
	echo ""
	echo ""
	
fi

if [ $input_db_external == "1" ] && [ $input_db_external_auto == "1" ]; then
    
	debug=
    debug=echo
	
	#Create credentials for external DB and show the user what to configure.
    DATABASE_DIR="${BASE_DIR}/config.d/system/database.yaml"
	echo "Are you connecting to a Galera Cluster? Yes or No"
	read input_db_galera_yn
	if [ ${input_db_galera_yn,,} == "yes" ]; then
	sed -i 's|START WITH 0 INCREMENT BY 1|START WITH 0 INCREMENT BY 0|g' /usr/share/doc/libopenxpki-perl/examples/schema-mariadb.sql
	fi
	input_db_name="openxpki"
    input_db_user="openxpki"
	input_db_pass=`openssl rand 50 | base64`
	cgi_session_db_user="openxpki_cgiSession_user"
    cgi_session_db_pass=`openssl rand 50 | base64`
	echo "Enter remote database admin user"
	read DB_ADMIN_USER
	echo "Enter remote database admin password"
	read DB_ADMIN_PASSWORD
	echo "Enter the IP of the remote database"
	read input_db_external_IP
	echo "Enter the port of the remote database"
	read input_db_external_Port
	echo "Run these commands on your external database to prepare for operations."
	echo ""
	while ! mariadb -u "${DB_ADMIN_USER}" -p"${DB_ADMIN_PASSWORD}" --host="${input_db_external_IP}" --port="${input_db_external_Port}" -e ";" ; do
       read -s -p "Can't connect, please retry: " DB_ADMIN_PASSWORD
    done
	mariadb -u "${DB_ADMIN_USER}" -p"${DB_ADMIN_PASSWORD}" --host="${input_db_external_IP}" --port="${input_db_external_Port}" -e "CREATE DATABASE IF NOT EXISTS "${input_db_name}" CHARSET utf8;"
	echo ""
	mariadb -u "${DB_ADMIN_USER}" -p"${DB_ADMIN_PASSWORD}" --host="${input_db_external_IP}" --port="${input_db_external_Port}" -e "CREATE USER IF NOT EXISTS '"${input_db_user}"'@'%' IDENTIFIED BY '"${input_db_pass}"';"
	echo ""
	mariadb -u "${DB_ADMIN_USER}" -p"${DB_ADMIN_PASSWORD}" --host="${input_db_external_IP}" --port="${input_db_external_Port}" -e "GRANT ALL PRIVILEGES ON "${input_db_name}".* TO '"${input_db_user}"'@'%';"
	echo ""
	cat /usr/share/doc/libopenxpki-perl/examples/schema-mariadb.sql | mariadb -u "${DB_ADMIN_USER}" -p"${DB_ADMIN_PASSWORD}" --host="${input_db_external_IP}" --port="${input_db_external_Port}" --database  "${input_db_name}"
	
	#Store credentials in /etc/openxpki/config.d/system/database.yaml
    sed -i "s^name:.*^name: ${input_db_name}^g" ${DATABASE_DIR}
    sed -i "s^host:.*^host: ${input_db_external_IP}^g" ${DATABASE_DIR}
	sed -i "s^port:.*^port: ${input_db_external_Port}^g" ${DATABASE_DIR}
	sed -i "s^user:.*^user: ${input_db_user}^g" ${DATABASE_DIR}
    sed -i "s^passwd:.*^passwd: ${input_db_pass}^g" ${DATABASE_DIR}
	
	#Create cgi session credentials for DB
    echo ""
    echo ""
    echo "Making additional db login user for the webui CGI session"
    echo "This is a limited user that interacts with the cgiSession and helps prevent"
    echo "Your admin database credentials potentially being exposed."
    echo ""
    echo "CREATE USER ${cgi_session_db_user}"
    mariadb -u "${DB_ADMIN_USER}" -p"${DB_ADMIN_PASSWORD}" --host="${input_db_external_IP}" --port="${input_db_external_Port}" -e "CREATE USER IF NOT EXISTS "${cgi_session_db_user}"@'%' IDENTIFIED BY '"${cgi_session_db_pass}"';"

    # Grant privileges to cgi user for frontend
    echo "Granting SELECT, INSERT, UPDATE, DELETE ON on ""${input_db_name}".frontend_session "to: ""${cgi_session_db_user}"
	mariadb -u "${DB_ADMIN_USER}" -p"${DB_ADMIN_PASSWORD}" --host="${input_db_external_IP}" --port="${input_db_external_Port}" -e "GRANT SELECT, INSERT, UPDATE, DELETE ON "${input_db_name}".frontend_session TO "${cgi_session_db_user}"@'%';"
    mariadb -u "${DB_ADMIN_USER}" -p"${DB_ADMIN_PASSWORD}" --host="${input_db_external_IP}" --port="${input_db_external_Port}" -e "FLUSH PRIVILEGES;"
	echo ""
	echo ""
	
fi

## Extra encryption keys for sessions
## Generate the PEM, remove the BEGIN and END lines, and then remove the new lines
echo ""
echo "Generating public and private keys for non-password authenticated web sessions."
echo "This is viewable in ${BASE_DIR}/webui/default.conf"
echo "The keys are stored in ${BASE_DIR}/tmp"
mkdir -p ${BASE_DIR}/tmp/
`openssl ecparam -name prime256v1 -genkey -noout -out ${BASE_DIR}/tmp/cgi_session_enc_key.key`
`openssl ec -in ${BASE_DIR}/tmp/cgi_session_enc_key.key -pubout -out ${BASE_DIR}/tmp/cgi_session_enc_pub.pem`
v_cgi_session_enc_key=`(cat ${BASE_DIR}/tmp/cgi_session_enc_key.key | sed '1,1d;$ d' | tr -d '\r\n')`
v_cgi_session_enc_pub=`(cat ${BASE_DIR}/tmp/cgi_session_enc_pub.pem | sed '1,1d;$ d' | tr -d '\r\n')`

#Generate a session cookie and additional database session encryption key
cgi_session_cookie=`openssl rand 50 | base64`
db_session_enc_key=`openssl rand 50 | base64`
mv ${BASE_DIR}/webui/default.conf ${BASE_DIR}/webui/default.conf.bak

#Update openxpki apache conf to account for our chosen directory
sed -i "s|/etc/openxpki|"${BASE_DIR}"|g" /etc/apache2/sites-available/openxpki.conf
if [ $input_db_external == "1" ]; then
echo "
[global]
scripturl = cgi-bin/webui.fcgi

realm_mode = select
locale_directory: /usr/share/locale/
default_language: en_US

[logger]
log_level = INFO

[session]
driver = driver:openxpki
timeout = +10m
ip_match = 1
fingerprint = HTTP_ACCEPT_ENCODING, HTTP_USER_AGENT, HTTP_ACCEPT_LANGUAGE, REMOTE_USER, SSL_CLIENT_CERT
cookey = "${cgi_session_cookie}"

[session_driver]
Directory = /tmp
NameSpace = "${input_db_name}"
DataSource = dbi:MariaDB:dbname="${input_db_name}";host="${input_db_external_IP}"
User = "${cgi_session_db_user}"
Password = "${cgi_session_db_pass}"
EncryptKey = "${db_session_enc_key}"
LogIP = 1
LongReadLen = 100000

[realm]

[auth]
sign.key="${v_cgi_session_enc_key}"

# those headers are added to all http responses
[header]
Strict-Transport-Security = max-age=31536000;
X-Frame-Options = SAMEORIGIN;
X-XSS-Protection = 1; mode=block;

# Authentication settings used for e.g. public access scripts
# where no user login is required, by default Anonymous is used
[auth]
stack = _System
" >> ${BASE_DIR}/webui/default.conf

fi
#Need to add the tag here to check out version and not overwrite
if [ $input_db_external == "0" ]; then
echo "
[global]
socket = /var/openxpki/openxpki.socket
scripturl = cgi-bin/webui.fcgi

realm_mode = select
locale_directory: /usr/share/locale/
default_language: en_US

[logger]
log_level = INFO

[session]
driver = driver:openxpki
timeout = +10m
ip_match = 1
fingerprint = HTTP_ACCEPT_ENCODING, HTTP_USER_AGENT, HTTP_ACCEPT_LANGUAGE, REMOTE_USER, SSL_CLIENT_CERT
cookey = "${cgi_session_cookie}"

[session_driver]
Directory = /tmp

NameSpace = "${input_db_name}"
DataSource = dbi:MariaDB:dbname="${input_db_name}"
User = "${cgi_session_db_user}"
Password = "${cgi_session_db_pass}"
EncryptKey = "${db_session_enc_key}"
LogIP = 1
LongReadLen = 100000

[realm]

#[login]

[auth]
sign.key="${v_cgi_session_enc_key}"

# those headers are added to all http responses
[header]
Strict-Transport-Security = max-age=31536000;
X-Frame-Options = SAMEORIGIN;
X-XSS-Protection = 1; mode=block;

# Authentication settings used for e.g. public access scripts
# where no user login is required, by default Anonymous is used
[auth]
stack = _System
" >> ${BASE_DIR}/webui/default.conf
fi

echo ""
echo ""
echo "Begin the script again AFTER you've configured the database."
echo "If you've installed locally, everything has been tested to work."
echo "If you've configured an external database, TEST IT FIRST from this host."
}

transfer_keys_files () {
keys_dir="${BASE_DIR}/local/keys/${REALM}/"
vault_dir="${BASE_DIR}/local/keys/"
# Copy KEY file to PEM file because the designer chose PEM as the key extension...
# The idea is that the Root Cert will be stored elsewhere, not this host.
echo "Copying KEY files to PEM files for transfers to new directory."
if [ $import_xpki_Inter == "1" ]; then
echo "Copying Intermediate CA"
cp ${ISSUING_CA_KEY} ${SSL_REALM}/${ISSUING_CA}.${PEM_SUFFIX}
fi
if [ $import_xpki_Scep == "1" ]; then
echo "Copying SCEP"
cp ${SCEP_KEY} ${SSL_REALM}/${SCEP}.${PEM_SUFFIX}
fi
if [ $import_xpki_Ratoken == "1" ]; then
echo "Copying RATOKEN"
cp ${RATOKEN_KEY} ${SSL_REALM}/${RATOKEN}.${PEM_SUFFIX}
fi
if [ $import_xpki_Web == "1" ]; then
echo "Copying WEB"
cp ${WEB_KEY} ${SSL_REALM}/${WEB}.${PEM_SUFFIX}
fi
if [ $import_xpki_DV == "1" ]; then
echo "Copying Datavault"
cp ${DATAVAULT_KEY} ${SSL_REALM}/${DATAVAULT}.${PEM_SUFFIX}
fi
# Move .PEMs to the keys directory...
# NOT moving ROOT PEM. # mv ${ROOT_PEM} ${keys_dir}
if [ $import_xpki_Inter == "1" ] || [ $import_xpki_Scep == "1" ] || [ $import_xpki_Ratoken == "1" ] || [ $import_xpki_Web == "1" ] || [ $import_xpki_DV == "1" ]; then
chmod 440 ${SSL_REALM}/*.${PEM_SUFFIX}
chown root:root ${SSL_REALM}/*.${REQUEST_SUFFIX} ${SSL_REALM}/*.${PEM_SUFFIX} ${SSL_REALM}/*.${PASS_SUFFIX}
chown root:${group} ${SSL_REALM}/*.${CERTIFICATE_SUFFIX} ${SSL_REALM}/*.${PEM_SUFFIX}
fi
if [ $import_xpki_Inter == "1" ]; then
echo "Moving Intermediate"
mv ${ISSUING_CA_PEM} ${keys_dir}
fi
if [ $import_xpki_Scep == "1" ]; then
echo "Moving SCEP"
mv ${SCEP_PEM} ${keys_dir}
fi
if [ $import_xpki_Ratoken == "1" ]; then
echo "Moving RATOKEN"
mv ${RATOKEN_PEM} ${keys_dir}
fi
if [ $import_xpki_Web == "1" ]; then
echo "Moving Web"
mv ${WEB_PEM} ${keys_dir}
fi
if [ $import_xpki_DV == "1" ]; then
### Need to change default Vault Key location, or prevent constant rewrites if the script runs again.
echo "Checking for existing vault-1.pem"
v_KEY_FILE=${vault_dir}${REALM}/vault-1.pem
  if [ -f "$v_KEY_FILE" ]; then
   echo "Do you want to replace the existing Datavault key? 'Y | y'"
   read input_overwrite_dv
    if [ "${input_overwrite_dv,,}" != "y" ]; then
     echo -e "\nYou've chosen to end the script."
     exit 1
    fi

 echo "Backing up previous vault key, if found."
 timeStamp="$(echo -e `date` | tr -d '[:space:]' | tr -d '[:]' )"
 mv ${vault_dir}${REALM}/vault-1.pem ${vault_dir}${REALM}/vault-1.pem."${REALM}"."${timeStamp}".bak
  fi
mv ${DATAVAULT_PEM} ${vault_dir}${REALM}/vault-1.pem
echo "Vault key moved"
fi
echo "Modifying folder and file permissions."
# chown/chmod
chmod 400 ${SSL_REALM}/*.${PASS_SUFFIX}
chmod 440 ${SSL_REALM}/*.${KEY_SUFFIX}
chmod 444 ${SSL_REALM}/*.${CERTIFICATE_SUFFIX}
chown root:root ${SSL_REALM}/*.${REQUEST_SUFFIX} ${SSL_REALM}/*.${KEY_SUFFIX} ${SSL_REALM}/*.${PASS_SUFFIX}
chown root:${group} ${SSL_REALM}/*.${CERTIFICATE_SUFFIX} ${SSL_REALM}/*.${KEY_SUFFIX}
echo "Done modifying folder and file permissions."

#### Need to Add an additional keyword "0perational C0nfig" at the top of target file
#### so we can put these 'seds' into an if state and only run them only once.
#### Modify the new realm crypto.yaml file with new variables
#echo "REALM_YAML="${BASE_DIR}/config.d/realm/${REALM}/crypto.yaml"" #debug
REALM_YAML="${BASE_DIR}/config.d/realm/${REALM}/crypto.yaml"
mv "${BASE_DIR}/config.d/realm/${REALM}/crypto.yaml" "${BASE_DIR}/config.d/realm/${REALM}/crypto.yaml.bak"
# Copy our crypto template to the realm's crypto.yaml file
echo "
type:
  certsign: ca-signer
  datasafe: vault
  cmcra: ratoken
  scep: scep

# The actual token setup
token:
  default:
    backend: OpenXPKI::Crypto::Backend::OpenSSL

    # possible values are OpenSSL, nCipher, LunaCA
    engine: OpenSSL
    engine_section: ''
    engine_usage: ''
    key_store: OPENXPKI

    # OpenSSL binary location
    shell: /usr/bin/openssl

    # OpenSSL binary call gets wrapped with this command
    wrapper: ''

    # random file to use for OpenSSL
    randfile: /var/openxpki/rand

  vault:
    inherit: default
    key: ${vault_dir}${REALM}/vault-1.pem
    secret: vault

  ca-signer:
    inherit: default
    key: ${vault_dir}${REALM}/${ISSUING_CA}.pem
    secret: ca-signer

  ratoken:
    inherit: default
    key: ${vault_dir}${REALM}/${RATOKEN}.pem
    secret: ratoken

  scep:
    inherit: default
    key: ${vault_dir}${REALM}/${SCEP}.pem
    secret: scep

# Define the secret groups
secret:" >> ${BASE_DIR}/config.d/realm/${REALM}/crypto.yaml

# Has the crypto.yaml file been edited before? Checking for our keyword to decide.
echo "Editing config file at: ${REALM_YAML}"
#echo "TAG="0perational C0nfig"" #debug
TAG="0perational C0nfig"
if grep -Fq "${TAG}" ${REALM_YAML}; then
echo -e "It looks like this isn't the first time we've edited your realm crypto"
echo -e " file. Attempting to configure for new aliases."

# put contents of the password file into a variable to pass into the crypto.yaml file
if [ $import_xpki_Inter == "1" ]; then
v_ISSUING_CA_KEY_PASSWORD="$(cat ${ISSUING_CA_KEY_PASSWORD})"
fi
if [ $import_xpki_DV == "1" ]; then
v_DATAVAULT_KEY_PASSWORD="$(cat ${DATAVAULT_KEY_PASSWORD})"
fi
if [ $import_xpki_Scep == "1" ]; then
v_SCEP_KEY_PASSWORD="$(cat ${SCEP_KEY_PASSWORD})"
fi
if [ $import_xpki_Ratoken == "1" ]; then
v_RATOKEN_KEY_PASSWORD="$(cat ${RATOKEN_KEY_PASSWORD})"
fi
if [ $import_xpki_DV == "1" ]; then
echo "  vault:
    label: ${DATAVAULT}
    export: 0
    method: literal
    value: ${v_DATAVAULT_KEY_PASSWORD}
" >> ${BASE_DIR}/config.d/realm/${REALM}/crypto.yaml
fi
if [ $import_xpki_Inter == "1" ]; then
echo "  ca-signer:
    label: ${ISSUING_CA}
    export: 0
    method: literal
    value: ${v_ISSUING_CA_KEY_PASSWORD}
" >> ${BASE_DIR}/config.d/realm/${REALM}/crypto.yaml
fi
if [ $import_xpki_Scep == "1" ]; then
echo "  scep:
    label: ${SCEP}
    export: 0
    method: literal
    value: ${v_SCEP_KEY_PASSWORD}
" >> ${BASE_DIR}/config.d/realm/${REALM}/crypto.yaml
fi
if [ $import_xpki_Ratoken == "1" ]; then
echo "  ratoken:
    label: ${RATOKEN}
    export: 0
    method: literal
    value: ${v_RATOKEN_KEY_PASSWORD}
" >> ${BASE_DIR}/config.d/realm/${REALM}/crypto.yaml
fi
else
 # echo -e "\nThis config file has not been edited by this script. Assuming it's a new copy from the "
 # echo -e "from the Realm.Tpl directory, we're going to prep it for operation. "
 # # Have to keep the first sed command at the top because we're counting lines.
 # sed -i '53 s|default:|# default:|g' ${REALM_YAML}
 # sed -i '43d' ${REALM_YAML}
 # sed -i '42 a\    key: ${BASE_DIR}/local/keys/[% PKI_REALM %]/[% ALIAS %].pem' ${REALM_YAML}
 # sed -i -z 's/import:/# import:/1' ${REALM_YAML}
 # sed -i -z 's/secret: default/# secret: default/' ${REALM_YAML}
 # sed -i '/ca-signer:/a\    secret: ca-signer' ${REALM_YAML} # Add version number?
 # sed -i '/LibSCEP/a\    secret: scep' ${REALM_YAML} # Add version number?
 # sed -i '/vault:/a\    secret: vault' ${REALM_YAML} # Add version number?
 # sed -i 's@key: ${BASE_DIR}/local/keys/[% ALIAS %].pem@key: ${BASE_DIR}/local/keys/[% PKI_REALM %]/[% ALIAS %].pem@' ${REALM_YAML}
 sed -i '1s/^/#0perational C0nfig\n/' ${REALM_YAML} # Tag the config so we don't fill it with these settings again.
# put contents of the password file into a variable to pass into the crypto.yaml file
if [ $import_xpki_Inter == "1" ]; then
v_ISSUING_CA_KEY_PASSWORD="$(cat ${ISSUING_CA_KEY_PASSWORD})"
fi
if [ $import_xpki_DV == "1" ]; then
v_DATAVAULT_KEY_PASSWORD="$(cat ${DATAVAULT_KEY_PASSWORD})"
fi
if [ $import_xpki_Scep == "1" ]; then
v_SCEP_KEY_PASSWORD="$(cat ${SCEP_KEY_PASSWORD})"
fi
if [ $import_xpki_Ratoken == "1" ]; then
v_RATOKEN_KEY_PASSWORD="$(cat ${RATOKEN_KEY_PASSWORD})"
fi
if [ $import_xpki_DV == "1" ]; then
echo "  vault:
    label: ${DATAVAULT}
    export: 0
    method: literal
    value: ${v_DATAVAULT_KEY_PASSWORD}
" >> ${BASE_DIR}/config.d/realm/${REALM}/crypto.yaml
fi
if [ $import_xpki_Inter == "1" ]; then
echo "  ca-signer:
    label: ${ISSUING_CA}
    export: 0
    method: literal
    value: ${v_ISSUING_CA_KEY_PASSWORD}
" >> ${BASE_DIR}/config.d/realm/${REALM}/crypto.yaml
fi
if [ $import_xpki_Ratoken == "1" ]; then
echo "  ratoken:
    label: ${RATOKEN}
    export: 0
    method: literal
    value: ${v_RATOKEN_KEY_PASSWORD}
" >> ${BASE_DIR}/config.d/realm/${REALM}/crypto.yaml
fi
if [ $import_xpki_Scep == "1" ]; then
echo "  scep:
    label: ${SCEP}
    export: 0
    method: literal
    value: ${v_SCEP_KEY_PASSWORD}
" >> ${BASE_DIR}/config.d/realm/${REALM}/crypto.yaml
fi
fi
}

# The order of importing Certificates matters
# The OpenXPKI instance must be off for this first part or importing is broken
# Need to verify the order of operations
openxpkiadm_root () {
# Importing Root CA
echo -e "\nImporting Root Certificate.."
echo "openxpkiadm alias --token root --file "${ROOT_CA_CERTIFICATE}" --realm "${REALM}" --config "${CONF_DIR}"" >> ${BASE_DIR}/ca/"${REALM}"/openxpkiadmCommands.txt
openxpkiadm alias --token root --file "${ROOT_CA_CERTIFICATE}" --realm "${REALM}" --config "${CONF_DIR}"
echo "Imported Root CA."
}

openxpkiadm_dv () {
# Importing Datavault
echo -e "\nImporting Datavault Certificate: ${DATAVAULT_CERTIFICATE}"
echo "openxpkiadm alias --token datasafe --file "${DATAVAULT_CERTIFICATE}" --key "${vault_dir}${REALM}"/vault-1.pem --realm "${REALM}" --config "${CONF_DIR}"" >> ${BASE_DIR}/ca/"${REALM}"/openxpkiadmCommands.txt
openxpkiadm alias --token datasafe --file "${DATAVAULT_CERTIFICATE}" --key "${vault_dir}${REALM}"/vault-1.pem --realm "${REALM}" --config "${CONF_DIR}"
sleep 1;
echo "Imported Datavault."
}

# Keys NEED to be added to keys directory before these commands happen or the import fails
openxpkiadm_issue () {
echo "Importing Intermediate Certificate and put key in keys directory.."
echo "openxpkiadm alias --token certsign --file "${ISSUING_CA_CERTIFICATE}" --realm "${REALM}" --key "${ISSUING_CA_KEY}"" >> ${BASE_DIR}/ca/"${REALM}"/openxpkiadmCommands.txt
openxpkiadm alias --token certsign --file "${ISSUING_CA_CERTIFICATE}" --realm "${REALM}" --key "${ISSUING_CA_KEY}" --config "${CONF_DIR}"
echo "Imported Intermediate CA."
}

# Keys NEED to be added to keys directory before these commands happen or the import fails
openxpkiadm_scep () {
echo "openxpkiadm alias --token scep --file "${SCEP_CERTIFICATE}" --realm "${REALM}"  --key "${SCEP_KEY}" --config "${CONF_DIR}"" >> ${BASE_DIR}/ca/"${REALM}"/openxpkiadmCommands.txt
openxpkiadm alias --token scep --file "${SCEP_CERTIFICATE}" --realm "${REALM}"  --key "${SCEP_KEY}" --config "${CONF_DIR}"
echo "Imported Scep."
}

# Keys NEED to be added to keys directory before these commands happen or the import fails
openxpkiadm_ratoken () {
echo "openxpkiadm alias --token cmcra --file "${RATOKEN_CERTIFICATE}" --realm "${REALM}" --key "${RATOKEN_KEY}" --config "${CONF_DIR}"" >> ${BASE_DIR}/ca/"${REALM}"/openxpkiadmCommands.txt
openxpkiadm alias --token cmcra --file "${RATOKEN_CERTIFICATE}" --realm "${REALM}" --key "${RATOKEN_KEY}" --config "${CONF_DIR}"
echo "Imported RA Token."
}

update_default_configs () {
echo "Updating some of the default configuration files to include the values of your install variables"
mv "${BASE_DIR}"/config.d/realm/"${REALM}"/auth/handler.yaml "${BASE_DIR}"/config.d/realm/"${REALM}"/auth/handler.yaml.bak

echo "
# Those stacks are usually required so you should not remove them
Anonymous:
    type: Anonymous
    label: Anonymous

System:
    type: Anonymous
    role: System

# Using the default config this allows a user login with ANY certificate
# issued by the ${REALM} which has the client auth keyUsage bit set
# the commonName is used as username!
Certificate:
    type: ClientX509
    role: User
    arg: CN
    trust_anchor:
        realm: ${REALM}

# Read the userdata from a YAML file defined in auth/connector.yaml
Production:
    type: Password
    user@: connector:auth.connector.userdb
" >> "${BASE_DIR}"/config.d/realm/"${REALM}"/auth/handler.yaml

#Verify Ownership
chown -R openxpki:openxpki /etc/openxpki

mv "${BASE_DIR}"/config.d/realm/"${REALM}"/auth/stack.yaml "${BASE_DIR}"/config.d/realm/"${REALM}"/auth/stack.yaml.bak
v_cgi_session_enc_pub=`(cat ${BASE_DIR}/tmp/cgi_session_enc_pub.pem | sed '1,1d;$ d' | tr -d '\r\n')`

echo "
# Allows Anonymous Login (also from the WebUI!)
# Disable or make ACL to limit interaction from anon
Anonymous:
    label: Anonymous
    description: Access for guests without credentials.
    handler: Anonymous
    type: anon

# Regular login for users via an external password database defined
# in handler.yaml as "Production"
Production:
    label: User Login
    description: Login with username and password
    handler: Production
    type: passwd

# Login with a client certificate, needs to be setup on the webserver
Certificate:
    label: Client certificate
    description: Login using a client certificate
    handler: Certificate
    type: x509
    sign:
    key: ${v_cgi_session_enc_pub}

# The default handler for automated interfaces, hidden from the UI
_System:
    handler: System
" >> "${BASE_DIR}"/config.d/realm/"${REALM}"/auth/stack.yaml

#Verify Ownership
chown -R openxpki:openxpki /etc/openxpki

# mv "${BASE_DIR}"/config.d/realm/"${REALM}"/auth/roles.yaml "${BASE_DIR}"/config.d/realm/"${REALM}"/auth/roles.yaml.bak
# echo "
# User:
    # label: User

# # operator personel
# RA Operator:
    # label: RA Operator

# # operator with ca key access
# CA Operator:
    # label: CA Operator

# # system user, anything which is running on the shell
# System:
    # label: System
# " >> "${BASE_DIR}"/config.d/realm/"${REALM}"/auth/roles.yaml

echo "updating the Realm default profile."
DomainName=`hostname -d`
# Edit the issuing profiles under realm 
sed -i "s|pki.example.com|${FQDN,,}|g" ${BASE_DIR}/config.d/realm/${REALM}/profile/default.yaml
sed -i "s|ocsp.example.com|ocsp.${DomainName,,}|g" ${BASE_DIR}/config.d/realm/${REALM}/profile/default.yaml

echo "updating the Server default scep, est and rpc confs"
#Add the new realm to the configs for rpc, scep and est
sed -i "s|realm = democa|realm = ${REALM}|g" ${BASE_DIR}/scep/default.conf
sed -i "s|realm = democa|realm = ${REALM}|g" ${BASE_DIR}/est/default.conf
sed -i "s|realm = democa|realm = ${REALM}|g" ${BASE_DIR}/rpc/default.conf
sed -i "s|realm = democa|realm = ${REALM}|g" ${BASE_DIR}/rpc/public.conf
sed -i "s|realm = democa|realm = ${REALM}|g" ${BASE_DIR}/rpc/enroll.conf

echo "Removing the democa from the realms file."
#Remove democa CA realm
sed -i '/democa/d' ${BASE_DIR}/config.d/system/realms.yaml
sed -i '/[Ee]xample/d' ${BASE_DIR}/config.d/system/realms.yaml

#Clean up the spaces before continuing
sed -i '/^[[:space:]]*$/d' ${BASE_DIR}/config.d/system/realms.yaml

echo "Removing the democa realm directory."
rm -rf ${BASE_DIR}/config.d/realm/democa

echo "Restarting Server."
openxpkictl stop
sleep 10;
openxpkictl start
sleep 1;
}

#Verify Ownership
chown -R openxpki:openxpki /etc/openxpki

apache2_setup () {
# Setup the Webserver
a2enmod ssl rewrite headers
a2ensite openxpki
a2dissite 000-default default-ssl
#Configure download permissions
chmod -R 755 /var/www/download/

# if you're regenerating SSL Keys, then you need to delete this chain folder, or edit this to include some user input
if [ ! -e "${BASE_DIR}/tls/chain" ]; then
    mkdir -m755 -p ${BASE_DIR}/tls/chain
    # The files in this directory have to be PEM-encoded and are accessed through hash filenames.
    # https://httpd.apache.org/docs/current/mod/mod_ssl.html#sslcacertificatefile
    openssl x509 -in "${ROOT_CA_CERTIFICATE}" -out ${BASE_DIR}/tls/chain/Root.pem
    openssl x509 -in "${ISSUING_CA_CERTIFICATE}" -out ${BASE_DIR}/tls/chain/Inter.pem
    c_rehash ${BASE_DIR}/tls/chain/
fi

if [ ! -e "${BASE_DIR}/tls/endentity/openxpki.crt" ]; then
    mkdir -m755 -p ${BASE_DIR}/tls/endentity
    mkdir -m700 -p ${BASE_DIR}/tls/private
    `cp -r ${WEB_CERTIFICATE} ${BASE_DIR}/tls/endentity/openxpki.crt`
    cat ${ISSUING_CA_CERTIFICATE} >> ${BASE_DIR}/tls/endentity/openxpki.crt
    echo -e "\nWeb Certificate"
    echo "openssl rsa -in ${WEB_KEY} -passin file:${WEB_KEY_PASSWORD} -out ${BASE_DIR}/tls/private/openxpki.pem" >> certificateCommands.txt
    openssl rsa -in ${WEB_KEY} -passin file:${WEB_KEY_PASSWORD} -out ${BASE_DIR}/tls/private/openxpki.pem
    chmod 400 ${BASE_DIR}/tls/private/openxpki.pem
	chown -R openxpki:openxpki /etc/openxpki
    service apache2 restart
fi

openssl x509 -in "${ROOT_CA_CERTIFICATE}" -out /etc/ssl/certs/Root.pem
openssl x509 -in "${ISSUING_CA_CERTIFICATE}" -out /etc/ssl/certs/Inter.pem
c_rehash /etc/ssl/certs
update-ca-certificates
}

import_certificates () {

#Version 3.X doesn't need to be stopped before importing.
#Needs continous testing
#20230928

# Create systemd file and run with the correction location
echo "
[Unit]
Description=OpenXPKI Trustcenter Backend
After=network.target apache2.service

[Service]
Type=exec
PIDFile=/var/run/openxpki/openxpkid.pid
ExecStart=/usr/bin/openxpkictl start --nd  --config "${CONF_DIR}"
ExecStop=/usr/bin/openxpkictl stop --config "${CONF_DIR}"
# We want systemd to give the daemon some time to finish gracefully, but still want
# it to kill httpd after TimeoutStopSec if something went wrong during the
# graceful stop. Normally, Systemd sends SIGTERM signal right after the
# ExecStop, which would kill the daemon. We are sending useless SIGCONT here to give
# the daemon time to finish.
Restart=on-failure
KillSignal=SIGCONT
PrivateTmp=true

[Install]
WantedBy=multi-user.target" > /etc/systemd/system/openxpkid.service

#Reload systemctl daemon
systemctl daemon-reload

#Start OpenXPKI
systemctl start openxpkid.service


#openxpkictl start --config "${CONF_DIR}"
#if [ $import_xpki_Root == "1" ] || [ $import_xpki_DV == "1" ]; then
# echo "Stopping OpenXPKI if it's running.."
# if pgrep "openxpki" > /dev/null
# then
    # openxpkictl stop
# fi
#fi
if [ $import_xpki_Root == "1" ]; then
    openxpkiadm_root
fi
if [ $import_xpki_DV == "1" ]; then
    openxpkiadm_dv
fi

# Start OpenX before importing the tokens
# echo -e "\nStarting server before running import ... "
# openxpkictl start

if [ $import_xpki_Inter == "1" ]; then
   openxpkiadm_issue
fi
if [ $import_xpki_Scep == "1" ]; then
   openxpkiadm_scep
fi
if [ $import_xpki_Ratoken == "1" ]; then
   openxpkiadm_ratoken
fi
if [ $import_xpki_Web == "1" ]; then
   apache2_setup
fi

echo -e "\nOpenXPKI configuration should be complete and server should be running..."
}

#This script creates a new user.
#Need to configure directory and handler still

add_new_user () {
echo "Enter new user name."
echo ""
read v_new_user
echo "Run the following command to create an argon digest."
echo "openxpkiadm hashpwd -s argon2"
echo "Next, copy the below output with the digest inside single quotes (')"
echo "to the userdb file."

# Add new user details to the userdb or admindb
if [ $v_new_user_role == "CA" ] || [ $v_new_user_role == "RA" ]; then
	userFile='/home/pkiadm/userdb.yaml'
	if [ ! -f $userFile ]; then
    touch $userFile
	chown -R openxpki:openxpki $userFile
	fi
    echo "Add the digest to $userFile"
	echo "$v_new_user:
    digest: ''
    role: $v_new_user_role Operator" >> $userFile
fi
if [ $v_new_user_role == "User" ]; then
	userFile='/home/pkiadm/userdb.yaml'
	if [ ! -f $userFile ]; then
    touch $userFile
	chown -R openxpki:openxpki $userFile
	fi
	echo "Add the digest to $userFile"
	echo "$v_new_user:
    digest: ''
    role: $v_new_user_role" >> $userFile
fi
# While using local userdb/admindb, openX needs to restart to pull in DB
# during the startup process, else users can't login.
echo ""
echo "Restarting Server to apply the new user."
echo "Add the digest to the correct user in the userdb file."
openxpkictl stop
sleep 3;
openxpkictl start
create_new_user
}

create_new_user () {
PS3="Select user role.  "
select role in Run_First_Create_Hash Certificate_Authority Registration_Authority User Quit; do
case $role in
Run_First_Create_Hash)
 echo "Run the following command to get your digest,"
 echo "then run the script again."
 echo ""
 echo "openxpkiadm hashpwd -s argon2"
 echo ""
 break
 ;;
Certificate_Authority)
 v_new_user_role="CA"
 add_new_user
 break
 ;;
Registration_Authority)
 v_new_user_role="RA"
 add_new_user
 break
 ;;
User)
 v_new_user_role="User"
 add_new_user
 break
 ;;
 Quit)
 exit 1
 ;;
*)
  echo "Invalid Option: $REPLY"
  ;;
esac
done
}

show_realm_certs () {
openxpkiadm alias --realm ${REALM}
}

echo -e "\nFollow the prompts for creating certificates ... "
import_xpki_Scep="0"
import_xpki_Ratoken="0"
import_xpki_Root="0"
import_xpki_Inter="0"
import_xpki_DV="0"
import_xpki_Web="0"

PS3="Select the operation: "
select opt in Install_OpenXPKI Create_Realm Generate_new_Root_CA Generate_new_Intermediate_CA Generate_new_Datavault_Certificate Generate_new_Scep_Certificate Generate_new_Ratoken_Certificate Generate_new_Web_Certificate Add_Users Quit; do
case $opt in
Install_OpenXPKI)
 function_OpenXinstaller
 break
 ;;
Create_Realm)							## First_run
 import_xpki_Root="1"
 import_xpki_Inter="1"
 import_xpki_DV="1"
 import_xpki_Web="1"
 import_xpki_Ratoken="1"
 import_xpki_Scep="1"
 check_installed
 question_realm
 question_ou
 question_rootVer
 question_interVer
 question_scepVer
 question_ratokenVer
 question_webVer
 question_country
 question_state
 question_locality
 question_email
 confirm_input
 populate_files
 define_certificates  #123
 define_openssl
 confirm_run
 gen_RootCA
 gen_InterCA
 gen_ScepCert
 gen_RatokenCert
 gen_DatavaultCert
 gen_WebCert
 echo "Certificates created, Continuing"
 transfer_keys_files
 import_certificates
 update_default_configs
 show_realm_certs
## openx command
 break
 ;;
Generate_new_Root_CA)						## Generate_new_Root_CA
 import_xpki_Root="1"
 import_xpki_Inter="0"
 import_xpki_DV="0"
 import_xpki_Web="0"
 import_xpki_Scep="0"
 import_xpki_Ratoken="0"
 check_installed
 question_realm
 question_ou
 question_rootVer
 question_country
 question_state
 question_locality
 question_email
 confirm_input
 populate_files
 define_certificates  #123
 define_openssl
 confirm_run
 gen_RootCA
 transfer_keys_files
 import_certificates
##openx command
 break
 ;;
Generate_new_Intermediate_CA)					## Generate_new_Intermediate_CA
 import_xpki_Root="0"
 import_xpki_Inter="1"
 import_xpki_DV="0"
 import_xpki_Web="0"
 import_xpki_Scep="0"
 import_xpki_Ratoken="0"
 check_installed
 question_realm
 question_ou
 question_interVer
 question_country
 question_state
 question_locality
 question_email
 confirm_input
 populate_files
 define_certificates  #123
 define_openssl
 confirm_run
 gen_InterCA
 transfer_keys_files
 import_certificates
##openx command
 break
 ;;
Generate_new_Datavault_Certificate)				## Generate_new_Datavault_Certificate
 echo "WARNING!!! THIS OPTION IS POTENTIALLY DESTRUCTIVE!"
 echo "IF YOU DON'T FULLY UNDERSTAND THE DECISION YOU'RE MAKING"
 echo "YOU COULD LOSE ACCESS TO YOUR PKI INFRASTRUCTURE!!!"
 echo "OpenXPKI will NOT be held accountable for your decisions!"
 echo "Are you sure you wish to proceed with this risky option???"
 echo "Type or paste the following string at the prompt."
 echo "      I accept the consequences of my actions"
 read input_warning
 string_acceptLiability="I accept the consequences of my actions"
 if [ "${input_warning}" != "${string_acceptLiability}" ]; then
 exit 1
 fi
 import_xpki_Root="0"
 import_xpki_Inter="0"
 import_xpki_DV="1"
 import_xpki_Web="0"
 import_xpki_Scep="0"
 import_xpki_Ratoken="0"
 check_installed
 question_realm
 confirm_input
 populate_files
 define_certificates  #123
 define_openssl
 confirm_run
 gen_DatavaultCert
 transfer_keys_files
 import_certificates
## openx command
 break
 ;;
 Generate_new_Scep_Certificate)					## Generate_new_Scep_Certificate
 import_xpki_Root="0"
 import_xpki_Inter="0"
 import_xpki_DV="0"
 import_xpki_Web="0"
 import_xpki_Ratoken="0"
 import_xpki_Scep="1"
 check_installed
 question_realm
 question_ou
 question_scepVer
 question_country
 question_state
 question_locality
 question_email
 confirm_input
 populate_files
 define_certificates  #123
 define_openssl
 confirm_run
 gen_ScepCert
 transfer_keys_files
 import_certificates
 ## openx command
 break
 ;;
Generate_new_Ratoken_Certificate)					## Generate_new_Ratoken_Certificate
 import_xpki_Root="0"
 import_xpki_Inter="0"
 import_xpki_DV="0"
 import_xpki_Web="0"
 import_xpki_Scep="0"
 import_xpki_Ratoken="1"
 check_installed
 question_realm
 question_ou
 question_ratokenVer
 question_country
 question_state
 question_locality
 question_email
 confirm_input
 populate_files
 define_certificates  #123
 define_openssl
 confirm_run
 gen_RatokenCert
 transfer_keys_files
 import_certificates
 ## openx command
 break
 ;;
Generate_new_Web_Certificate)					## Generate_new_Web_Certificate
 import_xpki_Root="0"
 import_xpki_Inter="0"
 import_xpki_DV="0"
 import_xpki_Web="1"
 import_xpki_Scep="0"
 import_xpki_Ratoken="0"
 check_installed
 question_realm
 question_ou
 question_webVer
 question_country
 question_state
 question_locality
 question_email
 confirm_input
 populate_files
 define_certificates  #123
 define_openssl
 confirm_run
 gen_WebCert
 transfer_keys_files
 import_certificates
 break
 ;;
#List_Users)
Add_Users)
 create_new_user
 break
 ;;
##Change_Password)
Quit)
 exit 1
 ;;
*)
  echo "Invalid Option: $REPLY"
  ;;
esac
done
