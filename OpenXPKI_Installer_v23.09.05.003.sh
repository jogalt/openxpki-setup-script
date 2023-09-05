#!/bin/bash

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

check_installed () {
#
# basic openxpki settings
#
BASE_DIR='/opt/openxpki';
OPENXPKI_CONFIG="${BASE_DIR}/config.d/system/server.yaml"
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
echo "will create a Root certificate, Intermediate (Issuing) Certificate, SCEP certificate"
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
echo "Root Version: '${rootVer}'"
echo "Issuer Version: '${interVer}'"
echo "Scep Version: '${scepVer}'"
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

define_certificates () {
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
ROOT_CA_SUBJECT="/C=${COUNTRY^^}/ST=${STATE^^}/L=${LOCALITY^^}/O=${REALM^^}/OU=${OrgU^^}/${DCFQDN}/CN=${REALM^^} Root CA ${rootVer}"
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
ISSUING_CA_SUBJECT="/C=${COUNTRY^^}/ST=${STATE^^}/L=${LOCALITY^^}/O=${REALM^^}/OU=${OrgU^^}/${DCFQDN}/CN=${REALM^^} Intermediate CA ${interVer}"
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
SCEP_SUBJECT="/C=${COUNTRY^^}/ST=${STATE^^}/L=${LOCALITY^^}/O=${REALM^^}/OU=${OrgU^^}/${DCFQDN}/CN=${FQDN}:${REALM,,}-SCEP-RA-${scepVer}"
  # Show user the expected output.
  if [ $import_xpki_Scep == "1" ]; then
  echo "${SCEP_SUBJECT}"
  fi

# Apache WEB certificate signed by root CA above
WEB="${REALM^^}_WebUI_${webVer}"
WEB_REQUEST="${SSL_REALM}/${WEB}.${REQUEST_SUFFIX}"
WEB_KEY="${SSL_REALM}/${WEB}.${KEY_SUFFIX}"
WEB_PEM="${SSL_REALM}/${WEB}.${PEM_SUFFIX}"
WEB_KEY_PASSWORD="${SSL_REALM}/${WEB}.${PASS_SUFFIX}"
WEB_CERTIFICATE="${SSL_REALM}/${WEB}.${CERTIFICATE_SUFFIX}"
WEB_SUBJECT="/C=${COUNTRY^^}/ST=${STATE^^}/L=${LOCALITY^^}/O=${REALM^^}/OU=${OrgU^^}/${DCFQDN}/CN=${FQDN} Web Cert ${webVer}"
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
DATAVAULT_SUBJECT="/C=${COUNTRY^^}/ST=${STATE^^}/L=${LOCALITY^^}/O=${REALM^^}/OU=${OrgU^^}/${DCFQDN}/CN=${REALM^^} Internal DataVault"
  # Show user the expected output.
  if [ $import_xpki_DV == "1" ]; then
  echo "${DATAVAULT_SUBJECT}"
  fi

# Define Root and Intermediate authorityInfoAccess and crlDistributionPoints
ROOT_CA_CERTIFICATE_URI="URI"':''http://'"${FQDN}"'/download/'"${ROOT_CA}"'.cer'
ROOT_CA_REVOCATION_URI="URI"':''http://'"${FQDN}"'/download/'"${ROOT_CA}"'.crl'
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
    # This avoids readding it after everytime the script runs.
    # Add new realm to the Realms config.
if grep -Fq "$REALM" ${REALM_CONF}; then
  echo "It appears your Realm is alreddy in configured in:"
  echo "${BASE_DIR}/config.d/system/realms.yaml"
else
echo "
${REALM}:
   label: ${REALM} CA
   baseurl: https://`hostname -f`/openxpki/
" >> "${REALM_CONF}"
fi
}

define_openssl () {
#
# openssl.conf
#
BITS="8192"
DVBITS="16384" # Customizing Datavault bits for experimenting
DAYS="397" # 397 days, Setting to 397 since apple said they wouldn't support over 398 days
RDAYS="7305" # 20 years for root
IDAYS="5479" # 15 years for issuing
SDAYS="365" # 1 years for scep
WDAYS="397" # 3 years web
DDAYS="$RDAYS" # 20 years datavault (same a root)
SDATE="$input_SDATE" # Need the correct format # incorporate with if statements
EDATE="$input_EDATE" # Need the correct format # incorporate with if statements
# Add future option to input start date for adding certificates :
# openssl ca -in csr.pem -startdate 140529000000Z
#SDATE=YYMMDDHHMMSSZ
#EDATE=YYMMDDHHMMSSZ

# creation neccessary directories and files
echo -n "Creating configuration for openssl ($OPENSSL_CONF) .. "
test -d "${SSL_REALM}" || mkdir -m 755 -p "${SSL_REALM}" && chown ${user}:root "${SSL_REALM}"
OPENSSL_DIR="${SSL_REALM}/.openssl"
test -d "${OPENSSL_DIR}" || mkdir -m 700 "${OPENSSL_DIR}" && chown root:root "${OPENSSL_DIR}"
cd "${OPENSSL_DIR}";

## Verify output during testing
#echo -e ${ROOT_CA_CERTIFICATE_URI}"\n" >> ${BASE_DIR}/ca/${REALM}/URI.txt
#echo -e ${ROOT_CA_REVOCATION_URI}"\n" >> ${BASE_DIR}/ca/${REALM}/URI.txt
#echo -e ${ISSUING_REVOCATION_URI}"\n">> ${BASE_DIR}/ca/${REALM}/URI.txt
#echo -e ${ISSUING_CERTIFICATE_URI} >> ${BASE_DIR}/ca/${REALM}/URI.txt

OPENSSL_CONF="${OPENSSL_DIR}/openssl.cnf"

touch "${OPENSSL_DIR}/index.txt"
touch "${OPENSSL_DIR}/index.txt.attr"
touch "${OPENSSL_DIR}/serial"
echo $(date +%Y%m%d%H%M)"0001" > "${OPENSSL_DIR}/crlnumber"
echo $(date +%Y%m%d%H%M)"0001" >> "${OPENSSL_DIR}/serial"

echo "
HOME			= .
RANDFILE		= \$ENV::HOME/.rnd

[ ca ]
default_ca		= CA_default

[ req ]
default_bits		= ${BITS}
distinguished_name	= req_distinguished_name

[ CA_default ]
dir			= ${OPENSSL_DIR}
certs			= ${OPENSSL_DIR}/certs
crldir			= ${OPENSSL_DIR}/
database		= ${OPENSSL_DIR}/index.txt
new_certs_dir		= ${OPENSSL_DIR}/
serial			= ${OPENSSL_DIR}/serial
crlnumber		= ${OPENSSL_DIR}/crlnumber
crl			= ${OPENSSL_DIR}/crl.pem
private_key		= ${OPENSSL_DIR}/cakey.pem
RANDFILE		= ${OPENSSL_DIR}/.rand
default_md		= sha3-512
preserve		= no
policy			= policy_match
default_days		= ${DAYS}
email_in_dn		= no
countryName_default     = "${COUNTRY}"
stateOrProvinceName_default     = "${STATE}"
0.organizationName_default      = "${REALM}"
0.organizationUnitName_default  = "${OrgU}"

#x509_extensions               = v3_ca_extensions
#x509_extensions               = v3_issuing_extensions
#x509_extensions               = v3_datavault_extensions
#x509_extensions               = v3_scep_extensions
#x509_extensions               = v3_web_extensions

[ policy_match ]
countryName             = match
stateOrProvinceName	    = supplied
localityName            = supplied
organizationName        = match
organizationalUnitName	= supplied
commonName		        = supplied
emailAddress	       	= supplied

# x509_extensions               = v3_ca_reqexts # not for root self signed, only for issuing
# x509_extensions              = v3_datavault_reqexts # not required self signed
# x509_extensions               = v3_scep_reqexts
# x509_extensions               = v3_web_reqexts

[ req_distinguished_name ]
countryName		= Country Name (2 letter code)
countryName_default	= "${COUNTRY}"

stateOrProvinceName 	= State or Province Name (full name)
stateOrProvinceName_default	= "${STATE}"

localityName		= Locality Name (eg, city)
0.localityName_default      = "${LOCALITY}"

0.organizationName	= Organization Name (eg, company)
0.organizationName_default	= "${REALM}"

0.organizationUnitName	= Organization Unit Name (eg, section)
0.organizationUnitName_default	= "${OrgU}"

commonName		= Common Name (eg, YOUR name)
commonName_max		= 64

emailAddress		= Email Address
emailAddress_max	= 64

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
authorityInfoAccess	= caIssuers;"${ROOT_CA_CERTIFICATE_URI}"

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

[ v3_web_extensions ]
subjectKeyIdentifier    = hash
keyUsage                = critical, digitalSignature, keyEncipherment
extendedKeyUsage        = serverAuth, clientAuth
basicConstraints        = critical,CA:FALSE
subjectAltName		= DNS:"${FQDN}"
crlDistributionPoints	= "${ISSUING_REVOCATION_URI}"
authorityInfoAccess	= caIssuers;"${ISSUING_CERTIFICATE_URI}"
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
   openssl req -verbose -config "${OPENSSL_CONF}" -extensions v3_ca_extensions -batch -x509 -newkey rsa:$BITS -days ${RDAYS} -passout file:"${ROOT_CA_KEY_PASSWORD}" -keyout "${ROOT_CA_KEY}" -subj "${ROOT_CA_SUBJECT}" -out "${ROOT_CA_CERTIFICATE}"
   echo "Putting the certificate commands into certificateCommands.txt"
   echo "Putting the certificate commands into certificateCommands.txt" >> ${BASE_DIR}/ca/"${REALM}"/certificateCommands.txt
   echo "openssl req -verbose -config "${OPENSSL_CONF}" -extensions v3_ca_extensions -batch -x509 -newkey rsa:$BITS -days ${RDAYS} -passout file:"${ROOT_CA_KEY_PASSWORD}" -keyout "${ROOT_CA_KEY}" -subj "${ROOT_CA_SUBJECT}" -out "${ROOT_CA_CERTIFICATE}"" >> certificateCommands.txt
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
	 echo "done."
      fi
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
   openssl req -verbose -config "${OPENSSL_CONF}" -reqexts v3_scep_reqexts -batch -newkey rsa:$BITS -passout file:"${SCEP_KEY_PASSWORD}" -keyout "${SCEP_KEY}" -subj "${SCEP_SUBJECT}" -out "${SCEP_REQUEST}"
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
apt install gnupg*
echo "GnuPG installed."
echo "Done"
echo "Retrieving OpenXPKI package key and verifying."
wget https://packages.openxpki.org/v3/debian/Release.key -O - | apt-key add -
#
echo "Adding OpenXPKI to sources."
echo -e "Types: deb\nURIs: https://packages.openxpki.org/v3/bookworm/\nSuites: bookworm\nComponents: release\nSigned-By: /usr/share/keyrings/openxpki.pgp" > /etc/apt/sources.list.d/openxpki.sources
apt update
PS3="Do you want to install MySQL or MariaDB?   "
select db in MySQL MariaDB Exit; do

    case $db in
      MySQL)
       apt install default-mysql-server libdbd-mysql-perl
       echo "Selected MySQL as your DB Server."
       break
       ;;
      MariaDB)
       apt install mariadb-server libdbd-mariadb-perl
       echo "Selected MariaDB as your DB Server."
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
apt install apache2 libapache2-mod-fcgid
a2enmod fcgid

##Install OpenXPKI
echo "Beginning OpenXPKI installation."
apt install libopenxpki-perl openxpki-cgi-session-driver openxpki-i18n
echo "Showing installed OpenXPKI version."
openxpkiadm version
sleep 3

echo "Do you want to automate the secure database initialization?"
echo "We'll ask for your root password, the database name, user and password."
echo "The details will be placed into the file:  config.d/system/database.yaml"
echo "    Y  |  y  "
read input_secureDB
if [ "${input_secureDB,,}" == "y" ] || [ "${input_secureDB,,}" == "yes" ]; then
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
#    echo -e "What would you like to name your Database?\n"
#    read input_db_name
input_db_name="openxpki"
#    echo -e "What's the username for the database?\n"
#    read input_db_user
input_db_user="openxpki"
#    echo -e "What's the password for the database?\n"
#    read input_db_pass
input_db_pass=`openssl rand 40 | base64`
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

echo "Beginning MariaDB Secure installation..."
sudo mysql -u root -p"${ROOT_PW}" -e "SET PASSWORD FOR root@localhost = PASSWORD('"${ROOT_PW}"');FLUSH PRIVILEGES;"
echo "Removing Anonymous user."
sudo mysql -u root -p"${ROOT_PW}" -e "DELETE FROM mysql.user WHERE User='';"
sudo mysql -u root -p"${ROOT_PW}" -e "DROP USER IF EXISTS ''@'localhost'"
sudo mysql -u root -p"${ROOT_PW}" -e "DROP USER IF EXISTS ''@'$(hostname)'"
echo "Dropped anonymous user."
sudo mysql -u root -p"${ROOT_PW}" -e "DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1');"
echo "Disable remote Root Authentication."
sudo mysql -u root -p"${ROOT_PW}" -e "DROP DATABASE IF EXISTS test"
echo "Dropping test DB"
sudo mysql -u root -p"${ROOT_PW}" -e "FLUSH PRIVILEGES;"
echo -e "Initializing Database...\n"
sudo mysql -u root -p"${ROOT_PW}" -e "CREATE DATABASE IF NOT EXISTS "${input_db_name}" CHARSET utf8;"
echo "Database: ""${input_db_name}"  "created."
sudo mysql -u root -p"${ROOT_PW}" -e "CREATE USER IF NOT EXISTS '"${input_db_user}"'@'localhost' IDENTIFIED BY '"${input_db_pass}"';"
echo "User: ""${input_db_user}"  "created."
sudo mysql -u root -p"${ROOT_PW}" -e "GRANT ALL PRIVILEGES ON "${input_db_name}".* TO '"${input_db_user}"'@'localhost';"
echo "Granting permissions on ""${input_db_name}" "to: ""${input_db_user}"
sudo mysql -u root -p"${ROOT_PW}" -e "FLUSH PRIVILEGES;"
DATABASE_DIR="${BASE_DIR}/config.d/system/database.yaml"
sed -i "s/name: openxpki/name: "${input_db_name}"/" ${DATABASE_DIR}
sed -i "s/user: openxpki/user: "${input_db_user}"/" ${DATABASE_DIR}
sed -i "s@passwd: openxpki@passwd: "${input_db_pass}"@" ${DATABASE_DIR}
fi
echo "Copying database template to Server."
cat /usr/share/doc/libopenxpki-perl/examples/schema-mariadb.sql | mysql -u root -p"${ROOT_PW}" --database  "${input_db_name}"
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
if [ $import_xpki_Inter == "1" ] || [ $import_xpki_Scep == "1" ] || [ $import_xpki_Web == "1" ] || [ $import_xpki_DV == "1" ]; then
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
if [ $import_xpki_DV == "1" ]; then
echo "
    vault:
        label: ${DATAVAULT}
        export: 0
        method: literal
        value: ${v_DATAVAULT_KEY_PASSWORD}
" >> ${BASE_DIR}/config.d/realm/${REALM}/crypto.yaml
fi
if [ $import_xpki_Inter == "1" ]; then
echo "
    ca-signer:
        label: ${ISSUING_CA}
        export: 0
        method: literal
        value: ${v_ISSUING_CA_KEY_PASSWORD}
" >> ${BASE_DIR}/config.d/realm/${REALM}/crypto.yaml
fi
if [ $import_xpki_Scep == "1" ]; then
echo "
    scep:
        label: ${SCEP}
        export: 0
        method: literal
        value: ${v_SCEP_KEY_PASSWORD}
" >> ${BASE_DIR}/config.d/realm/${REALM}/crypto.yaml
fi
else
 echo -e "\nThis config file has not been edited by this script. Assuming it's a new copy from the "
 echo -e "from the Realm.Tpl directory, we're going to prep it for operation. "
 # Have to keep the first sed command at the top because we're counting lines.
 sed -i '53 s|default:|# default:|g' ${REALM_YAML}
 sed -i '43d' ${REALM_YAML}
 sed -i '42 a\    key: ${BASE_DIR}/local/keys/[% PKI_REALM %]/[% ALIAS %].pem' ${REALM_YAML}
 sed -i -z 's/import:/# import:/1' ${REALM_YAML}
 sed -i -z 's/secret: default/# secret: default/' ${REALM_YAML}
 sed -i '/ca-signer:/a\    secret: ca-signer' ${REALM_YAML} # Add version number?
 sed -i '/LibSCEP/a\    secret: scep' ${REALM_YAML} # Add version number?
 sed -i '/vault:/a\    secret: vault' ${REALM_YAML} # Add version number?
 sed -i 's@key: ${BASE_DIR}/local/keys/[% ALIAS %].pem@key: ${BASE_DIR}/local/keys/[% PKI_REALM %]/[% ALIAS %].pem@' ${REALM_YAML}
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
if [ $import_xpki_DV == "1" ]; then
echo "
    vault:
        label: ${DATAVAULT}
        export: 0
        method: literal
        value: ${v_DATAVAULT_KEY_PASSWORD}
" >> ${BASE_DIR}/config.d/realm/${REALM}/crypto.yaml
fi
if [ $import_xpki_Inter == "1" ]; then
echo "
    ca-signer:
        label: ${ISSUING_CA}
        label: ${ISSUING_CA}
        export: 0
        method: literal
        value: ${v_ISSUING_CA_KEY_PASSWORD}
" >> ${BASE_DIR}/config.d/realm/${REALM}/crypto.yaml
fi
if [ $import_xpki_Scep == "1" ]; then
echo "
    scep:
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
openxpkiadm_root () {
# Importing Root CA
echo -e "\nImporting Root Certificate.."
echo "openxpkiadm certificate import --file "${ROOT_CA_CERTIFICATE}" --realm "${REALM}"" >> openxpkiadmCommands.txt
openxpkiadm certificate import --file "${ROOT_CA_CERTIFICATE}" --realm "${REALM}"
}

openxpkiadm_dv () {
# Importing Datavault
# Should look at grep'ing output of the openxpkiadm list command to see if the DV key is present before importing another.
# Can turn this into a "Require user input" option. Use in tandem with Case we're building above for generating certs.
# Can echo value into a variable for each case choice and run the openxpkictl commands if the values are/aren't present.
# This can also apply to copying over the Datavault key to a new location.
echo -e "\nImporting Datavault Certificate: ${DATAVAULT_CERTIFICATE}"
echo "openxpkiadm certificate import --file "${DATAVAULT_CERTIFICATE}"" >> openxpkiadmCommands.txt
openxpkiadm certificate import --file "${DATAVAULT_CERTIFICATE}"
echo -e "\nRegistering Datavault Certificate ${DATAVAULT_CERTIFICATE} as datasafe token.."
echo "openxpkiadm alias --file "${DATAVAULT_CERTIFICATE}" --realm "${REALM}" --token datasafe" >> openxpkiadmCommands.txt
openxpkiadm alias --file "${DATAVAULT_CERTIFICATE}" --realm "${REALM}" --token datasafe
}

# Keys NEED to be added to keys directory before these commands happen or the import fails
openxpkiadm_issue () {
echo "Importing Intermediate Certificate and put key in keys directory.."
echo "openxpkiadm alias --file "${ISSUING_CA_CERTIFICATE}" --realm "${REALM}" --token certsign --key ${ISSUING_CA_KEY}" >> openxpkiadmCommands.txt
openxpkiadm alias --file "${ISSUING_CA_CERTIFICATE}" --realm "${REALM}" --token certsign --key ${ISSUING_CA_KEY}
}

# Keys NEED to be added to keys directory before these commands happen or the import fails
openxpkiadm_scep () {
echo "openxpkiadm alias --file "${SCEP_CERTIFICATE}" --realm "${REALM}" --token scep  --key "${SCEP_KEY}"" >> openxpkiadmCommands.txt
openxpkiadm alias --file "${SCEP_CERTIFICATE}" --realm "${REALM}" --token scep  --key "${SCEP_KEY}"
echo -e "Done.\n"
}

apache2_setup () {
# Setup the Webserver
a2enmod ssl rewrite headers
a2ensite openxpki
a2dissite 000-default default-ssl

# if you're regenerating SSL Keys, then you need to delete this chain folder, or edit this if to include some user input
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
    service apache2 restart
fi

openssl x509 -in "${ROOT_CA_CERTIFICATE}" -out /etc/ssl/certs/Root.pem
openssl x509 -in "${ISSUING_CA_CERTIFICATE}" -out /etc/ssl/certs/Inter.pem
c_rehash /etc/ssl/certs
update-ca-certificates
}

import_certificates () {
if [ $import_xpki_Root == "1" ] || [ $import_xpki_DV == "1" ]; then
echo "Stopping OpenXPKI if it's running.."
if pgrep "openxpki" > /dev/null
then
    openxpkictl stop
fi
fi
if [ $import_xpki_Root == "1" ]; then
    openxpkiadm_root
fi
if [ $import_xpki_DV == "1" ]; then
    openxpkiadm_dv
fi

# Start OpenX before importing the tokens
echo -e "\nStarting server before running import ... "
openxpkictl start

if [ $import_xpki_Inter == "1" ]; then
   openxpkiadm_issue
fi
if [ $import_xpki_Scep == "1" ]; then
   openxpkiadm_scep
fi
if [ $import_xpki_Web == "1" ]; then
   apache2_setup
fi

echo -e "\nOpenXPKI configuration should be complete and server should be running..."
}

add_new_user () {
echo "Enter new user name."
echo ""
read v_new_user
echo "Enter user password."
echo ""
read v_new_user_pass
salt=$(openssl rand -base64 3)
echo $salt
v_new_user_saltPass=$((echo -n '$password$salt' | openssl sha1 -binary)'$salt' | openssl enc -base64)
echo $v_new_user_saltPass
# Add new user details to the userdb or admindb
if [ $v_new_user_role == "CA" ] || [ $v_new_user_role == "RA" ]; then
	userFile='/home/pkiadm/admindb.yaml'
	if [ -z $userFile ]; then
    touch $userFile
	fi
	echo $v_new_user $v_new_user_saltPass $v_new_user_role 
	# echo "
	# $v_new_user:
		# digest: "{SSHA}"$v_new_user_saltPass
		# role: $v_new_user_role Operator
		# "
fi
if [ $v_new_user_role == "user" ]; then
	userFile='/home/pkiadm/userdb.yaml'
	if [ -z "$userFile" ]; then
    touch $userFile
	fi
	echo >>"
	$v_new_user:
		digest: "{SSHA}$v_new_user_saltPass"
		role: $v_new_user_role
		"
fi
}

create_new_user () {
PS3="Select user role.  "
select role in Certificate_Authority Registration_Authority User Quit; do
case $role in
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

echo -e "\nFollow the prompts for creating certificates ... "
import_xpki_Scep="0"
import_xpki_Root="0"
import_xpki_Inter="0"
import_xpki_DV="0"
import_xpki_Web="0"

PS3="Select the operation: "
select opt in Install_OpenXPKI Create_Realm Generate_new_Root_CA Generate_new_Intermediate_CA Generate_new_Datavault_Certificate Generate_new_Scep_Certificate Generate_new_Web_Certificate Add_Users Quit; do
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
 import_xpki_Scep="1"
 check_installed
 question_realm
 question_ou
 question_rootVer
 question_interVer
 question_scepVer
 question_webVer
 question_country
 question_state
 question_locality
 confirm_input
 populate_files
 define_certificates  #123
 define_openssl
 confirm_run
 gen_RootCA
 gen_InterCA
 gen_ScepCert
 gen_DatavaultCert
 gen_WebCert
 echo "Certificates created, Continuing"
 transfer_keys_files
 import_certificates
## openx command
 break
 ;;
Generate_new_Root_CA)						## Generate_new_Root_CA
 import_xpki_Root="1"
 import_xpki_Inter="0"
 import_xpki_DV="0"
 import_xpki_Web="0"
 import_xpki_Scep="0"
 check_installed
 question_realm
 question_ou
 question_rootVer
 question_country
 question_state
 question_locality
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
 check_installed
 question_realm
 question_ou
 question_interVer
 question_country
 question_state
 question_locality
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
 import_xpki_Scep="1"
 check_installed
 question_realm
 question_ou
 question_scepVer
 question_country
 question_state
 question_locality
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
Generate_new_Web_Certificate)					## Generate_new_Web_Certificate
 import_xpki_Root="0"
 import_xpki_Inter="0"
 import_xpki_DV="0"
 import_xpki_Web="1"
 import_xpki_Scep="0"
 check_installed
 question_realm
 question_ou
 question_webVer
 question_country
 question_state
 question_locality
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
