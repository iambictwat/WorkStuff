#!/bin/sh -e
# ESET PROTECT
# Copyright (c) 1992-2020 ESET, spol. s r.o. All Rights Reserved

cleanup_file="$(mktemp -q)"
finalize()
{
  set +e
  if test -f "$cleanup_file"
  then
    while read f
    do
      rm -f "$f"
    done < "$cleanup_file"
    rm -f "$cleanup_file"
  fi
}

trap 'finalize' HUP INT QUIT TERM EXIT

eraa_server_hostname="SBS-2012-TEST.cl.local"
eraa_server_port="2222"
eraa_server_company_name=""
eraa_peer_cert_b64="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"
eraa_peer_cert_pwd=""
eraa_ca_cert_b64="MIIDITCCAgmgAwIBAgIQRIjga2UbpZBLmhlt0DAalTANBgkqhkiG9w0BAQUFADApMScwJQYDVQQDEx5TZXJ2ZXIgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkwHhcNMTkwOTE2MjMwMDAwWhcNMjkwOTE3MjMwMDAwWjApMScwJQYDVQQDEx5TZXJ2ZXIgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDFOiYh/S+L9YqwDiVwglWCbovb+OU456VfH/bAenzDHSVrRFOYOhSauRfOspl5sWTvXoYSbbbULsFknpEFAAlkkZ/fb2A8piYdxabHGtOGh1nT7ujoDJr9nHHVr5WzMLi+dJLtx9eLdZsSUtVKnd3kEOWIOWGrqAqAdItYv6kK+fJ+v9aus+alyUhXOYZOF59RB+23NnvPuO/Y516kJHtKpLhxVcwZn2BKEblAdefTFy64SCZv42rHlwQzt6GDkimQAVnxBDlWJQEpT0Gz4XAiUt/2/lF8a+du79zzL3lUcAm5r8H0otOcNe4Oy8Rng38bETLCihe7iJzzQ45WVAl3AgMBAAGjRTBDMA4GA1UdDwEB/wQEAwIBBjASBgNVHRMBAf8ECDAGAQH/AgEAMB0GA1UdDgQWBBSQzaDO7L+5IpDJJNqlJzBHKVsdhDANBgkqhkiG9w0BAQUFAAOCAQEAh9mgIpETARaEW98QyW8gXpRt5DPbznGDGyj0Sc/K0P5hXNDqW7F//9fF7PUACItmuO+xcu4X8p9vI9xgV7J3rxb7arIo7LKRKsfP9bDTM18J3Gj9OkhLJCLS32Igv1zFEftiaxiXrzCWIveObyydJWQuGmlAZhnn4SYmmgosK65A1E/4F7JBpi2iShjU1N1JzlXtA8LQXE4XXtPoEtt374MU+ts1DcP1imx/L4MWZ+R/1pEP4Dx67OBOuIVbr3QpZrak6NuMiXX+nDuAZOY7INotsV4xczjbeeoMINRKizzyc9pb8u60MW/h7LnNeAwLsnxYn1bHZzWQNTfLCeUPhQ=="
eraa_product_uuid=""
eraa_initial_sg_token=""
eraa_policy_data=""

arch=$(uname -m)
eraa_installer_url="http://repository.eset.com/v1/com/eset/apps/business/era/agent/v8/8.0.2216.0/agent_linux_i386.sh"
eraa_installer_checksum="7994d7c3199ed817ea7ff84f22a05a2d2585a233"

if $(echo "$arch" | grep -E "^(x86_64|amd64)$" 2>&1 > /dev/null)
then
    eraa_installer_url="http://repository.eset.com/v1/com/eset/apps/business/era/agent/v8/8.0.2216.0/agent_linux_x86_64.sh"
    eraa_installer_checksum="756004e83b290c45ef4a482207d0d2759e68b6a7"
fi

echo "ESET Management Agent live installer script. Copyright © 1992-2020 ESET, spol. s r.o. - All rights reserved."

if test ! -z $eraa_server_company_name
then
  echo " * CompanyName: $eraa_server_company_name"
fi
echo " * Hostname: $eraa_server_hostname"
echo " * Port: $eraa_server_port"
echo " * Installer: $eraa_installer_url"
echo

if test -z $eraa_installer_url
then
  echo "No installer available for '$arch' arhitecture."
  exit 1
fi

local_cert_path="$(mktemp -q -u)"
echo $eraa_peer_cert_b64 | base64 -d > "$local_cert_path" && echo "$local_cert_path" >> "$cleanup_file"

if test -n "$eraa_ca_cert_b64"
then
  local_ca_path="$(mktemp -q -u)"
  echo $eraa_ca_cert_b64 | base64 -d > "$local_ca_path" && echo "$local_ca_path" >> "$cleanup_file"
fi


local_installer="$(mktemp -q -u)"

eraa_http_proxy_value="http://192.168.50.240:3128"

echo "Downloading ESET Management Agent installer..."

if test -n "$eraa_http_proxy_value"
then
  export use_proxy=yes
  export http_proxy="$eraa_http_proxy_value"
  (wget --connect-timeout 300 --no-check-certificate -O "$local_installer" "$eraa_installer_url" || wget --connect-timeout 300 --no-proxy --no-check-certificate -O "$local_installer" "$eraa_installer_url" || curl --fail --connect-timeout 300 -k "$eraa_installer_url" > "$local_installer") && echo "$local_installer" >> "$cleanup_file"
else
  (wget --connect-timeout 300 --no-check-certificate -O "$local_installer" "$eraa_installer_url" || curl --fail --connect-timeout 300 -k "$eraa_installer_url" > "$local_installer") && echo "$local_installer" >> "$cleanup_file"
fi

if test ! -s "$local_installer"
then
   echo "Failed to download installer file"
   exit 2
fi

echo -n "Checking integrity of installer script " && echo "$eraa_installer_checksum  $local_installer" | sha1sum -c

chmod +x "$local_installer"

local_migration_list="$(mktemp -q -u)"
tee "$local_migration_list" 2>&1 > /dev/null << __LOCAL_MIGRATION_LIST__

__LOCAL_MIGRATION_LIST__
test $? = 0 && echo "$local_migration_list" >> "$cleanup_file"

for dir in /sys/class/net/*/
do
    if test -f "$dir/address"
    then
        grep -E '00:00:00:00:00:00' "$dir/address" > /dev/null || macs="$macs $(sed 's/\://g' "$dir/address" | awk '{print toupper($0)}')"
    fi
done

while read line
do
    if test -n "$macs" -a -n "$line"
    then
        mac=$(echo $line | awk '{print $1}')
        uuid=$(echo $line | awk '{print $2}')
        lsid=$(echo $line | awk '{print $3}')
        if $(echo "$macs" | grep "$mac" > /dev/null)
        then
            if test -n "$mac" -a -n "$uuid" -a -n "$lsid"
            then
                additional_params="--product-guid $uuid --log-sequence-id $lsid"
                break
            fi
        fi
    fi
done < "$local_migration_list"

command -v sudo > /dev/null && usesudo="sudo -E" || usesudo=""

export _ERAAGENT_PEER_CERT_PASSWORD="$eraa_peer_cert_pwd"

echo
echo Running installer script $local_installer
echo

$usesudo /bin/sh "$local_installer"\
   --skip-license \
   --hostname "$eraa_server_hostname"\
   --port "$eraa_server_port"\
   --cert-path "$local_cert_path"\
   --cert-password "env:_ERAAGENT_PEER_CERT_PASSWORD"\
   --cert-password-is-base64\
   --initial-static-group "$eraa_initial_sg_token"\
   --proxy-hostname '192.168.50.240' --proxy-port 3128 \
   --disable-imp-program\
   $(test -n "$local_ca_path" && echo --cert-auth-path "$local_ca_path")\
   $(test -n "$eraa_product_uuid" && echo --product-guid "$eraa_product_uuid")\
   $(test -n "$eraa_policy_data" && echo --custom-policy "$eraa_policy_data")\
   $additional_params
