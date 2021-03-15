# OpenVPN-X-LDAP-Usage-Logging

Script matches LDAP authenticated username to OpenVPN clients metrics stored in the /var/log/openvpn/status.log log file.

# Requirements

Created for Ubuntu 18.04 hosting OpenVPN server with LDAP plugin (https://github.com/threerings/openvpn-auth-ldap) for domain account authentication

Meant to be run on a Ubuntu Machine hosting an OpenVPN server

Requires InfluxDB server to be running inorder to log data.



# Commandline Arguments
Using the commandline argument "status", it will output the current users to stdout in a table format

Using the commandline argument "log", it will send current users and usage data to influxdb server.
