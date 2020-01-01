#!/bin/bash



############################################################################################
# Print usage
############################################################################################
usage() {
cat <<-EOF

This utility registers/un-registers HDB resource with Cockpit.

Usage:
   $base_name -action <register|unregister|check|change_pwd|config_proxy> [options]

   -action <register|unregister|check|change_pwd|config_proxy>
           register                Register resource to Cockpit
           unregister              Unregister resource from Cockpit
           check                   Check registered resource
           change_pwd              Change telemetry technical user password
           config_proxy            Configure proxy with Cockpit

   -h                              Print this help

   Register options
   ----------------
   -u    <system_admin_user_name>     System administrator user name
   -p    <system_admin_user_password> System administrator user password
   -xsau <xsa_admin_user_name>        XSA administrator user name
   -xsap <xsa_admin_user_password>    XSA administrator user password
   -tu  <telemetry_user_name>      Telemetry technical user name
   -tp  <telemetry_user_password>  Telemetry technical user password

   -i   <instance number>          HANA database instance number.
   -d   <database_name>            Database name. Default is "SystemDB".
   -on  <system_owner_name>        System owner name. Default is <login>.
   -oe  <system_owner_email>       System owner Email. Default is <login>@<local_host>.
   -od  <system_owner_details>     System owner details. Default is "Sample details".
   -s   <space>                    Space name. Default is "SAP".
   -sj  <"true","false">           Use encryption for JDBC connection.  Default is "true".
   -sc  <"true","false">           Use encrypted SAPControl.  Default is "true".
   -vc  <"true","false">           Validate server certificate.  Default is "true".
   -ch  <certificateHost>          Certificate host.  Default is <local_host>.

   Un-register options
   -------------------
   -u    <system_admin_user_name>     System administrator user name
   -p    <system_admin_user_password> System administrator user password
   -xsau <xsa_admin_user_name>        XSA administrator user name
   -xsap <xsa_admin_user_password>    XSA administrator user password

   -d  <database_name>             Database name. Default is "SystemDB".
   -s  <space>                     Space name. Default is "SAP".

   Check options
   -------------
   -xsau <xsa_admin_user_name>        XSA administrator user name
   -xsap <xsa_admin_user_password>    XSA administrator user password

   -d  <database_name>             Database name. Default is "SystemDB".
   -s  <space>                     Space name. Default is "SAP".

   Change password options
   -----------------------
   -u    <system_admin_user_name>     System administrator user name
   -p    <system_admin_user_password> System administrator user password
   -xsau <xsa_admin_user_name>        XSA administrator user name
   -xsap <xsa_admin_user_password>    XSA administrator user password

   -tu  <telemetry_user_name>      Telemetry technical user name
   -tp  <telemetry_user_password>  Telemetry technical user password
   -ntp <new_telemetry_user_password>  New Telemetry technical user password

   -i   <instance number>          HANA database instance number.
   -d   <database_name>            Database name. Default is "SystemDB".
   -on  <system_owner_name>        System owner name. Default is <login>.
   -oe  <system_owner_email>       System owner Email. Default is <login>@<local_host>.
   -od  <system_owner_details>     System owner details. Default is "Sample details".
   -s   <space>                    Space name. Default is "SAP".

   Set proxy options
   -----------------
   -proxy_action <enable_http|disable_http|enable_network|disable_network>
                                   Enable or disable HTTP(S)/network proxy

   -u    <system_admin_user_name>     System administrator user name
   -p    <system_admin_user_password> System administrator user password
   -xsau <xsa_admin_user_name>        XSA administrator user name
   -xsap <xsa_admin_user_password>    XSA administrator user password

   -d   <database_name>            Database name. Default is "SystemDB".
   -s   <space>                    Space name. Default is "SAP".

   -q                              Use system proxy host/port if available.
                                   Do not prompt proxy host/port.

   -ph  <proxy_host>               Proxy host
   -pp  <proxy_port>               Proxy port
   -nph <no_proxy_hosts>           Comma separated list of hosts that do not
                                   need proxy.

EOF
}

############################################################################################
# Get SID from current user login <sid>adm
############################################################################################
getSID() {
	local me=`whoami`
	if echo $me | grep 'adm$' >& /dev/null; then
		sid=`echo $me | cut -c1-3 | tr '[:lower:]' '[:upper:]'`
		if [ ! -d /hana/shared/${sid} ]; then
			echo "You login as \"$me\"; but SID \"${sid}\" (/hana/shared/${sid}) does not exist."
			exit 1
		fi
	else
		echo "You need to run this from HANA administrator user \"<sid>adm\"."
		exit 1
	fi
}

############################################################################################
# Check if executables in path
############################################################################################
checkEnv() {
	if ! which xs >& /dev/null; then
		echo "Cannot find \"xs\" executable in path.  Check if XSA is correctly installed."
		exit 1
	fi
}

############################################################################################
# Wait all Cockpit apps started
############################################################################################
waitCockpitAppsStarted() {
	echo "Check/Wait for Cockpit app to start..."
	xs wait-for-apps --timeout 13600 --apps "cockpit-adminui-svc,cockpit-admin-web-app,cockpit-hdb-svc,cockpit-persistence-svc,cockpit-collection-svc,cockpit-telemetry-svc,cockpit-xsa-svc"
	if [ $? -ne 0 ]; then
		echo
		echo "Please start required Cockpit apps and rerun ${base_name}."
		exit 1
	fi
}

isTenantDbStarted() {
	local hdbinfo_output=$(HDB info)
	echo ${hdbinfo_output} | grep hdbindexserver >& /dev/null
}

############################################################################################
# Get clientid, clientsecret, uaa_url, and adminui_url
############################################################################################
getClientid_secret_url() {
	echo "Get client ID, client secret key, UAA URL, ADMINUI, ADMIN_WEB_APP URL..."

	create_tmp_file
	xs login -u $xsa_admin -p $xsa_admin_pwd -s $space >> ${out_tmp_file} 2>&1
	api_endpoint=`grep "API endpoint:" ${out_tmp_file}`
	if [ -z "$api_endpoint" ]; then
		cat ${out_tmp_file}
		echo
		echo "ERROR: Failed to get API endpoint"
		remove_tmp_file
		exit 1
	fi

	create_tmp_file
	xs env cockpit-hdb-svc >> ${out_tmp_file} 2>&1
	clientid=`cat ${out_tmp_file} | grep '^[[:space:]]*"clientid' | awk '/clientid/{print $NF}' | sed 's/[^"]*"\([^"]*\).*/\1/'`
	clientsecret=`cat ${out_tmp_file} | awk '/clientsecret/{print $NF}' | sed 's/[^"]*"\([^"]*\).*/\1/'`
	uaa_url=`cat ${out_tmp_file} | awk '/uaa-security/{print $NF}' | sed 's/[^"]*"\([^"]*\).*/\1/'`
	if [ -z "${clientid}" -o -z "${clientsecret}" -o -z "${uaa_url}" ]; then
		cat ${out_tmp_file}
		echo
		echo "ERROR: Failed to get client ID, secret key, and/or UAA URL"
		remove_tmp_file
	        exit 1
	fi

	create_tmp_file
	xs apps >> ${out_tmp_file} 2>&1
	adminui_url=`cat ${out_tmp_file} | grep cockpit-adminui-svc | awk -F' ' '{print $NF}'`
	if [ -z "${adminui_url}" ]; then
		cat ${out_tmp_file}
		echo
		echo "ERROR: Failed to get admin URL"
		remove_tmp_file
		exit 1
	fi

	admin_web_app_url=`cat ${out_tmp_file} | grep cockpit-admin-web-app | awk -F' ' '{print $NF}'`
	if [ -z "${admin_web_app_url}" ]; then
		cat ${out_tmp_file}
		echo
		echo "ERROR: Failed to get Cockpit admin web app URL"
		remove_tmp_file
		exit 1
	fi

	ls_url=`cat ${out_tmp_file} | grep cockpit-landscape-svc | awk -F' ' '{print $NF}'`
	if [ -z "${ls_url}" ]; then
		cat ${out_tmp_file}
		echo
		echo "ERROR: Failed to get Cockpit-landscape-svc URL"
		remove_tmp_file
		exit 1
	fi

	hdb_url=`cat ${out_tmp_file} | grep cockpit-hdb-svc | awk -F' ' '{print $NF}'`
	if [ -z "${hdb_url}" ]; then
		cat ${out_tmp_file}
		echo
		echo "ERROR: Failed to get Cockpit-hdb-svc URL"
		remove_tmp_file
		exit 1
	fi

        persistence_url=`cat ${out_tmp_file} | grep cockpit-persistence-svc | awk -F' ' '{print $NF}'`
        if [ -z "${persistence_url}" ]; then
                cat ${out_tmp_file}
                echo
                echo "ERROR: Failed get Cockpit persistence URL"
                remove_tmp_file
                exit 1
        fi

        xsa_url=`cat ${out_tmp_file} | grep cockpit-xsa-svc | awk -F' ' '{print $NF}'`
        if [ -z "${xsa_url}" ]; then
                cat ${out_tmp_file}
                echo
                echo "ERROR: Failed to get Cockpit-xsa-svc URL"
                remove_tmp_file
                exit 1
        fi

        tel_url=`cat ${out_tmp_file} | grep cockpit-telemetry-svc | awk -F' ' '{print $NF}'`
        if [ -z "${tel_url}" ]; then
                cat ${out_tmp_file}
                echo
                echo "ERROR: Failed to get Cockpit-telemetry-svc URL"
                remove_tmp_file
                exit 1
        fi

	remove_tmp_file
}

############################################################################################
# Get authentication token from UAA
############################################################################################
getAccessToken() {
	echo "Get authentication token from UAA..."

	export LD_LIBRARY_PATH=
	curl -s -u $clientid:$clientsecret --insecure -X POST --data-urlencode "client_id=$clientid" --data-urlencode "client_secret=$clientsecret" --data-urlencode "grant_type=password" --data-urlencode "username=$xsa_admin" --data-urlencode "password=$xsa_admin_pwd" --data-urlencode "response_type=token" "$uaa_url/oauth/token" >> ${out_tmp_file} 2>&1
	access_token=`cat ${out_tmp_file} | grep access_token | sed 's/{"access_token":"\(.*\)/\1/' | sed 's/","token_type".*//'`
	if [ -z "$access_token" ]; then
		cat ${out_tmp_file}
		echo
		echo "ERROR: Failed get authentication token from UAA"
		exit 1
	fi
	export LD_LIBRARY_PATH="$SAVE_LD_PATH"
}

# Create table _SYS_TELEMETRY.HXE_INSTALLATION_TYPE

createTelemetryTable() {
        local installType=""
        if [ -f /usr/sap/${sid}/SYS/global/hdb/hxe_info.txt ]; then
                installType=`grep '^INSTALL_TYPE.*=' /usr/sap/${sid}/SYS/global/hdb/hxe_info.txt | cut -d'=' -f2`
                installType=`trim ${installType}`
        fi

        execSQL ${instance_number} ${db_name} ${system_admin} ${system_admin_pwd} "SELECT COUNT(*) FROM TABLES WHERE SCHEMA_NAME='_SYS_TELEMETRY' and TABLE_NAME='HXE_INSTALLATION_TYPE_BASE'"
        SQL_OUTPUT=`trim ${SQL_OUTPUT}`
        if [ "$SQL_OUTPUT" != "1" ]; then
                echo "Create table _SYS_TELEMETRY.HXE_INSTALLATION_TYPE_BASE..."
                execSQL ${instance_number} ${db_name} ${system_admin} ${system_admin_pwd} "CREATE TABLE _SYS_TELEMETRY.HXE_INSTALLATION_TYPE_BASE (SNAPSHOT_ID TIMESTAMP, TYPE VARCHAR(10))"
        else
		echo "Truncate table _SYS_TELEMETRY.HXE_INSTALLATION_TYPE_BASE..."
                execSQL ${instance_number} ${db_name} ${system_admin} ${system_admin_pwd} "TRUNCATE TABLE _SYS_TELEMETRY.HXE_INSTALLATION_TYPE_BASE"
        fi

	# Drop table _SYS_TELEMETRY.HXE_INSTALLATION_TYPE and recreate as a view
	execSQL ${instance_number} ${db_name} ${system_admin} ${system_admin_pwd} "SELECT COUNT(*) FROM TABLES WHERE SCHEMA_NAME='_SYS_TELEMETRY' and TABLE_NAME='HXE_INSTALLATION_TYPE'"
	SQL_OUTPUT=`trim ${SQL_OUTPUT}`
	if [ "$SQL_OUTPUT" == "1" ]; then
		echo "Drop table _SYS_TELEMETRY.HXE_INSTALLATION_TYPE..."
		execSQL ${instance_number} ${db_name} ${system_admin} ${system_admin_pwd} "DROP TABLE _SYS_TELEMETRY.HXE_INSTALLATION_TYPE"
	fi
	execSQL ${instance_number} ${db_name} ${system_admin} ${system_admin_pwd} "SELECT COUNT(*) FROM VIEWS WHERE SCHEMA_NAME='_SYS_TELEMETRY' and VIEW_NAME='HXE_INSTALLATION_TYPE'"
	SQL_OUTPUT=`trim ${SQL_OUTPUT}`
	if [ "$SQL_OUTPUT" != "1" ]; then
		echo "Create view _SYS_TELEMETRY.HXE_INSTALLATION_TYPE..."
		execSQL ${instance_number} ${db_name} ${system_admin} ${system_admin_pwd} "CREATE VIEW _SYS_TELEMETRY.HXE_INSTALLATION_TYPE (SNAPSHOT_ID, TYPE) AS SELECT SNAPSHOT_ID, TYPE FROM _SYS_TELEMETRY.HXE_INSTALLATION_TYPE_BASE WITH READ ONLY"
	fi

	execSQL ${instance_number} ${db_name} ${system_admin} ${system_admin_pwd} "INSERT INTO _SYS_TELEMETRY.HXE_INSTALLATION_TYPE_BASE (SNAPSHOT_ID, TYPE) VALUES (CURRENT_UTCTIMESTAMP, '${installType}')"
	execSQL ${instance_number} ${db_name} ${system_admin} ${system_admin_pwd} "DELETE FROM _SYS_TELEMETRY.CONFIGURATION WHERE COLLECTOR_NAME = 'HXE_INSTALLATION_TYPE'"
	# Fix bug 219156: HXE Binary install HXE sp40 failed on register cockpit 
	execSQL ${instance_number} ${db_name} ${system_admin} ${system_admin_pwd} "INSERT INTO _SYS_TELEMETRY.CONFIGURATION (COLLECTOR_ID, COLLECTOR_NAME, COLLECTOR_STATUS, COLLECTOR_VERSION, BASE_COLLECTOR_ID, COLLECTION_INTERVAL, DEFAULT_COLLECTION_INTERVAL, MIN_COLLECTION_INTERVAL, MAX_COLLECTION_INTERVAL) VALUES (4099, 'HXE_INSTALLATION_TYPE', true, 1, 0, 1, 1, 1, 12)"
}

dropTelemetryTable() {
	execSQL ${instance_number} ${db_name} ${system_admin} ${system_admin_pwd} "SELECT COUNT(*) FROM TABLES WHERE SCHEMA_NAME='_SYS_TELEMETRY' and TABLE_NAME='HXE_INSTALLATION_TYPE'"
	SQL_OUTPUT=`trim ${SQL_OUTPUT}`
	if [ "$SQL_OUTPUT" == "1" ]; then
		echo "Drop table _SYS_TELEMETRY.HXE_INSTALLATION_TYPE..."
		execSQL ${instance_number} ${db_name} ${system_admin} ${system_admin_pwd} "DROP TABLE _SYS_TELEMETRY.HXE_INSTALLATION_TYPE"
	fi

	execSQL ${instance_number} ${db_name} ${system_admin} ${system_admin_pwd} "SELECT COUNT(*) FROM VIEWS WHERE SCHEMA_NAME='_SYS_TELEMETRY' and VIEW_NAME='HXE_INSTALLATION_TYPE'"
	SQL_OUTPUT=`trim ${SQL_OUTPUT}`
	if [ "$SQL_OUTPUT" == "1" ]; then
		echo "Drop view _SYS_TELEMETRY.HXE_INSTALLATION_TYPE..."
		execSQL ${instance_number} ${db_name} ${system_admin} ${system_admin_pwd} "DROP VIEW _SYS_TELEMETRY.HXE_INSTALLATION_TYPE"
	fi

        execSQL ${instance_number} ${db_name} ${system_admin} ${system_admin_pwd} "SELECT COUNT(*) FROM TABLES WHERE SCHEMA_NAME='_SYS_TELEMETRY' and TABLE_NAME='HXE_INSTALLATION_TYPE_BASE'"
        SQL_OUTPUT=`trim ${SQL_OUTPUT}`
        if [ "$SQL_OUTPUT" == "1" ]; then
                echo "Drop table _SYS_TELEMETRY.HXE_INSTALLATION_TYPE_BASE"
                execSQL ${instance_number} ${db_name} ${system_admin} ${system_admin_pwd} "DROP TABLE _SYS_TELEMETRY.HXE_INSTALLATION_TYPE_BASE"
        fi

	execSQL ${instance_number} ${db_name} ${system_admin} ${system_admin_pwd} "DELETE FROM _SYS_TELEMETRY.CONFIGURATION WHERE COLLECTOR_NAME = 'HXE_INSTALLATION_TYPE'"
}

############################################################################################
# Register resource
############################################################################################
registerResource() {
	echo "Register resource..."

	local db_name_lc=`echo "${db_name}" | tr '[:upper:]' '[:lower:]'`
	if [ "${db_name_lc}" == "systemdb" ]; then
		databaseType="SystemDB"
	else
		if ! isTenantDbStarted; then
			echo "Cannot register \"$db_name\" database because it does not exist or started."
			exit 1
		fi

		databaseType="Tenant"
	fi
        createTelemetryTable

	local need_restage=0
	if xs trusted-certificates | grep "SYSTEM_CERT" >& /dev/null; then
		create_tmp_file
		echo "Delete trusted certificate SYSTEM_CERT..."
		xs untrust-certificate SYSTEM_CERT >> ${out_tmp_file} 2>&1
		if [ $? -ne 0 ]; then
			cat ${out_tmp_file}
			remove_tmp_file
			exit 1
		fi
                remove_tmp_file
		need_restage=1
	fi

	if [[ "${validateCertificate}" =~ ^[T,t][R,r][U,u][E,e]$ ]]; then
		rm -rf /tmp/cert.$$
		touch /tmp/cert.$$
		chmod 600 /tmp/cert.$$
		if [ -z "$certificateHost" ]; then
			certificateHost=`hostname -f`
		fi

		export LD_LIBRARY_PATH=
		/usr/bin/openssl s_client -connect ${certificateHost}:3${instance_number}13 -showcerts -tls1 2>&1 | sed -n -e '/BEGIN\ CERTIFICATE/,/END\ CERTIFICATE/ p' >> /tmp/cert.$$ 2>&1
		if ! grep -q "BEGIN CERTIFICATE" /tmp/cert.$$ >& /dev/null; then
			cat /tmp/cert.$$
			rm -rf /tmp/cert.$$
			echo "Fail to retrieve certificate."
			exit 1
		fi
		export LD_LIBRARY_PATH="$SAVE_LD_PATH"

		create_tmp_file
		echo "Add trusted certificate SYSTEM_CERT..."
		xs trust-certificate SYSTEM_CERT -c /tmp/cert.$$ >> ${out_tmp_file} 2>&1
		if ! grep -q "TIP: Restart the SAP XS Controller" ${out_tmp_file} >& /dev/null; then
			cat ${out_tmp_file}
			rm -rf /tmp/cert.$$
			remove_tmp_file
			echo "Fail to add trusted certificate."
			exit 1
		fi
                remove_tmp_file
		need_restage=1

                rm -rf /tmp/cert.$$
        fi

	if [ $need_restage -eq 1 ]; then
		create_tmp_file
		echo "Restage cockpit-hdb-svc..."
		xs restage cockpit-hdb-svc >> ${out_tmp_file} 2>&1
		if [ $? -ne 0 ]; then
			cat ${out_tmp_file}
			remove_tmp_file
			rm -rf /tmp/cert.$$
			exit 1
		fi
                remove_tmp_file

		create_tmp_file
		echo "Restart cockpit-hdb-svc..."
		xs restart cockpit-hdb-svc >> ${out_tmp_file} 2>&1
		if [ $? -ne 0 ]; then
			cat ${out_tmp_file}
			remove_tmp_file
			rm -rf /tmp/cert.$$
			exit 1
		fi
                remove_tmp_file

                create_tmp_file
                echo "Restage hrtt-service..."
                xs restage hrtt-service >> ${out_tmp_file} 2>&1
                if [ $? -ne 0 ]; then
                        cat ${out_tmp_file}
                        remove_tmp_file
                        rm -rf /tmp/cert.$$
                        exit 1
                fi
                remove_tmp_file

                create_tmp_file
                echo "Restart hrtt-service..."
                xs restart hrtt-service >> ${out_tmp_file} 2>&1
                if [ $? -ne 0 ]; then
                        cat ${out_tmp_file}
                        remove_tmp_file
                        rm -rf /tmp/cert.$$
                        exit 1
                fi
                remove_tmp_file

	fi

	waitCockpitAppsStarted

        create_tmp_file
        echo "Create role collections..."
        export LD_LIBRARY_PATH=
        curl -s --insecure -H "Content-Type:application/json" -H "Authorization:Bearer $access_token" -H "Accept:application/json" -X POST "${adminui_url}/user/CreateRoleCollections" >> ${out_tmp_file} 2>&1
        if grep "true" ${out_tmp_file} >& /dev/null
        then
                echo "Role collections created."
        else
                cat ${out_tmp_file}
                echo
                echo "ERROR: Failed to create role collections."
                remove_tmp_file
                exit 1
        fi
        remove_tmp_file
        export LD_LIBRARY_PATH="$SAVE_LD_PATH"

        getAccessToken
	create_tmp_file
       if [[ "${db_name}" =~ ^[S,s][Y,y][S,s][T,t][E,e][M,m][D,d][B,b]$ ]]; then
		cat >> ${in_tmp_file} <<-EOF
{"hostName":"$local_hostname","instanceNumber":"$instance_number","techUser":"$tech_user","techUserCredentials":"$tech_user_pwd","isMultiTenant":"true","databaseType":"$databaseType","databaseName":"$db_name","systemOwnerName":"$owner_name","systemOwnerEmail":"$owner_email","systemOwnerDetail":"$owner_details", "security": {"encryptJDBC":"$encryptJDBC", "encryptSAPControl":"$encryptSAPControl", "validateServerCertificate":"$validateCertificate", "certificateHostName":"$certificateHost"}}
EOF
	else
		 cat >> ${in_tmp_file} <<-EOF
{"hostName":"$local_hostname","port":"3${instance_number}15","techUser":"$tech_user","techUserCredentials":"$tech_user_pwd","isMultiTenant":"true","databaseType":"$databaseType","databaseName":"$db_name","systemOwnerName":"$owner_name","systemOwnerEmail":"$owner_email","systemOwnerDetail":"$owner_details", "security": {"encryptJDBC":"$encryptJDBC", "encryptSAPControl":"$encryptSAPControl", "validateServerCertificate":"$validateCertificate", "certificateHostName":"$certificateHost"}}
EOF
	fi

	export LD_LIBRARY_PATH=
	curl -s --insecure -H "Content-Type:application/json" -H "Authorization:Bearer $access_token" -H "Accept:application/json" -X POST -d @${in_tmp_file} "$adminui_url/registration/SystemRegister" >> ${out_tmp_file} 2>&1
	if grep "resid" ${out_tmp_file} >& /dev/null
	then
		echo "\"$db_name\" database is registered to Cockpit."
	else
		if grep "PERSIST_REGISTRATION_RESOURCE_EXISTS" ${out_tmp_file} >& /dev/null
		then
			echo "\"$db_name\" database is already registered to Cockpit."
		else
			cat ${out_tmp_file}
			echo
			echo "ERROR: Failed to register \"$db_name\" database to Cockpit."
			remove_tmp_file
			exit 1
		fi
	fi
	remove_tmp_file
	export LD_LIBRARY_PATH="$SAVE_LD_PATH"

	create_tmp_file
        if [[ "${db_name}" =~ ^[S,s][Y,y][S,s][T,t][E,e][M,m][D,d][B,b]$ ]]; then
                echo "Register XSA..."
                resource_id=$(getResourceIDFromDB)
                cat >> ${in_tmp_file} <<-EOF
{"resid":"${resource_id}","xsaUser":"${xsa_admin}","xsaPassword":"${xsa_admin_pwd}"}
EOF
		export LD_LIBRARY_PATH=
                curl -s --insecure -H "Content-Type:application/json" -H "Authorization:Bearer $access_token" -H "Accept:application/json" -X POST -d @${in_tmp_file} "${persistence_url}/api/XSATelRegister" >> ${out_tmp_file} 2>&1
                if grep "XSA is registered successfully" ${out_tmp_file} >& /dev/null
                then
                        echo "XSA is registered."
                else
			if grep "XSA is already registered in cockpit" ${out_tmp_file} >& /dev/null
                        then
                                echo "XSA is already registered"
                        else
                                cat ${out_tmp_file}
                                echo
                                echo "ERROR: Failed to register XSA."
                                remove_tmp_file
                                exit 1
                        fi
		fi
		export LD_LIBRARY_PATH="$SAVE_LD_PATH"
        fi
        remove_tmp_file
}

############################################################################################
# Unregister resource
############################################################################################
unregisterResource() {
	local db_name_lc=`echo "${db_name}" | tr '[:upper:]' '[:lower:]'`
	if [ "${db_name_lc}" != "systemdb" ]; then
		if ! isTenantDbStarted; then
			echo "Cannot unregister \"$db_name\" database because it does not exist or started."
			exit 1
		fi
	fi

	echo "Get \"${db_name}\" database resource ID..."
	resource_id=$(getResourceIDFromDB)
	if [ -z "$resource_id" ]; then
		echo "\"${db_name}\" database is not registered in Cockpit."
		return
	fi

	if xs trusted-certificates | grep "${db_name}_CERT" >& /dev/null; then
		create_tmp_file
		echo "Delete trusted certificate ${db_name}_CERT..."
		xs untrust-certificate ${db_name}_CERT >> ${out_tmp_file} 2>&1
		if [ $? -ne 0 ]; then
			cat ${out_tmp_file}
			remove_tmp_file
			exit 1
		fi
		remove_tmp_file
	fi

	export LD_LIBRARY_PATH=
        if [[ "${db_name}" =~ ^[S,s][Y,y][S,s][T,t][E,e][M,m][D,d][B,b]$ ]]; then
		create_tmp_file
		echo "Unregister XSA..."
		curl -s --insecure -H "Content-Type:application/json" -H "Authorization:Bearer $access_token" -H "Accept:application/json" -X POST -d '{"resid":"'"$resource_id"'"}' "${persistence_url}/api/XSATelUnRegister" >> ${out_tmp_file} 2>&1
                if grep "XSA is unregistered successfully" ${out_tmp_file} >& /dev/null
                then
                        echo "XSA is unregistered."
                else
		        if grep "XSA is not registered" ${out_tmp_file} >& /dev/null
			then
				echo "XSA is not registered."
			else 
                        	cat ${out_tmp_file}
                        	echo
                        	echo "ERROR: Failed to unregister XSA."
                        	remove_tmp_file
                        	exit 1
                	fi
		fi
		remove_tmp_file
        fi

        create_tmp_file
        echo "Unregister \"${db_name}\" database from Cockpit..."
        curl -s --insecure -H "Content-Type:application/json" -H "Authorization:Bearer $access_token" -H "Accept:application/json" -X POST -d '{"resid":"'"$resource_id"'"}' "$adminui_url/registration/ResourceUnregister" >> ${out_tmp_file} 2>&1
        if [ ! -s ${out_tmp_file} ]; then
                echo "\"${db_name}\" database is unregistered in Cockpit."
        else
                cat ${out_tmp_file}
                echo
                echo "ERROR: Failed to unregister \"$db_name\" database in Cockpit."
                remove_tmp_file
                exit 1
        fi
	export LD_LIBRARY_PATH="$SAVE_LD_PATH"
        remove_tmp_file

        dropTelemetryTable
}


############################################################################################
# Check resource
############################################################################################
checkResource() {
	local db_name_lc=`echo "${db_name}" | tr '[:upper:]' '[:lower:]'`
	if [ "${db_name_lc}" != "systemdb" ]; then
		if ! isTenantDbStarted; then
			echo "Cannot check \"$db_name\" database because it does not exist or started."
			exit 1
		fi
	fi

	echo "Get \"${db_name}\" database resource ID..."
	resource_id=$(getResourceIDFromDB)
	if [ -n "$resource_id" ]; then
		getSSLInfo

		echo
		echo "Database    : ${db_name}"
		echo "Resource ID : ${resource_id}"
		echo
		echo "Use encrypted JDBC connection : $encryptJDBC"
		echo "Use encrypted SAPControl      : $encryptSAPControl"
		echo "Validate server certificate   : $validateCertificate"
		echo "Certificate host              : $certificateHost"
		echo
		echo "\"${db_name}\" database is registered."
	else
		echo
		echo "\"${db_name}\" database is not registered in Cockpit."
		exit 1
	fi
}

############################################################################################
# Get SSL info
############################################################################################
getSSLInfo() {
	if [ -z "$resource_id" ]; then
		echo "Resource ID is null.  Cannot get SSL info."
		exit 1
	fi

	create_tmp_file
	echo "Get cockpit-persistence-svc environment..."
	xs env cockpit-persistence-svc >> ${out_tmp_file} 2>&1
	if [ $? -ne 0 ]; then
		cat ${out_tmp_file}
		echo "Cannot get cockpit-persistence-svc environment."
		remove_tmp_file
		exit 1
	fi
	local persist_usr=`grep '"user"' ${out_tmp_file} | cut -d'"' -f4`
	local persist_pwd=`grep '"password"' ${out_tmp_file} | cut -d'"' -f4`

	if [ -n "$persist_usr" -a -n "$persist_pwd" ]; then
		execSQL ${instance_number} SystemDB ${persist_usr} ${persist_pwd} "SELECT RSEC_ENCRYPTED_JDBC, RSEC_ENCRYPTED_SAP_CONTROL, RSEC_VALIDATE_SERVER_CERTIFICATE, RSEC_CERTIFICATE_HOST_NAME FROM \"CP_RESOURCE_SEC\" S, \"CP_RESOURCES\" R WHERE S.RSEC_RES_REFID = R.RES_ID and R.RES_ID = '${resource_id}'"
		SQL_OUTPUT=`trim ${SQL_OUTPUT}`

		if [ "`echo $SQL_OUTPUT | cut -d',' -f1`" == "1" ]; then
			encryptJDBC="true"
		else
			encryptJDBC="false"
		fi

		if [ "`echo $SQL_OUTPUT | cut -d',' -f2`" == "1" ]; then
			encryptSAPControl="true"
		else
			encryptSAPControl="false"
		fi

		if [ "`echo $SQL_OUTPUT | cut -d',' -f3`" == "1" ]; then
			validateCertificate="true"
		else
			validateCertificate="false"
		fi

		certificateHost="`echo $SQL_OUTPUT | cut -d',' -f4 | cut -d'"' -f2`"
	fi

	remove_tmp_file
}


############################################################################################
# Change telemetry technical user password
############################################################################################
changePwd() {
	local db_name_lc=`echo "${db_name}" | tr '[:upper:]' '[:lower:]'`
	if [ "${db_name_lc}" != "systemdb" ]; then
		if ! isTenantDbStarted; then
			echo "Cannot change password on \"$db_name\" database because it does not exist or started."
			exit 1
		fi
	fi

	resource_id=$(getResourceIDFromDB)
	if [ -n "$resource_id" ]; then
		getSSLInfo
		unregisterResource
	fi

	echo "Change \"${tech_user}\" user password on \"${db_name}\" database..."
	if [[ -z $(hdbsql -i ${instance_number} -d ${db_name} -u ${tech_user} -p "${tech_user_pwd}" "ALTER USER ${tech_user} PASSWORD \"${new_tech_user_pwd}\" no force_first_password_change" | grep "0 rows affected") ]]; then
		echo "ERROR: Fail to change \"${tech_user}\" user password on \"${db_name}\" database"
		exit 1
	else
		sleep 120s
		echo "\"${tech_user}\" user password is changed on \"${db_name}\" database."
	fi

	tech_user_pwd="${new_tech_user_pwd}"
	getClientid_secret_url
	getAccessToken
	registerResource
}


############################################################################################
# Get resource ID from DB
#
# Return: resource ID
############################################################################################
getResourceIDFromDB() {
	create_tmp_file
	export LD_LIBRARY_PATH=
	curl -s --insecure -H "Content-Type:application/json" -H "Authorization:Bearer $access_token" -H "Accept:application/json" -X GET -d '{"hostName":"'"$local_hostname"'"}' $adminui_url/resource/RegisteredResourcesGet >> ${out_tmp_file} 2>&1
	resources=$(grep "ResourceId" ${out_tmp_file})
	if [ -n  "$resources" ]; then
		local db_name_uc=`echo "$db_name" | tr '[:lower:]' '[:upper:]'`
		IFS='}' read -ra arrResources <<< "$resources"
		for i in "${arrResources[@]}"; do
			local resid=$(echo $i | grep "$db_name_uc@$sid" | sed -e 's/^.*ResourceId\":\"//' | sed -e 's/",.*//')
			if [[ ! -z $resid ]]; then
				echo "$resid"
				break
			fi
		done
	fi
	echo

	export LD_LIBRARY_PATH="$SAVE_LD_PATH"
	remove_tmp_file
}

############################################################################################
# Prompt user password
############################################################################################
# arg 1: Description
# arg 2: variable name to store user name value
# arg 3  Default user name if arg 2 is empty
# arg 4: variable name to store password value
#
promptUserPwd() {
	local default_user=`echo ${!2}`
	local usr=""
	local pwd=""
	if [ -z "$default_user" ]; then
		default_user="$3"
		read -p "Enter ${1} user name [${default_user}]: " usr
		if [ -n "$usr" ]; then
			default_user=$usr
		fi
		eval $2=\$default_user
	fi

	if [ -z "`echo ${!4}`" ]; then
		read -r -s -p "Enter $default_user user password: " pwd
		eval $4=\$pwd
	fi

	echo
}

#############################################################################################
# Prompt new user password
# arg 1: user name
# arg 2: variable name to store password value
############################################################################################
promptNewPwd() {
	local msg=""
	local showPolicy=0
	local pwd=""
	local confirm_pwd=""
	echo
	echo "Password must be at least 8 characters in length.  It must contain at least"
	echo "1 uppercase letter, 1 lowercase letter, and 1 number.  Special characters"
	echo "are allowed, except \\ (backslash), ' (single quote), \" (double quotes),"
	echo "\` (backtick), and \$ (dollar sign)."
	echo
	while [ 1 ] ; do
		read -r -s -p "Enter new password for ${1}: " pwd
		echo

		if [ `echo "${pwd}" | wc -c` -le 8 ]; then
			msg="too short"
			showPolicy=1
		fi
		if ! echo "${pwd}" | grep "[A-Z]" >& /dev/null; then
			if [ -z "$msg" ]; then
				msg="missing uppercase letter"
			else
				msg="$msg, missing uppercase letter"
			fi
			showPolicy=1
		fi
		if ! echo "${pwd}" | grep "[a-z]" >& /dev/null; then
			if [ -z "$msg" ]; then
				msg="missing lowercase letter"
			else
				msg="$msg, missing lowercase letter"
			fi
			showPolicy=1
		fi
		if ! echo "${pwd}" | grep "[0-9]" >& /dev/null; then
			if [ -z "$msg" ]; then
				msg="missing a number"
			else
				msg="$msg, missing a number"
			fi
			showPolicy=1
		fi
		if echo "$pwd" | grep -F '\' >& /dev/null; then
			if [ -z "$msg" ]; then
				msg="\\ (backslash) not allowed"
			else
				msg="$msg, \\ (backslash) not allowed"
			fi
			showPolicy=1
		fi
		if echo "$pwd" | grep -F "'" >& /dev/null; then
			if [ -z "$msg" ]; then
				msg="' (single quote) not allowed"
			else
				msg="$msg, ' (single quote) not allowed"
			fi
			showPolicy=1
		fi
		if echo "$pwd" | grep -F '"' >& /dev/null; then
			if [ -z "$msg" ]; then
				msg="\" (double quotes) not allowed"
			else
				msg="$msg, \" (double quotes) not allowed"
			fi
			showPolicy=1
		fi
		if echo "$pwd" | grep -F '`' >& /dev/null; then
			if [ -z "$msg" ]; then
				msg="\` (backtick) not allowed"
			else
				msg="$msg, \` (backtick) not allowed"
			fi
			showPolicy=1
		fi
		if echo "$pwd" | grep -F '$' >& /dev/null; then
			if [ -z "$msg" ]; then
				msg="\$ (dollar sign) not allowed"
			else
				msg="$msg, \$ (dollar sign) not allowed"
			fi
			showPolicy=1
		fi
		if [ $showPolicy -eq 1 ]; then
			echo
			echo "Invalid password: ${msg}." | fold -w 80 -s
			echo
			echo "Password must meet all of the following criteria:"
			echo "- 8 or more letters"
			echo "- At least 1 uppercase letter"
			echo "- At least 1 lowercase letter"
			echo "- At least 1 number"
			echo
			echo "Special characters are optional; except \\ (backslash), ' (single quote),"
			echo "\" (double quotes), \` (backtick), and \$ (dollar sign)."
			echo
			msg=""
			showPolicy=0
			continue
		fi

		read -r -s -p "Enter new confirm password for ${1}: " confirm_pwd
		echo
		if [ "${pwd}" != "${confirm_pwd}" ]; then
			echo "Passwords do not match."
			continue
		fi

		eval $2=\$pwd

		break;
	done
}


############################################################################################
# Prompt instance number
############################################################################################
promptInstanceNumber() {
	if [ -n "$instance_number" ] && [ -d /hana/shared/${sid}/HDB${instance_number} ] ; then
		return
	fi

	local num=""
	if [ ! -d "/hana/shared/${sid}/HDB${instance_number}" ]; then
		instance_number=""
		for i in /hana/shared/${sid}/HDB?? ; do
			num=`echo "$i" | cut -c21-22`
			if [[ ${num} =~ ^[0-9]+$ ]] ; then
				instance_number="$num"
				break
			fi
		done
	fi

	while [ 1 ]; do
		read -p "Enter HANA instance number [${instance_number}]: " num

		if [ -z "${num}" ]; then
			if [ -z "${instance_number}" ]; then
				continue
			else
				num="${instance_number}"
			fi
		fi

		if ! [[ ${num} =~ ^[0-9]+$ ]] ; then
			echo
			echo "\"$num\" is not a number.  Enter a number between 00 and 99."
			echo
			continue
		elif [ ${num} -ge 0 -a ${num} -le 99 ]; then
			if [[ ${num} =~ ^[0-9]$ ]] ; then
				num="0${num}"
			fi

			if [ ! -d "/hana/shared/${sid}/HDB${num}" ]; then
				echo
				echo "Instance ${num} does not exist in SID \"$sid\" (/hana/shared/${sid}/HDB${num})."
				echo
				continue
			else
				instance_number="${num}"
				break
			fi
		else
			echo
			echo "Invalid number.  Enter a number between 00 and 99."
			echo
			continue
		fi
	done
}


############################################################################################
# Prompt proxy host and port
############################################################################################
promptProxyInfo() {
	if [ "$proxy_action" == "enable_http" ]; then

		# Proxy host
		if [ -z "$proxy_host" ]; then
			while [ 1 ]; do
				read -p "Enter proxy host name [$system_proxy_host]: " tmp
				if [ -z "$tmp" ]; then
					if [ -n "$system_proxy_host" ]; then
						tmp="$system_proxy_host"
					else
						continue
					fi
				fi
				if ! $(isValidHostName "$tmp"); then
					echo
					echo "\"$tmp\" is not a valid host name or IP address."
					echo
				else
					proxy_host="$tmp"
					break
				fi
			done
		fi

		# Proxy port
		if [ -z "$proxy_port" ]; then
			while [ 1 ]; do
				read -p "Enter proxy port number [$system_proxy_port]: " tmp
				if [ -z "$tmp" ]; then
					if [ -n "$system_proxy_port" ]; then
						tmp="$system_proxy_port"
					else
						continue
					fi
				fi
				if ! $(isValidPort "$tmp"); then
					echo
					echo "\"$tmp\" is not a valid port number."
					echo "Enter number between 1 and 65535."
					echo
				else
					proxy_port="$tmp"
					break
				fi
			done
		fi
		# No proxy hosts
		if [ -z "$no_proxy_host" ]; then
			read -p "Enter comma separated domains that do not need proxy [$system_no_proxy_host]: " tmp
			if [ -z "$tmp" ]; then
				no_proxy_host="$system_no_proxy_host"
			else
				no_proxy_host="$tmp"
				no_proxy_host="$(addLocalHostToNoProxy "$no_proxy_host")"
			fi
		fi
	elif [ "$proxy_action" == "enable_network" ]; then
		# Proxy host
		if [ -z "$proxy_host" ]; then
			while [ 1 ]; do
				read -p "Enter network proxy host [$system_proxy_host]: " tmp
				if [ -z "$tmp" ]; then
					if [ -n "$system_proxy_host" ]; then
						tmp="$system_proxy_host"
					else
						continue
					fi
				fi
				if ! $(isValidHostName "$tmp"); then
					echo
					echo "\"$tmp\" is not a valid host name or IP address."
					echo
				else
					proxy_host="$tmp"
					break
				fi
			done
		fi

		# Proxy port
		if [ -z "$proxy_port" ]; then
			while [ 1 ]; do
				read -p "Enter network proxy port number [$system_proxy_port]: " tmp
				if [ -z "$tmp" ]; then
					if [ -n "$system_proxy_port" ]; then
						tmp="$system_proxy_port"
					else
						continue
					fi
				fi
				if ! $(isValidPort "$tmp"); then
					echo
					echo "\"$tmp\" is not a valid port number."
					echo "Enter number between 1 and 65535."
					echo
				else
					proxy_port="$tmp"
					break
				fi
			done
		fi
	fi
}


############################################################################################
# Get the system proxy host and port
############################################################################################
getSystemHTTPProxy() {
	local url="$https_proxy"
	local is_https_port=1

	if [ -z "$url" ]; then
		url="$http_proxy"
		is_https_port=0
	fi
	if [ -z "$url" ] && [ -f /etc/sysconfig/proxy ]; then
		url=`grep ^HTTPS_PROXY /etc/sysconfig/proxy | cut -d'=' -f2`
		is_https_port=1
	fi
	if [ -z "$url" ] && [ -f /etc/sysconfig/proxy ]; then
		url=`grep ^HTTP_PROXY /etc/sysconfig/proxy | cut -d'=' -f2`
		is_https_port=0
	fi

	url="${url%\"}"
	url="${url#\"}"
	url="${url%\'}"
        url="${url#\'}"

	if [ -z "$url" ]; then
		return
	fi

	# Get proxy host
	system_proxy_host=$url
	if echo $url | grep -i '^http' >& /dev/null; then
		system_proxy_host=`echo $url | cut -d '/' -f3 | cut -d':' -f1`
	else
		system_proxy_host=`echo $url | cut -d '/' -f1 | cut -d':' -f1`
	fi

	# Get proxy port
	if echo $url | grep -i '^http' >& /dev/null; then
		if echo $url | cut -d '/' -f3 | grep ':' >& /dev/null; then
			system_proxy_port=`echo $url | cut -d '/' -f3 | cut -d':' -f2`
		elif [ $is_https_port -eq 1 ]; then
			system_proxy_port="443"
		else
			system_proxy_port="80"
		fi
	else
		if echo $url | cut -d '/' -f1 | grep ':' >& /dev/null; then
			system_proxy_port=`echo $url | cut -d '/' -f1 | cut -d':' -f2`
		elif [ $is_https_port -eq 1 ]; then
			system_proxy_port="443"
		else
			system_proxy_port="80"
		fi
        fi

	# Get no proxy hosts
	system_no_proxy_host="$no_proxy"
	if [ -z "$system_no_proxy_host" ] && [ -f /etc/sysconfig/proxy ]; then
		system_no_proxy_host=`grep ^NO_PROXY /etc/sysconfig/proxy | cut -d'=' -f2`
		system_no_proxy_host="${system_no_proxy_host%\"}"
		system_no_proxy_host="${system_no_proxy_host#\"}"
		system_no_proxy_host="${system_no_proxy_host%\'}"
		system_no_proxy_host="${system_no_proxy_host#\'}"
	fi
	if [ -z "$system_no_proxy_host" ] && [ -f /etc/sysconfig/proxy ]; then
		system_no_proxy_host=`grep ^no_proxy /etc/sysconfig/proxy | cut -d'=' -f2`
		system_no_proxy_host="${system_no_proxy_host%\"}"
		system_no_proxy_host="${system_no_proxy_host#\"}"
		system_no_proxy_host="${system_no_proxy_host%\'}"
		system_no_proxy_host="${system_no_proxy_host#\'}"
	fi
	if [[ -n "$system_no_proxy_host" ]]; then
		system_no_proxy_host="$(addLocalHostToNoProxy "$system_no_proxy_host")"
	fi
}

addLocalHostToNoProxy() {
	if [ -z "$1" ]; then
		return
	fi

	local no_ph=$1
	local has_localhost=0
	local has_localhost_name=0
	local has_localhost_ip=0

	IFS=',' read -ra hlist <<< "$no_ph"
	for i in "${hlist[@]}"; do
		tmp=$(trim "$i")
		if [ -n "${tmp}" ]; then
			if [[ "${tmp}" =~ [Ll][Oo][Cc][Aa][Ll][Hh][Oo][Ss][Tt] ]]; then
				has_localhost=1
			elif echo ${tmp} | grep -i "^${host_name}$" >& /dev/null; then
				has_localhost_name=1
			elif [[ "$tmp" == "127.0.0.1" ]]; then
				has_localhost_ip=1
			fi
		fi
	done

	if [ $has_localhost_ip -eq 0 ]; then
		no_ph="127.0.0.1, ${no_ph}"
	fi
	if [ $has_localhost_name -eq 0 ]; then
		no_ph="${host_name}, ${no_ph}"
	fi
	if [ $has_localhost -eq 0 ]; then
		no_ph="localhost, ${no_ph}"
	fi

	echo ${no_ph}
}

isValidHostName() {
	local hostname_regex='^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$'
	echo "$1" | egrep $hostname_regex >& /dev/null
}

isValidPort() {
	if [[ $1 =~ ^[0-9]?+$ ]]; then
		if [ $1 -ge 1 ] && [ $1 -le 65535 ]; then
			return 0
		else
			return 1
		fi
	else
		return 1
	fi
}

isTrueFalse() {
	[[ $1 =~ ^([T,t][R,r][U,u][E,e])|([F,f][A,a][L,l][S,s][E,e])$ ]]
}

#
# Execute SQL statement and store output to SQL_OUTPUT
# $1 - instance #
# $2 - database
# $3 - user
# $4 - password
# $5 - SQL
execSQL() {
	local db="$2"
	local db_lc=`echo "$2" | tr '[:upper:]' '[:lower:]'`
	if [ "${db_lc}" == "systemdb" ]; then
		db="SystemDB"
	fi
	local sql="$5"
	SQL_OUTPUT=`/usr/sap/${sid}/HDB${1}/exe/hdbsql -a -x -i ${1} -d ${db} -u ${3} -p ${4} ${sql} 2>&1`
	if [ $? -ne 0 ]; then
		# Strip out password string
		if [ -n "$xsa_admin_pwd" ]; then
			sql=`echo "${sql}" | sed "s/${xsa_admin_pwd}/********/g"`
		fi
		if [ -n "$tech_user_pwd" ]; then
			sql=`echo "${sql}" | sed "s/${tech_user_pwd}/********/g"`
		fi
		if [ -n "$new_tech_user_pwd" ]; then
			sql=`echo "${sql}" | sed "s/${new_tech_user_pwd}/********/g"`
		fi
		echo "hdbsql $db => ${sql}"
		echo "${SQL_OUTPUT}"
		exit 1
	fi
}

# Trim leading and trailing spaces
trim()
{
	local trimmed="$1"
	trimmed=${trimmed%% }
	trimmed=${trimmed## }
	echo "$trimmed"
}

#
formatNoProxyHost() {
	if [ -z "$1" ]; then
		return
	fi

	local no_ph=""
	IFS=',' read -ra hlist <<< "$1"
	for i in "${hlist[@]}"; do
		tmp=$(trim "$i")
		if [ -n "${tmp}" ]; then
			if [[ "${tmp}" =~ ^[0-9]+\. ]] || [[ "${tmp}" =~ [Ll][Oo][Cc][Aa][Ll][Hh][Oo][Ss][Tt] ]]; then
				no_ph="${no_ph}|${tmp}"
			elif echo ${tmp} | grep -i "^${host_name}$" >& /dev/null; then
				no_ph="${no_ph}|${tmp}"
			elif echo ${tmp} | grep -i "^${host_name}\.?*" >& /dev/null; then
				no_ph="${no_ph}|${tmp}"
			elif [[ "${tmp}" =~ ^\. ]]; then
				no_ph="${no_ph}|*${tmp}"
			else
				no_ph="${no_ph}|*.${tmp}"
			fi
		fi
	done
	echo ${no_ph} | sed 's/^|//'
}

############################################################################################
# Configure proxy
############################################################################################
configProxy() {
	if [ "$proxy_action" == "enable_http" ]; then
		echo "Enable HTTP(S) proxy"
		proxyKey="http_proxy_enabled"
		proxyValue="true"
		doProxySetting

		proxyKey="http_proxy_host"
		proxyValue="$proxy_host"
		doProxySetting

		proxyKey="http_proxy_port"
		proxyValue="$proxy_port"
		doProxySetting

		proxyKey="http_non_proxy_hosts"
		proxyValue="$(formatNoProxyHost "$no_proxy_host")"
		doProxySetting
	elif [ "$proxy_action" == "disable_http" ]; then
		echo "Disable HTTP(S) proxy"
		proxyKey="http_proxy_enabled"
		proxyValue="false"
		doProxySetting

		proxyKey="http_proxy_host"
		proxyValue=""
		doProxySetting

		proxyKey="http_proxy_port"
		proxyValue=""
		doProxySetting

		proxyKey="http_non_proxy_hosts"
		proxyValue=""
		doProxySetting
	elif [ "$proxy_action" == "enable_network" ]; then
		echo "Enable network proxy"
		proxyKey="network_proxy_enabled"
		proxyValue="true"
		doProxySetting

		proxyKey="network_proxy_host"
		proxyValue="$proxy_host"
		doProxySetting

		proxyKey="network_proxy_port"
		proxyValue="$proxy_port"
		doProxySetting
	elif [ "$proxy_action" == "disable_network" ]; then
		echo "Disable network proxy"
		proxyKey="network_proxy_enabled"
		proxyValue="false"
		doProxySetting

		proxyKey="network_proxy_host"
		proxyValue=""
		doProxySetting

		proxyKey="network_proxy_port"
		proxyValue=""
		doProxySetting
	fi
}


doProxySetting() {
	echo "Set:"
	echo "  proxyKey=$proxyKey"
	echo "  proxyValue=$proxyValue"
	export LD_LIBRARY_PATH=

	create_tmp_file
	curl -s --insecure -H "Content-Type:application/json" -H "Authorization:Bearer $access_token" -H "Accept:application/json" -X POST -d '{"key":"'"$proxyKey"'", "value":"'"$proxyValue"'"}' "$ls_url/settings/SettingsCreate" >> ${out_tmp_file} 2>&1
	if [[ -s ${out_tmp_file} ]] ; then
		if ! grep -q "The System Settings to be updated already exists with the new requested settings\|\"\"" ${out_tmp_file} >& /dev/null; then
			cat ${out_tmp_file}
			echo
			echo "ERROR: Failed to create setting!"
			remove_tmp_file
			exit 1
		fi
	fi

	create_tmp_file
	curl -s --insecure -H "Content-Type:application/json" -H "Authorization:Bearer $access_token" -H "Accept:application/json" -X POST -d '{"key":"'"$proxyKey"'", "value":"'"$proxyValue"'"}' "$ls_url/settings/SettingsUpdate" >> ${out_tmp_file} 2>&1
	if [[ -s ${out_tmp_file} ]] ; then
		if ! grep -q "The System Settings to be updated already exists with the new requested settings\|\"\"" ${out_tmp_file} >& /dev/null; then
			cat ${out_tmp_file}
			echo
			echo "ERROR: Failed to update setting!"
			remove_tmp_file
			exit 1
		fi
	fi

	create_tmp_file
	curl -s --insecure -H "Content-Type:application/json" -H "Authorization:Bearer $access_token" -H "Accept:application/json" -X POST -d '{"key":"'"$proxyKey"'", "value":"'"$proxyValue"'"}' "$hdb_url/hdb/proxy/Refresh" >> ${out_tmp_file} 2>&1
	if [[ -s ${out_tmp_file} ]] ; then
		if ! grep -q "{\"result\":{\"Updated\":true}}\|\"\"" ${out_tmp_file} >& /dev/null; then
			cat ${out_tmp_file}
			echo
			echo "ERROR: Failed to refresh HDB proxy setting!"
			remove_tmp_file
			exit 1
		fi
	fi

        create_tmp_file
        curl -s --insecure -H "Content-Type:application/json" -H "Authorization:Bearer $access_token" -H "Accept:application/json" -X POST -d '{"key":"'"$proxyKey"'", "value":"'"$proxyValue"'"}' "$xsa_url/xsa/proxy/Refresh" >> ${out_tmp_file} 2>&1
        if [[ -s ${out_tmp_file} ]] ; then
                if ! grep -q "{\"result\":{\"Updated\":true}}\|\"\"" ${out_tmp_file} >& /dev/null; then
                        cat ${out_tmp_file}
                        echo
                        echo "ERROR: Failed to refresh XSA proxy setting!"
                        remove_tmp_file
                        exit 1
                fi
        fi

        create_tmp_file
        curl -s --insecure -H "Content-Type:application/json" -H "Authorization:Bearer $access_token" -H "Accept:application/json" -X POST -d '{"key":"'"$proxyKey"'", "value":"'"$proxyValue"'"}' "$tel_url/telemetry/proxy/Refresh" >> ${out_tmp_file} 2>&1
        if [[ -s ${out_tmp_file} ]] ; then
                if ! grep -q "{\"result\":{\"Updated\":true}}\|\"\"" ${out_tmp_file} >& /dev/null; then
                        cat ${out_tmp_file}
                        echo
                        echo "ERROR: Failed to refresh Telemetry proxy setting!"
                        remove_tmp_file
                        exit 1
                fi
        fi

	export LD_LIBRARY_PATH="$SAVE_LD_PATH"

	echo "Succeed"
	echo
	remove_tmp_file
}

############################################################################################
# Create temp file
############################################################################################
create_tmp_file() {
	rm -f ${in_tmp_file} >& /dev/null
	rm -f ${out_tmp_file} >& /dev/null

	touch ${in_tmp_file}
	touch ${out_tmp_file}

	chmod 600 ${in_tmp_file}
	chmod 600 ${out_tmp_file}
}

############################################################################################
# Remove temp file
############################################################################################
remove_tmp_file() {
        rm -f ${in_tmp_file} >& /dev/null
        rm -f ${out_tmp_file} >& /dev/null
}

############################################################################################
# Clean up
############################################################################################
cleanup() {
	rm -f ${in_tmp_file} >& /dev/null
	rm -f ${out_tmp_file} >& /dev/null
	exit 1
}


############################################################################################
# Main
############################################################################################
# Default values
DEFAULT_SYSTEM_ADMIN="SYSTEM"
DEFAULT_XSA_ADMIN="XSA_ADMIN"
DEFAULT_TECH_USER="TEL_ADMIN"
SAVE_LD_PATH="$LD_LIBRARY_PATH"

base_name=`basename $0`
in_tmp_file="/tmp/in.$$"
out_tmp_file="/tmp/out.$$"

action=""
proxy_action=""

# Inputs
sid="HXE"
instance_number=""
system_admin=""
system_admin_pwd=""
xsa_admin=""
xsa_admin_pwd=""
tech_user=""
tech_user_pwd=""
new_tech_user_pwd=""
space="SAP"
db_name=""
owner_name=`whoami`
local_hostname=`hostname -f`
owner_email="${owner_name}@${local_hostname}"
owner_details="Sample details"
resource_id=""
cfg_proxy_quiet=0
host_name=`basename $SAP_RETRIEVAL_PATH`
system_proxy_host=""
system_proxy_port=""
system_no_proxy_host=""
proxy_host=""
proxy_port=""
no_proxy_host=""

clientid=""
clientsecret=""
uaa_url="" 
adminui_url=""
admin_web_app_url=""
ls_url=""
hdb_url=""
persistence_url=""
access_token=""

encryptJDBC="true"
encryptSAPControl="true"
validateCertificate="true"
certificateHost="$local_hostname"

#
# Parse argument
#
if [ $# -gt 0 ]; then
	PARSED_OPTIONS=`getopt -n "$base_name" -a -o u:p:i:d:s:hq --long action:,xsau:,xsap:,tu:,tp:,ntp:,on:,oe:,od:,proxy_action:,ph:,pp:,nph:,sj:,sc:,vc:,ch: -- "$@"`
	if [ $? -ne 0 ]; then
		exit 1
	fi

	# Something has gone wrong with the getopt command
	if [ "$#" -eq 0 ]; then
		usage
		exit 1
	fi

	# Process command line arguments
	eval set -- "$PARSED_OPTIONS"
	while true
	do
		case "$1" in
                -action|--action)
                        action=`echo $2 | tr '[:upper:]' '[:lower:]'`
			shift 2;;
                -u)
                        system_admin="$2"
                        shift 2;;
                -p)
                        system_admin_pwd="$2"
                        shift 2;;
                -xsau|--xsau)
                        xsa_admin="$2"
                        shift 2;;
                -xsap|--xsap)
                        xsa_admin_pwd="$2"
                        shift 2;;

		-tu|--tu)
			tech_user="$2"
			shift 2;;
		-tp|--tp)
			tech_user_pwd="$2"
			shift 2;;
		-ntp|--ntp)
			new_tech_user_pwd="$2"
			shift 2;;
		-i)
			instance_number="$2"
			shift 2;;
		-d)
			db_name="$2"
			shift 2;;
		-on|--on)
			owner_name="$2"
			shift 2;;
		-oe|--oe)
			owner_email="$2"
			shift 2;;
		-od|--od)
			owner_details="$2"
			shift 2;;
		-s)
			space="$2"
			shift 2;;
		-proxy_action|--proxy_action)
			proxy_action=`echo $2 | tr '[:upper:]' '[:lower:]'`
			shift 2;;
		-ph|--ph)
			proxy_host="$2"
			if ! $(isValidHostName "$proxy_host"); then
				echo
				echo "\"$proxy_host\" is not a valid host name or IP address."
				exit 1
			fi
			shift 2;;
		-pp|--pp)
			proxy_port="$2"
			if ! $(isValidPort "$proxy_port"); then
				echo
				echo "\"$proxy_port\" is not a valid port number."
				echo "Enter number between 1 and 65535."
				exit 1
                        fi
			shift 2;;
		-nph|--nph)
			no_proxy_host="$2"
			shift 2;;
		-q)
			cfg_proxy_quiet=1
			shift;;
		-sj|--sj)
			encryptJDBC="$2"
			if ! isTrueFalse $encryptJDBC; then
				echo "Invalid --sj value.  Valid values are: \"true\" or \"false\"."
				exit 1
			fi
			shift 2;;
		-sc|--sc)
			encryptSAPControl="$2"
			if ! isTrueFalse $encryptSAPControl; then
				echo "Invalid --sc value.  Valid values are: \"true\" or \"false\"."
				exit 1
			fi
			shift 2;;
		-vc|--vc)
			validateCertificate="$2"
			if ! isTrueFalse $validateCertificate; then
				echo "Invalid --vc value.  Valid values are: \"true\" or \"false\"."
				exit 1
			fi
			shift 2;;
		-ch|--ch)
			certificateHost="$2"
			shift 2;;
		-h)
			usage
			exit 0
			break;;
		--)
			shift
			break;;
		*)
			echo "Invalid \"$1\" argument."
			usage
			exit 1
		esac
	done
fi

# Default action is register
if [ -z "$action" ]; then
	echo "You need to specify \"-action <register|unregister|check|change_pwd|config_proxy>\" option."
	exit 1
elif [ "$action" != "register" ] && [ "$action" != "unregister" ] && [ "$action" != "check" ] && [ "$action" != "change_pwd" ] && [ "$action" != "config_proxy" ]; then
	echo "Invalid \"-action\" option value."
	echo "Valid values are: register|unregister|check|change_pwd|config_proxy"
	exit 1
fi

if [ "$action" == "config_proxy" ]; then
	if [ -z "$proxy_action" ]; then
		echo "You need to specify \"-proxy_action\" value for \"-action config_proxy\"."
		exit 1
	elif [ "$proxy_action" != "enable_http" ] && [ "$proxy_action" != "disable_http" ] && [ "$proxy_action" != "enable_network" ] && [ "$proxy_action" != "disable_network" ];then
		echo "Invalid \"-proxy_action\" option value."
		echo "Valid values are: enable_http|disable_http|enable_network|disable_network"
		exit 1
	fi
fi


# Default db is SystemDB db
if [ -z "$db_name" ]; then
	db_name="SystemDB"
fi

getSID
checkEnv

if [ "$action" == "register" ]; then
	echo "==============================================================================="
	echo "Register resource on \"${db_name}\" database"
	echo "==============================================================================="
elif [ "$action" == "check" ]; then
	echo "==============================================================================="
	echo "Check register resource on \"${db_name}\" database"
	echo "==============================================================================="
elif [ "$action" == "unregister" ]; then
	echo "==============================================================================="
	echo "Unregister resource on \"${db_name}\" database"
	echo "==============================================================================="
elif [ "$action" == "change_pwd" ]; then
        echo "==============================================================================="
        echo "Change telemetry technical user password on \"${db_name}\" database"
        echo "==============================================================================="
elif [ "$action" == "config_proxy" ]; then
        echo "==============================================================================="
        echo "Configure proxy"
        echo "==============================================================================="
fi

# Prompt system user/password if not provided
if [ "$action" == "register" -o "$action" == "unregister" -o "$action" == "change_pwd" ]; then
        if [ -z "$system_admin" -o -z "$system_admin_pwd" ]; then
                promptUserPwd "System administrator" system_admin $DEFAULT_SYSTEM_ADMIN system_admin_pwd
        fi
fi

# Prompt XSA administrator user/password if not provided
if [ -z "$xsa_admin" -o -z "$xsa_admin_pwd" ]; then
	promptUserPwd "XSA administrator" xsa_admin $DEFAULT_XSA_ADMIN xsa_admin_pwd
fi

# If register or change password, prompt telemetry technical user/password if not provided
if [ "$action" == "register" -o "$action" == "change_pwd" ]; then
	promptUserPwd "telemetry technical" tech_user $DEFAULT_TECH_USER tech_user_pwd
fi

# If change password, prompt new telemetry technical user/password
if [ "$action" == "change_pwd" ]; then
	if [ -z "$new_tech_user_pwd" ]; then
		promptNewPwd "telemetry technical user" new_tech_user_pwd
	fi
fi

promptInstanceNumber


# Prompt proxy info if enable_http or enable_network
if [ "$action" == "config_proxy" ]; then
	if [ "$proxy_action" == "enable_http" -o "$proxy_action" == "enable_network" ]; then
		# Get proxy info from system
		getSystemHTTPProxy

		if [ $cfg_proxy_quiet -eq 1 ]; then
			if [ -z "$proxy_host" ]; then
				proxy_host="$system_proxy_host"
			fi
			if [ -z "$proxy_port" ]; then
				proxy_port="$system_proxy_port"
			fi
			if [ -z "$no_proxy_host" ]; then
				no_proxy_host="$system_no_proxy_host"
			fi
			if [ -z "$proxy_host" ] && [ -z "$proxy_port" ]; then
				echo
				echo "No proxy to configure."
				exit 0
			fi
		else
			promptProxyInfo
		fi
	fi
fi

echo

# Call 'cleanup' if Control-C or terminated
trap 'cleanup' SIGINT SIGTERM

echo "Login to XSA services..."
create_tmp_file
xs login -u $xsa_admin -p $xsa_admin_pwd -s $space >> ${out_tmp_file} 2>&1
if [ $? -ne 0 ]; then
	cat ${out_tmp_file}
	echo "Cannot login to XSA services.  Please check HANA has started and login/password are correct."
	remove_tmp_file
	exit 1
fi
remove_tmp_file

waitCockpitAppsStarted

getClientid_secret_url
getAccessToken

if [ "$action" == "register" ]; then
	if [[ ! "$encryptJDBC" =~ ^[T,t][R,r][U,u][E,e]$ ]] && [[ ! "$encryptSAPControl" =~ ^[T,t][R,r][U,u][E,e]$ ]]; then
		validateCertificate="false"
	fi
	if [[ ! "$validateCertificate" =~ ^[T,t][R,r][U,u][E,e]$ ]]; then
		certificateHost=""
	fi
	registerResource
elif [ "$action" == "check" ]; then
	checkResource
elif [ "$action" == "unregister" ]; then
	unregisterResource
elif [ "$action" == "change_pwd" ]; then
        changePwd
elif [ "$action" == "config_proxy" ]; then
	configProxy
fi
