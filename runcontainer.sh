# this runs the original container.
# Unfortunately, on Google N1 instance there is not enough time for all the 
# apps ro come up and it times out
sudo docker run  --stop-timeout 330 \
-p 39013:39013 -p 39015:39015 -p 39041-39045:39041-39045 -p 1128-1129:1128-1129 -p 59013-59014:59013-59014  -p 39030-39033:39030-39033 -p 51000-51060:51000-51060  -p 53075:53075  \
-h hxehost \
-v /data/dbapps:/hana/mounts \
--ulimit nofile=1048576:1048576 \
--sysctl kernel.shmmax=1073741824 \
--sysctl net.ipv4.ip_local_port_range='60000 65535' \
--sysctl kernel.shmmni=524288 \
--sysctl kernel.shmall=8388608 \
--name hana_with_apps \
store/saplabs/hanaexpressxsa:2.00.040.00.20190729.1 \
--agree-to-sap-license \
--passwords-url file:///hana/mounts/passwd.json
