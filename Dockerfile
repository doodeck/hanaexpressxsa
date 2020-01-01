FROM store/saplabs/hanaexpressxsa:2.00.040.00.20190729.1
# COPY ./run_hana.sh /
COPY ./register_cockpit.sh /usr/sap/HXE/home/bin/
# RUN /bin/bash -c 'whoami ; ls -la; chmod +x ./mod_run_hana.sh; ls -la'
# RUN su - hxeadm -c 'whoami ; ls -la; chmod +x ./mod_run_hana.sh; ls -la'
ENTRYPOINT ["/run_hana"]
# ENTRYPOINT ["/bin/bash"]
# CMD ["--help"]
