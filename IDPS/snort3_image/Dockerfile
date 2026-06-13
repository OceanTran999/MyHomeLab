FROM ciscotalos/snort3:latest
ARG DEBIAN_FRONTEND=noninteractive

# Must set this due to 'snorty' as default user
USER root

# copy configuration and rule files
COPY ./*.rules /home/snorty/snort3/etc/rules/
COPY ./oceantranlab.lua /home/snorty/snort3/etc/snort/

# install packages
RUN apt-get update && apt-get install -y iproute2 net-tools