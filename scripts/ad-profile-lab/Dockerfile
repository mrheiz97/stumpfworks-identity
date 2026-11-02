FROM debian:bookworm-slim@sha256:99c0b25c46d0214d5a2091092e7908907dcaecd6a962cde0ac700acee222b6f3
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends samba samba-ad-dc samba-ad-provision python3-samba ldap-utils openssl attr && rm -rf /var/lib/apt/lists/*
WORKDIR /lab
COPY provision.py /lab/provision.py
COPY run.sh /lab/run.sh
ENTRYPOINT ["sh", "/lab/run.sh"]
