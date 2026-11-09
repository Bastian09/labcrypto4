FROM ubuntu:24.04

RUN apt-get update && \
    apt-get install -y openssh-server && \
    useradd -m -s /bin/bash alumno && \
    echo 'alumno:LabSSH2026!' | chpasswd && \
    mkdir -p /run/sshd && \
    apt-get clean

COPY sshd_config /etc/ssh/sshd_config

EXPOSE 22

CMD ["/bin/sh", "-c", "ssh-keygen -A && exec /usr/sbin/sshd -D -e"]
