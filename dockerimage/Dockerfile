FROM ubuntu:16.04

RUN apt-get -y update && \
    apt-get -y install imagemagick xvfb x11-apps libgtk-3-0 libasound2 libdbus-glib-1-2

RUN groupadd -g 1000 websurfer && useradd -g websurfer -m -u 1000 websurfer -s /bin/bash
USER websurfer

ADD files/firefox.tar.bz2 /home/websurfer
ADD files/launch_firefox.sh /home/websurfer

CMD ["bash"]
