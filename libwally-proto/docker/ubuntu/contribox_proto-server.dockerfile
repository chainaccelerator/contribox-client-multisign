ARG LIBWALLY_CORE_VERSION

FROM wallycore:${LIBWALLY_CORE_VERSION}-ubuntu

RUN apt-get update -yy &&\
    apt-get install -yy --no-install-recommends python3.8-minimal libpython3.8 python3-pip wget &&\
    apt-get -yy autoremove &&\
    apt-get -yy clean &&\
    rm -rf /var/lib/apt/lists/* /var/cache/* /tmp/* /usr/share/locale/* /usr/share/man /usr/share/doc /lib/xtables/libip6*

ENV LC_ALL=C.UTF-8
ENV LANG=C.UTF-8 

# requirements
ENV PYTHONPATH='/usr/local/lib/python3.8/site-packages'
COPY requirements.txt /contribox_proto/requirements.txt
RUN [ "python3", "-m", "pip", "install", "-r", "/contribox_proto/requirements.txt" ]
COPY server/requirements.txt /contribox_proto/server/requirements.txt
RUN [ "python3", "-m", "pip", "install", "-r", "/contribox_proto/server/requirements.txt" ]


COPY contribox_proto /contribox_proto/contribox_proto
COPY server /contribox_proto/server

ENV PYTHONPATH "${PYTHONPATH}:/contribox_proto"
CMD [ "python3", "/contribox_proto/server/server.py" ]
