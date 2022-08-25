# image: tapis/authenticator
FROM tapis/flaskbase

COPY requirements.txt /home/tapis/requirements.txt
RUN pip install -r /home/tapis/requirements.txt

# give tapis permissions to write to tapipy -- this is important if you want tapipy to download more
# recent specs.
RUN chmod -R a+w /usr/local/lib/python3.7/site-packages/tapipy/

COPY configschema.json /home/tapis/configschema.json
COPY config-local.json /home/tapis/config.json

COPY service /home/tapis/service

RUN chown -R tapis:tapis /home/tapis
USER tapis
