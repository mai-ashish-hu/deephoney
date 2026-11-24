FROM dinotools/dionaea:0.11.0@sha256:6f06d0a6035c865cb60ef51bd96ff3b1f25ee4bfcd852dad3f551bc2d93464ca

USER root

COPY deployments/dionaea/log_json.yaml /opt/dionaea/template/etc/dionaea/ihandlers-enabled/log_json.yaml

RUN rm -f \
    /opt/dionaea/template/etc/dionaea/services-enabled/blackhole.yaml \
    /opt/dionaea/template/etc/dionaea/services-enabled/epmap.yaml \
    /opt/dionaea/template/etc/dionaea/services-enabled/memcache.yaml \
    /opt/dionaea/template/etc/dionaea/services-enabled/mirror.yaml \
    /opt/dionaea/template/etc/dionaea/services-enabled/mongo.yaml \
    /opt/dionaea/template/etc/dionaea/services-enabled/mqtt.yaml \
    /opt/dionaea/template/etc/dionaea/services-enabled/mssql.yaml \
    /opt/dionaea/template/etc/dionaea/services-enabled/mysql.yaml \
    /opt/dionaea/template/etc/dionaea/services-enabled/pptp.yaml \
    /opt/dionaea/template/etc/dionaea/services-enabled/printer.yaml \
    /opt/dionaea/template/etc/dionaea/services-enabled/sip.yaml \
    /opt/dionaea/template/etc/dionaea/services-enabled/upnp.yaml

EXPOSE 21 69/udp 80 445

HEALTHCHECK --interval=30s --timeout=5s --start-period=25s --retries=3 \
    CMD ["python3", "-c", "import socket; s=socket.create_connection(('127.0.0.1', 21), 3); s.close()"]
