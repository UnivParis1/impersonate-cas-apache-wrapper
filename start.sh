#!/bin/sh

cd /home/cas/cas-impersonate
exec ant jetty.run >> /var/log/cas/cas-impersonate-jetty.log 2>&1

