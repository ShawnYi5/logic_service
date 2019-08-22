#!/bin/sh

fromPath="LogicService.service"
toPath="/usr/lib/systemd/system/LogicService.service"

chmod 754 "$fromPath"
rm -f "$toPath"
cp "$fromPath" "$toPath"

logFolder="/var/log/aio"
if [ ! -d "$logFolder" ]; then
  mkdir "$logFolder"
fi

sudo systemctl daemon-reload
sudo systemctl enable LogicService
