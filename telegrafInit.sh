wget -qO- https://repos.influxdata.com/influxdb.key | sudo apt-key add -
source /etc/lsb-release
echo "deb https://repos.influxdata.com/${DISTRIB_ID,,} ${DISTRIB_CODENAME} stable" | sudo tee /etc/apt/sources.list.d/influxdb.list
sudo apt-get update

echo Enter the InfluxDB Token for Telegraf.
read token

sudo apt-get install telegraf

sudo systemctl enable --now telegraf
sudo systemctl start --now telegraf

export INFLUX_TOKEN=${token}

echo Enter Telegraf Config File Endpoint

sudo systemctl stop --now telegraf

read config

sudo curl $config --header "Authorization: Token ${token}" > /etc/telegraf/telegraf.conf
sudo sed -i "s/\$INFLUX_TOKEN/${token}/g" /etc/telegraf/telegraf.conf

sudo systemctl start --now telegraf
