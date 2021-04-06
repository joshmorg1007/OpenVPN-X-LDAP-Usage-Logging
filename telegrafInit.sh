wget -qO- https://repos.influxdata.com/influxdb.key | sudo apt-key add -
source /etc/lsb-release
echo "deb https://repos.influxdata.com/${DISTRIB_ID,,} ${DISTRIB_CODENAME} stable" | sudo tee /etc/apt/sources.list.d/influxdb.list
sudo apt-get update
sudo apt-get install telegraf

sudo systemctl enable --now telegraf
sudo systemctl start --now telegraf

echo Enter the InfluxDB Token for Telegraf.
read token

sudo export INFLUX_TOKEN=${token}

echo Enter Telegraf Config File Endpoint
read config

sudo systemctl stop --now telegraf

sudo curl $config --header "Authorization: Token ${token}" > /etc/telegraf/telegraf.conf

sudo systemctl start --now telegraf
