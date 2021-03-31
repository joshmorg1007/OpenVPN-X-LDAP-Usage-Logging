sudo apt update
sudo apt install telegraf

sudo systemctl enable --now telegraf
sudo systemctl start --now telegraf

echo Enter the InfluxDB Token for Telegraf.
read token

echo Enter Telegraf Config File Endpoint
read config

sudo systemctl stop --now telegraf

sudo curl $config --header "Authorization: Token ${token}" > /etc/telegraf/telegraf.conf

sudo systemctl start --now telegraf
