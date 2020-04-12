Docker solution
https://habr.com/ru/post/451264/
Moving logs from Acquia:
https://www.thinkbean.com/drupal-development-blog/moving-logs-acquia-elasticsearch

rsync -avz mcc.prod@mcc.ssh.prod.acquia-sites.com:/mnt/log/sites/mcc.prod/logs/ded-28721/drupal-watchdog.log /media/laptop/c6394850-de3c-4133-92fe-80bad5a764ef/hard-projects/docker-elk/logs/drupal-watchdog.log
rsync -avz mcc.prod@mcc.ssh.prod.acquia-sites.com:/mnt/log/sites/mcc.prod/logs/ded-28721/fpm-error.log /media/laptop/c6394850-de3c-4133-92fe-80bad5a764ef/hard-projects/docker-elk/logs/php-errors.log

rsync -avz mcc.prod@mcc.ssh.prod.acquia-sites.com:/mnt/log/sites/mcc.prod/logs/ded-28721/fpm-error.log /media/laptop/c6394850-de3c-4133-92fe-80bad5a764ef/hard-projects/docker-elk/logs/fpm-error.log

Parsing message with Grok plugin:
file:///home/laptop/Pictures/2016-DrupalCon_Dublin-HA_ELK%20(2).pdf
https://www.thinkbean.com/drupal-development-blog/moving-logs-acquia-elasticsearch
https://www.elastic.co/guide/en/logstash/current/plugins-filters-grok.html


Another articles about ELK:
Log with drupal_dblog logstash plugin:
https://blog.adminfactory.net/logging-drupal-logs-with-logstash-and-drupal_dblog.html


https://www.elastic.co/support/matrix
Elastic, Logstash, Kibana have the same versions.

Installing ELK:
Official documentation - https://www.elastic.co/guide/en/elastic-stack-get-started/7.6/get-started-elastic-stack.html
Official documentation - https://www.elastic.co/guide/en/elastic-stack-get-started/7.6/get-started-elastic-stack.html
https://logz.io/learn/complete-guide-elk-stack/#installing-elk
https://www.digitalocean.com/community/tutorials/how-to-install-elasticsearch-logstash-and-kibana-elk-stack-on-ubuntu-14-04

https://www.sitepoint.com/how-can-the-elk-stack-be-used-to-monitor-php-apps/

https://discuss.elastic.co/t/kibana-port-5601-connection-refused/71809/3

Install http://supervisord.org/
https://www.digitalocean.com/community/tutorials/how-to-install-and-manage-supervisor-on-ubuntu-and-debian-vps
https://www.thinkbean.com/drupal-development-blog/moving-logs-acquia-elasticsearch

Drupal watchdog:
https://demo.codesetter.com/drupal-log-elasticsearch-logstash-kibana

ELK with monolog:
https://pehapkari.cz/blog/2017/10/22/connecting-monolog-with-ELK/

Setup Filebeats:
https://www.elastic.co/guide/en/beats/filebeat/current/filebeat-getting-started.html
 sudo nano /etc/filebeat/filebeat.yml


Docker solution
https://habr.com/ru/post/451264/
Moving logs from Acquia:
https://www.thinkbean.com/drupal-development-blog/moving-logs-acquia-elasticsearch

rsync -avz mcc.prod@mcc.ssh.prod.acquia-sites.com:/mnt/log/sites/mcc.prod/logs/ded-28721/drupal-watchdog.log /media/laptop/c6394850-de3c-4133-92fe-80bad5a764ef/hard-projects/docker-elk/logs/drupal-watchdog.log
rsync -avz mcc.prod@mcc.ssh.prod.acquia-sites.com:/mnt/log/sites/mcc.prod/logs/ded-28721/fpm-error.log /media/laptop/c6394850-de3c-4133-92fe-80bad5a764ef/hard-projects/docker-elk/logs/php-errors.log

rsync -avz mcc.prod@mcc.ssh.prod.acquia-sites.com:/mnt/log/sites/mcc.prod/logs/ded-28721/fpm-error.log /media/laptop/c6394850-de3c-4133-92fe-80bad5a764ef/hard-projects/docker-elk/logs/fpm-error.log

Parsing message with Grok plugin:
file:///home/laptop/Pictures/2016-DrupalCon_Dublin-HA_ELK%20(2).pdf
https://www.thinkbean.com/drupal-development-blog/moving-logs-acquia-elasticsearch
https://www.elastic.co/guide/en/logstash/current/plugins-filters-grok.html


Setup file permissions for logstash data folder:
sudo chmod 777 /usr/share/logstash/data -R


Install Filebeat:
https://www.elastic.co/guide/en/beats/filebeat/current/filebeat-installation.html

Setup filebeat for Drupal:
https://logz.io/blog/drupal-log-analysis-elk-stack/

Pipe separated logs in Filebeat:
https://discuss.elastic.co/t/match-and-extract-last-part-of-log-in-pipe-delimited-log/90086


http://localhost:9200/ - Elastic
http://localhost:5601 - kibana


sudo service elasticsearch start
sudo service kibana start
sudo service logstash start
sudo service filebeat start

sudo service metricbeat start - ???



sudo nano /opt/bin/sync-logs.sh

sudo nano /etc/elasticsearch/elasticsearch.yml
sudo nano /etc/logstash/conf.d/manningham.conf
sudo nano /etc/kibana/kibana.yml


http://localhost:5601/app/kibana
https://localhost:5601/app/kibana


sudo service elasticsearch stop
sudo service kibana stop
sudo service metricbeat stop
sudo service logstash stop


/opt/log/manningham/access.log
whereis logstash
/opt/logstash/bin/logstash -f /etc/logstash/conf.d/manningham-apache-logs.conf
/usr/share/logstash/bin/logstash -f /etc/logstash/conf.d/manningham-apache-logs.conf

PHP errors:
https://gist.github.com/gerardorochin/36d2b1be8b65ca0c7373
php_error_logstash.conf

/opt/log/manningham/drupal-watchdog.log
/opt/log/manningham/php-error.log


Setup logstash:

sudo nano /etc/logstash/conf.d/manningham-apache-logs.conf

input {
  file {
    path => "/opt/log/mannigham/access.log"
    start_position => "beginning"
    type => "access"
    add_field => {
      "project" => "Manningham"
      "env" => "prod"
      "xhost" => "mcc.ssh.prod.acquia-sites.com"
    }
  }
}

filter {
  if [type] == "access" {
    grok {
      match => [
        "message", "(?:%{IPORHOST:ip}|-) - (?:%{USER:auth}|-) \[%{HTTPDATE:timestamp}\] \"(?:%{WORD:verb} %{NOTSPACE:request}(?: HTTP/%{NUMBER:httpversion})?|%{DATA:rawrequest})\" %{NUMBER:response} (?:%{NUMBER:bytes}|-) \"%{DATA:referrer}\" \"%{DATA:agent}\" vhost=%{IPORHOST:vhost} host=%{IPORHOST:domain} hosting_site=%{WORD} pid=%{NUMBER} request_time=%{NUMBER:request_time} forwarded_for=\"(?:%{IPORHOST:forwarded_for}|)(?:, %{IPORHOST}|)(?:, %{IPORHOST}|)\" request_id=\"%{NOTSPACE:request_id}\""
      ]
    }
    mutate {
      update => { "host" => "%{xhost}" }
      replace => { "path" => "%{request}" }
    }
    if (![ip]) {
      mutate {
        add_field => {
          "ip" => "%{forwarded_for}"
        }
      }
    }
    geoip { source => "ip" }
    date {
      locale => "en"
      match => [ "timestamp", "dd/MMM/yyyy:HH:mm:ss Z" ]
      target => "@timestamp"
    }
    mutate {
      remove_field => [ "forwarded_for", "message", "request", "timestamp", "xhost" ]
    }
  }
}

output {
  if [type] == "access" {
    elasticsearch {
      hosts => [ "http://localhost.com:9200" ]
      user => "elastic"
      password => "changeme"
      index => "logstash-access"
    }
  }
}





mcc.prod.acquia-sites.com host=www.manningham.vic.gov.au
ded-28722 mcc


curl -XPUT -u elastic:changeme 'localhost:9200/_xpack/security/user/elastic/_password?pretty' -H 'Content-Type: application/json' -d'
{
  "password": "changeme"
}
'


https://www.drupal.org/project/jsonlog

[2020-03-03T01:36:18,009][WARN ][logstash.outputs.elasticsearch][main] Attempted to resurrect connection to dead ES instance, but got an error. {:url=>"http://localhost.com:9200/"

Kibana login/password:
http://localhost:5601/login?next=%2F
elasticsearch.username: elastic
elasticsearch.password: changeme