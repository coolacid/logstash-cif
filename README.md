logstash-cif
============

Logstash Filter to Query a CIF Server

Config
======

```
input {
    generator {
	message => "8.8.8.8"
	count => 2
    }
}

filter {
    cif {
	source => "message"
	host => "https://server/api"
	apikey => "768ca6fe-feeb-beef-beef-0000000000"
    }
}

output {
    stdout { 
	codec => "rubydebug"
    }
}
```