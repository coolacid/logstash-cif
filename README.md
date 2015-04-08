** No Longer Maintained **
==========================

Note: CIFv2 uses Elasticsearch as a back end, thus you can use the elasticsearch filter. 


logstash-cif
============

Logstash Filter to Query a CIF Server

Build
=====

Run 'make tarball' to build the project. A tarball will end up in ./build. Extract the file over top of your logstash directory. 
(Hint: or, just copy the ./lib and ./vendor directories to your logstash folder)


Config
======

This is an example config. Replace host with your host string, and the apikey with an API key registered on your CIF server.

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