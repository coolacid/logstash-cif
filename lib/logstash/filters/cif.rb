# encoding: utf-8
require "logstash/filters/base"
require "logstash/namespace"

# The CIF filter adds information about the IP from a local CIF server.

class LogStash::Filters::CIF < LogStash::Filters::Base
  config_name "cif"
  milestone 1

  # The field containing the IP address or hostname to map via CIF. If
  # this field is an array, only the first value will be used.
  config :source, :validate => :string, :required => true

  # An array of geoip fields to be included in the event.
  #
  # Possible fields depend on the database type. By default, all cif fields
  # are included in the event.
  #
  # Right now, this doesn't actually do anything
  #
  config :fields, :validate => :array

  # Specify the field into which Logstash should store the CIF data.
  # This can be useful, for example, if you have `src\_ip` and `dst\_ip` fields and
  # would like the CIF information of both IPs.
  config :target, :validate => :string, :default => 'cif'

  config :severity, :validate => :number, :default => nil
  config :restriction, :validate => :number, :default => nil

  # Log the query on the CIF server. Default: No.
  config :nolog, :validate => :boolean, :default => true

  # The location to query. eg "https://cifserver/api
  config :host, :validate => :string, :required => true

  # The API key to query the CIF server
  config :apikey, :validate => :string, :required => true

  public
  def register
    require 'json'
    require 'net/http'
    require 'net/https'
    require 'net/http/persistent'

    require 'openssl'

    # Start building the URI, we'll append the query later
    params = {'apikey' => @apikey}
    params['restriction'] = restriction || @restriction if restriction || @restriction
    params['severity'] = severity || @severity if severity || @severity
    params['nolog'] = 1 if nolog || @nolog
    @s = "#{@host}?"+params.map{|k,v| "#{k}=#{v}"}.join("&")
    @logger.debug("Connection URL", :connect => @s)

    # Start a new Persistent HTTPS connection
    @http = Net::HTTP::Persistent.new 'Logstash'
    # Assume we don't have a valid cert, maybe this should be an option?
    @http.verify_mode = OpenSSL::SSL::VERIFY_NONE
    @http.idle_timeout = nil
    # Set some headers so the other side knows who we are, and what we want.
    @http.headers["User-Agent"] = "Ruby/#{RUBY_VERSION} logstash"
    @http.headers["Accept"] = "application/json"
  end # def register

  public
  def filter(event)
    return unless filter?(event)

    begin
      # Finish off building the URI with the query coming from @source
      ip = event[@source]
      uri = URI @s+"&query="+ip

      @logger.info("CIF query for", :ip => ip)
      @logger.debug("Full Query URI", :uri => uri)

      # Request the URI built above
      response = @http.request uri
      doc = response.body

      # CIF responds with a set of JSON responses, one per line, so go though them and add them to the @event
      doc.each_line do |line|
        data = JSON.parse(line)
        (event[@target] ||= []) << data
      end
    end

    #filter_matched(event)
  end # def filter
end # class LogStash::Filters::CIF
