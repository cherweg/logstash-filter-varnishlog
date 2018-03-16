# encoding: utf-8
require "logstash/filters/base"
require "logstash/namespace"

# This filter reads a varnishlog grouped by reqid 
# message field with whatever you specify in the configuration.
#
# It is only intended to be used as an .

##Extenting array class to to an something like grep -v
class Array
  def grepv(regex, &block)
    self.reject { |elem| elem =~ regex }.each(&block)
  end
end

class LogStash::Filters::Varnishlog < LogStash::Filters::Base

  # Setting the config_name here is required. This is how you
  # See https://varnish-cache.org/docs/trunk/reference/varnishlog.html
  #
  # filter {
  #    {
  #     varnishlog {}
  #   }
  # }
  #
  config_name "varnishlog"
  
  # Replace the message with this value.
  #config :message, :validate => :string, :default => "Hello World!"
  config :blacklist_sections, :validate => :array, :default => []

  public
  def register
    # Add instance variables 
  end # def register

  public
  def filter(event)
    items = event.get("[message]").split("\n")
    ##Remove Blacklisted items from items hash
    items = items.grepv(/(#{blacklist_sections.join("|")})/) if blacklist_sections.any?
    ##

    ##timestamps
    timestamps = items.grep(/Timestamp/)
    timestamps.each do |timestamp|
      if match = /-\s+Timestamp\s+(?<step>.*): (?<time_a>.*) (?<time_b>.*) (?<time_c>.*)/.match(timestamp)
        event.set("timestamp_" + match['step'], match['time_a'])
      end
    end
    ## VCL Log
    vcl_log = items.grep(/VCL_Log/)
    log_lines = []
    vcl_log.each_with_index do |log, index|
      if match = /-\s+VCL_Log\s+(?<log_line>.*)/.match(log)
        log_lines.push(match['log_line'])
      end
      if index == log_lines.size - 1
        event.set("VCL_Log", log_lines)
      end
    end

    # Requests
    ## Request headers.
    request_headers = items.grep(/ReqHeader/)
    request_headers.each do |header|
      if match = /-\s+ReqHeader\s+(?<header_name>.*?): (?<header_value>.*)/.match(header)
        event.set(match['header_name'], match['header_value'])
      end
    end
    ## Match ReqMethod.
    if method_match = /-\s+ReqMethod\s+(?<method>.*)/.match(items.grep(/ReqMethod/)[0])
      event.set("http-method", method_match['method'])
    end
    ## Match ReqURL.
    if url_match = /-\s+ReqURL\s+(?<url>\/.*)/.match(items.grep(/ReqURL/)[0])
      event.set("url", url_match['url'])
    end
    ## Match ReqProtocol.
    if protocol_match = /-\s+ReqProtocol\s+(?<protocol>.*)/.match(items.grep(/ReqProtocol/)[0])
      event.set("ReqProtocol", protocol_match['protocol'])
    end
    
    # Response
    ## Response headers.
    response_headers = items.grep(/RespHeader/)
    response_headers.each do |header|
      if match = /-\s+RespHeader\s+(?<header_name>.*?): (?<header_value>.*)/.match(header)
        event.set(match['header_name'], match['header_value'])
      end
    end
    ## Match RespProtocol
    if protocol_match = /-\s+RespProtocol\s+(?<protocol>.*)/.match(items.grep(/RespProtocol/)[0])
      event.set("RespProtocol", protocol_match['protocol'])
    end
    ## Match RespStatus
    status_match = items.grep(/RespStatus/)
    states = []
    status_match.each_with_index do |status, index|
      if match = /-\s+RespStatus\s+(?<status>.*)/.match(status)
         states.push(match['status'].to_i)
      end
      if index == status_match.size - 1
	 event.set("RespStatus", states)
      end
    end
    ## Match RespReason
    response_reason = items.grep(/RespReason/)
    reasons = []
    response_reason.each_with_index do |reason, index|
      if match = /-\s+RespReason\s+(?<reason>.*)/.match(reason)
         reasons.push(match['reason'])
      end
      if index == response_reason.size - 1
        event.set("RespReason", reasons)
      end
    end
    
    if @message
      # Replace the event message with our message as configured in the
      # config file.
      event.set("message", @message)
    end

    # filter_matched should go in the last line of our successful code
    filter_matched(event)
  end # def filter
end # class LogStash::Filters::Varnishlog
