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
    self.reject { |elem| elem.match(/#{regex}/i) }.each(&block)
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
  config :normalize_fieldnames, :validate => :boolean, :default => false
  public
  def register
    # Add instance variables
  end # def register

  public
  def filter(event)
    items = event.get("[message]").split("\n")
    if request=/\*+\s+<<\s+(?<type>\w+)\s+>>\s+/.match(items[0])
      event.set("type", request['type'].downcase)
    end
    ##Remove Blacklisted items from items hash
    items = items.grepv(blacklist_sections.join("|")) if blacklist_sections.any?
    ##

    ##timestamps
    timestamps = items.grep(/Timestamp/)
    timestamps.each do |timestamp|
      if match = /-\s+Timestamp\s+(?<step>.*): (?<time_a>.*) (?<time_b>.*) (?<time_c>.*)/.match(timestamp)
        event.set(normalize_fields("timestamp_" + match['step'] ), match['time_a'])
        event.set(normalize_fields("timestamp_" + match['step'] + "_raw"), match['time_a'] + " " + match['time_b'] + " " + match['time_c'])
      end
    end

    ##Acct
    account = items.grep(/(Be|Req)Acct/)
    account.each do |acct|
      if acct_match = /-\s+(Be|Req)Acct\s+(?<size_a>\d+)\s+(?<size_b>\d+)\s+(?<size_c>\d+)\s+(?<size_d>\d+)\s+(?<size_e>\d+)\s+(?<size_f>\d+)/.match(acct)
        event.set("bytes", acct_match['size_e'])
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
        event.set(normalize_fields("VCL_Log"), log_lines)
      end
    end

    # Requests
    ## Request headers.
    request_headers = items.grep(/(Be)?([rR]eq|[rR]esp)Header/)
    request_headers.each do |header|
      if match = /-+\s+(Be)?([rR]eq|[rR]esp)Header\s+(?<header_name>.*?): (?<header_value>.*)/.match(header)
        event.set(normalize_fields(match['header_name']), match['header_value'])
      end
    end
    ## Match ReqMethod.
    if method_match = /-+\s+(Be)?([rR]eq|[rR]esp)Method\s+(?<method>.*)/.match(items.grep(/(Be)?([rR]eq|[rR]esp)Method/)[0])
      event.set("http_method", method_match['method'])
    end
    ## Match ReqURL.
    if url_match = /-+\s+(Be)?([rR]eq|[rR]esp)URL\s+(?<url>\/.*)/.match(items.grep(/(Be)?([rR]eq|[rR]esp)URL/)[0])
      event.set("url", url_match['url'])
    end
    ## Match ReqProtocol.
    if protocol_match = /-+\s+(Be)?([rR]eq|[rR]esp)Protocol\s+(?<protocol>.*)/.match(items.grep(/(Be)?([rR]eq|[rR]esp)Protocol/)[0])
      event.set("protocol", protocol_match['protocol'])
    end
    ## FetchError.
    if error_match = /-+\s+FetchError\s+(?<error>.*)/.match(items.grep(/FetchError/)[0])
      event.set("FetchError", error_match['error'])
    end
    ## Match RespStatus
    status_match = items.grep(/(Be)?([rR]eq|[rR]esp)Status/)
    states = []
    status_match.each_with_index do |status, index|
      if match = /-+\s+(Be)?([rR]eq|[rR]esp)Status\s+(?<status>.*)/.match(status)
        states.push(match['status'].to_i)
      end
      if index == status_match.size - 1
        event.set("http-rc", states)
      end
    end
    ## Match RespReason
    response_reason = items.grep(/(Be)?([rR]eq|[rR]esp)Reason/)
    reasons = []
    response_reason.each_with_index do |reason, index|
      if match = /-+\s+(Be)?([rR]eq|[rR]esp)Reason\s+(?<reason>.*)/.match(reason)
        reasons.push(match['reason'])
      end
      if index == response_reason.size - 1
        event.set("reason", reasons)
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

  private
  def normalize_fields(name)
    name.capitalize.gsub(/[_-](\w)/){$1.upcase} if @normalize_fieldnames
  end
end # class LogStash::Filters::Varnishlog
