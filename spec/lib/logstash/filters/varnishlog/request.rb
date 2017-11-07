#!/usr/bin/env ruby

require 'headers'

#
# VarnishLog::Request - This class is used to create objects that represent HTTP
#                       requests from Varnish's perspective.
#

class VarnishLog
  class Request < Headers
    @methods = [:method, :url, :protocol]
    @methods.each do |method|
      attr_accessor method
    end

    # Assume the powers of Headers.
    def initialize
      super
    end

  end
end

