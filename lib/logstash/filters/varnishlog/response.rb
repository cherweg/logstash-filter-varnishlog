#!/usr/bin/env ruby

require 'headers'

#
# VarnishLog::Response - This class is used to create objects that represent HTTP
#                        responses from Varnish's perspective.
#

class VarnishLog
  class Response < Headers

    # Assume the powers of Headers.
    def initialize
      super
    end

  end
end
