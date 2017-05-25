#!/usr/bin/env ruby

# Copyright (C) 2017 Dmitry Yakimenko (detunized@gmail.com).
# Licensed under the terms of the MIT license. See LICENCE for details.
require "httparty"

HOST = "https://my.1password.com/api/v1"

#
# Network
#

class Http
    include HTTParty

    # Network modes:
    #  - :default: return mock response if one is provided
    #  - :force_online: always go online
    #  - :force_offline: never go online and return mock even if it's nil
    def initialize network_mode = :default
        @network_mode = network_mode
        @log = true
    end

    def get url, headers = {}, mock_response = nil
        if @log
            puts "=" * 80
            puts "GET to #{url}"
        end

        response = get_raw url, headers, mock_response

        if @log
            puts "-" * 40
            puts "HTTP: #{response.code}"
            ap response.parsed_response
        end

        raise "Request failed with code #{response.code}" if !response.success?

        response.parsed_response
    end

    def get_raw url, headers = {}, mock_response = nil
        return make_response mock_response if should_return_mock? mock_response

        self.class.get url, {headers: headers}
    end

    def should_return_mock? mock_response
        case @network_mode
        when :default
            mock_response
        when :force_online
            false
        when :force_offline
            true
        else
            raise "Invalid network_mode '#{@network_mode}'"
        end
    end

    def make_response mock_response
        @response_class ||= Struct.new :parsed_response, :code, :success?
        @response_class.new mock_response, 200, true
    end
end

def get_user_info username, uuid, http
    mock_response = {
                  "status" => "ok",
               "sessionID" => "HNGWF3SOH5HVHCLF6GFG4RXV5Y",
        "accountKeyFormat" => "A3",
          "accountKeyUuid" => "FRN8GF",
                "userAuth" => {
                "method" => "SRPg-4096",
                   "alg" => "PBES2g-HS256",
            "iterations" => 100000,
                  "salt" => "-JLqTVQLjQg08LWZ0gyuUA"
        }
    }

    url = [HOST, "auth", username, uuid, "-"].join "/"
    headers = {
        "X-AgileBits-Client" => "1Password for Web/343"
    }

    http.get url, headers, mock_response
end

def login username, password, account_key, uuid, http
    ap get_user_info username, uuid, http
end

#
# main
#

http = Http.new
config = YAML::load_file "config.yaml"
login config["username"], config["password"], config["account_key"], config["uuid"], http
