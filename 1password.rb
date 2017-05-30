#!/usr/bin/env ruby

# Copyright (C) 2017 Dmitry Yakimenko (detunized@gmail.com).
# Licensed under the terms of the MIT license. See LICENCE for details.
require "hkdf"
require "pbkdf256"
require "securerandom"
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

    def post url, args, headers = {}, mock_response = nil
        if @log
            puts "=" * 80
            puts "POST to #{url}"
            ap args
        end

        response = post_raw url,
                            args.to_json,
                            headers.merge({"Content-Type" => "application/json; charset=UTF-8"}),
                            mock_response

        if @log
            puts "-" * 40
            puts "HTTP: #{response.code}"
            ap response.parsed_response
        end
    end

    #
    # private
    #

    def get_raw url, headers = {}, mock_response = nil
        return make_response mock_response if should_return_mock? mock_response

        self.class.get url, headers: headers
    end

    def post_raw url, args, headers, mock_response
        return make_response mock_response if should_return_mock? mock_response

        self.class.post url, body: args, headers: headers
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

#
# Utils
#

module Util
    def self.bn_to_hex bn
        bn
            .to_s(16)
            .sub(/^0*/, "")
            .downcase
    end

    def self.bn_from_hex hex
        OpenSSL::BN.new hex, 16
    end

    def self.bn_from_bytes str
        OpenSSL::BN.new str, 2
    end

    def self.str_to_base64 str
        Base64.urlsafe_encode64(str).sub(/\=*$/, "")
    end

    def self.base64_to_str base64_or_base64url
        Base64.urlsafe_decode64 base64_to_base64url base64_or_base64url
    end

    def self.base64_to_base64url base64
        base64
            .tr("+/", "-_")
            .sub(/\=*$/, "")
    end

    def self.bytes_to_str bytes
        bytes.pack "c*"
    end

    def self.str_to_hex str
        str.unpack("H*")[0]
    end

    URL_ESCAPE_REGEXP = Regexp.new "[^#{URI::PATTERN::UNRESERVED}]"

    def self.url_escape url
        URI.escape url, URL_ESCAPE_REGEXP
    end

    def self.url_escape_join components
        components.map { |i| url_escape i }.join "/"
    end

    def self.normalize_utf8 str
        str.unicode_normalize :nfkd
    end
end

module Crypto
    def random size
        SecureRandom.random_bytes size
    end

    def self.sha256 str
        Digest::SHA256.digest str
    end

    def self.hkdf ikm, info, salt
        h = HKDF.new ikm, info: info, salt: salt, algorithm: "sha256"
        h.next_bytes 32
    end

    def self.pbes2 algorithm, password, salt, iterations
        # TODO: PBKDF2 doesn't work anymore, PBKDF256 supports only sha256
        hashes = {
            "PBES2-HS512" => nil,
            "PBES2g-HS512" => nil,
            "PBES2-HS256" => "sha256",
            "PBES2g-HS256" => "sha256",
        }

        hash = hashes[algorithm]
        raise "Unsupported algorithm '#{algorithm}'" if hash.nil?

        PBKDF256.dk password, salt, iterations, 32
    end

    # Notes on the encryption
    #
    # It seems 1password has AES-256-GCM hardcoded, though there are the "alg"
    # and the "enc" parameters everywhere
    # The authentication tag is simply appended to the ciphertext (the last 16 bytes)

    def self.encrypt_aes256gcm plaintext, iv, key
        c = OpenSSL::Cipher.new('aes-256-gcm')
        c.encrypt
        c.key = key
        c.iv = iv
        c.auth_data = ""
        c.update(plaintext) + c.final + c.auth_tag
    end

    def self.decrypt_aes256gcm ciphertext, iv, key
        c = OpenSSL::Cipher.new('aes-256-gcm')
        c.decrypt
        c.key = key
        c.iv = iv
        c.auth_tag = ciphertext[-16..-1]
        c.auth_data = ""
        c.update(ciphertext[0...-16]) + c.final
    end
end

#
# 1Password
#

class Session
    attr_reader :id,
                :key_format,
                :key_uuid,
                :srp_method,
                :key_method,
                :iterations,
                :salt

    def self.from_json server_response
        new server_response
    end

    def initialize server_response
        @id = server_response["sessionID"]
        @key_format = server_response["accountKeyFormat"]
        @key_uuid = server_response["accountKeyUuid"]
        @srp_method = server_response["userAuth"]["method"]
        @key_method = server_response["userAuth"]["alg"]
        @iterations = server_response["userAuth"]["iterations"]
        @salt = Util.base64_to_str server_response["userAuth"]["salt"]
    end
end

class AccountKey
    attr_reader :format, :uuid, :key

    def self.parse str
        s = str.upcase.gsub "-", ""
        format = s[0, 2]
        if (format == "A2" && s.size == 33) || (format == "A3" && s.size == 34)
            new format: format,
                uuid: s[2...8],
                key: s[8..-1]
        else
            raise "Invalid account key format"
        end
    end

    def initialize format:, uuid:, key:
        @key = key
        @format = format
        @uuid = uuid
    end

    def hash
        Crypto.hkdf @key, @format, @uuid
    end

    def combine str
        h = hash.bytes
        s = str.bytes
        raise "Size doesn't match hash function" if h.size != s.size
        Util.bytes_to_str h.size.times.map { |i| h[i] ^ s[i] }
    end
end

class EncryptionKey
    # TODO: Remove copy paste
    CONTAINER_TYPE = "b5+jwk+json"
    ENCRYPTION_MODE = "A256GCM"

    attr_reader :id, :key

    def initialize id:, key:
        @id = id
        @key = key
    end

    def encrypt plaintext, iv
        ciphertext = Crypto.encrypt_aes256gcm plaintext, iv, @key
        ciphertext_base64 = Util.str_to_base64 ciphertext
        iv_base64 = Util.str_to_base64 iv

        # The order is important as it matches one in Js. Otherwise mitmproxy doesn't
        # recognize the request. Like this it's possible to replay against the flow
        # recorded with the webpage.
        {
            "kid" => @id,
            "enc" => ENCRYPTION_MODE,
            "cty" => CONTAINER_TYPE,
            "iv" => iv_base64,
            "data" => ciphertext_base64,
        }
    end

    def decrypt payload
        raise "Unsupported container type '#{payload["cty"]}'" if payload["cty"] != CONTAINER_TYPE
        raise "Unsupported encryption '#{payload["enc"]}'" if payload["enc"] != ENCRYPTION_MODE
        raise "Session ID does not match" if payload["kid"] != @id

        ciphertext = Util.base64_to_str payload["data"]
        iv = Util.base64_to_str payload["iv"]

        Crypto.decrypt_aes256gcm ciphertext, iv, @key
    end
end

SIRP_N = Util.bn_from_hex "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" +
                          "29024E088A67CC74020BBEA63B139B22514A08798E3404DD" +
                          "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" +
                          "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" +
                          "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D" +
                          "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F" +
                          "83655D23DCA3AD961C62F356208552BB9ED529077096966D" +
                          "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B" +
                          "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9" +
                          "DE2BCBF6955817183995497CEA956AE515D2261898FA0510" +
                          "15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64" +
                          "ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7" +
                          "ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6B" +
                          "F12FFA06D98A0864D87602733EC86A64521F2B18177B200C" +
                          "BBE117577A615D6C770988C0BAD946E208E24FA074E5AB31" +
                          "43DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D7" +
                          "88719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA" +
                          "2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6" +
                          "287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED" +
                          "1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA9" +
                          "93B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934063199" +
                          "FFFFFFFFFFFFFFFF"
SIRP_g = OpenSSL::BN.new 5

class Srp
    def self.perform username, password, account_key, session, http
        srp = new username, password, account_key, session, http
        srp.perform
    end

    #
    # Private
    #

    def initialize username, password, account_key, session, http
        @username = username
        @password = password
        @account_key = account_key
        @session = session
        @http = http
    end

    def perform
        compute_a
        exchange_a_for_b
        validate_b
        compute_key
    end

    def compute_a
        @secret_a = Util.bn_from_bytes "\0" * 32 # TODO: Make it random
        @shared_a = SIRP_g.mod_exp @secret_a, SIRP_N
    end

    def exchange_a_for_b
        mock_response = {
            "encConfig" => nil,
            "sessionID" => "ZIMW7SO4URE5PEP2KHPZHWMRMA",
                "userB" => "66b5ab6c3b62547c2cc2f37b3da4c1bccc59163212442fb" +
                           "a5b0c5732ec89da67ed747db04a2763af983be1a56bc605" +
                           "cee5ac553806d60c5cb535afe4a0d842cd7065fe895fe2c" +
                           "6bff5e85f79fb530275c5cbb413eecb44e10b3c56dac2c1" +
                           "cbaf280eadb5246ed26894fc37d6fbdd4edf29a3b8e9deb" +
                           "35790de05316a8890c8dab50a9ac2f943c9085bb8280a75" +
                           "588458f6251accd49ec1296bf018eb26401ed6328c265e6" +
                           "fb88686f878508e98e8fc0fc59c08e71a73f71316867afb" +
                           "3b85aeb21efdee459840393822ebc7ec630dfb442cfbe81" +
                           "9cb1d7d72cd33eb2bf0e2545cbe45646db4e6fc1c392f5d" +
                           "35c34412485c3b29a6360163a588858883ec131b1193de1" +
                           "a299ca5047c78ec28102b092e9924d902a57b6d3777f0bc" +
                           "dfb59a7a27527f88c448db39a93d590d7a9e92d89466d81" +
                           "4a745a3b773b091e1b3f9a3978767ea4ccc3798df821b6a" +
                           "1fc139fd076557f4983e0e561a25088342436246cd63b50" +
                           "e52a294f6d49e45cfddb3d70ed9d17f05550bf63720d963" +
                           "d13630fa102b8deb42047dc70cf176c64d3e48167ca31d5" +
                           "17f80ad72dcef639b1fdb91dc7a8ae485fa045a6770b3f1" +
                           "b3d1abe72d791eb015265accac06f921e7210664f6bfa76" +
                           "3784c8b5e77c0313d732291840e1088f77b8f4215edcb41" +
                           "8eabdfe87dbcbda9c135eb95824d1899eda337d933a5577" +
                           "ac95539510cfed7d34831eb859daae1a62a1d"
        }

        args = {
            "sessionID" => @session.id,
            "userA" => Util.bn_to_hex(@shared_a)
        }

        response = @http.post [HOST, "auth"].join("/"), args, {}, mock_response
        raise "Invalid response" if response["sessionID"] != @session.id

        @shared_b = Util.bn_from_hex response["userB"]
    end

    def validate_b
        raise "Validation failed" if @shared_b % SIRP_N == 0
    end

    def compute_key
        # Some arbitraty crypto computation, variable names don't have much meaning
        a_b = Util.bn_to_hex(@shared_a) + Util.bn_to_hex(@shared_b)
        hash_a_b = Util.bn_from_bytes Crypto.sha256 a_b
        x = compute_x
        s = Util.bn_from_bytes @session.id
        y = @shared_b - SIRP_g.mod_exp(x, SIRP_N) * s
        z = y.mod_exp @secret_a + hash_a_b * x, SIRP_N
        key = Crypto.sha256 Util.bn_to_hex z

        EncryptionKey.new id: @session.id, key: key
    end

    def compute_x
        method = @session.srp_method
        iterations = @session.iterations

        if iterations == 0
            raise "Not supported yet"
        elsif method.start_with? "SRP-"
            raise "Not supported yet"
        elsif method.start_with? "SRPg-"
            k1 = Crypto.hkdf @session.salt, method, @username
            k2 = Crypto.pbes2 @session.key_method, @password, k1, iterations
            Util.bn_from_bytes @account_key.combine k2
        else
            raise "Invalid method '#{auth["userAuth"]["method"]}'"
        end
    end
end

def start_new_session username, uuid, http
    mock_response = {
                  "status" => "ok",
               "sessionID" => "ZIMW7SO4URE5PEP2KHPZHWMRMA",
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

    response = http.get url, headers, mock_response

    Session.from_json response
end

# TODO: Think of a better name, since the verification is just a side effect. Is it?
def verify_key key, session, http
    mock_response = {
         "cty" => "b5+jwk+json",
        "data" => "Fn2Z4qlq3uqqfzLLyhe_tsMOeA13iRyHiBy0HFlJRjQGXk-vrcN5L0zM" +
                  "pOm3EBFqdOY1UqMXRuFwPuEXiBCHSs_D_ErXXCfjH6DGa51j0tVSVpnb" +
                  "u6SMAZ1DVZ05XsFlT64rwr7i2g6LNmXQX767EKpU9WRrm34b08iXF7Pd" +
                  "lAfnN2j60jusgPniphiU5XSgRabaqq3sN8SjoZ82zwcSNRVw7qthO2EC" +
                  "fl_1BNmopv5n58LNRzRrQSFkKXLuOtAM_XiJNJc3H4bCV3QfNgK6bBGU" +
                  "p6A2-ncwcmK6HWUKb-k6Ice3j3QrJk_J9c6n",
         "enc" => "A256GCM",
          "iv" => "s2wM_JBD77IqCsE6",
         "kid" => "ZIMW7SO4URE5PEP2KHPZHWMRMA"
    }

    payload = JSON.dump({"sessionID" => session.id})
    encrypted_payload = key.encrypt payload, "\0" * 12 # TODO: Generate random
    response = http.post [HOST, "auth", "verify"].join("/"),
               encrypted_payload,
               {},
               mock_response
    JSON.load key.decrypt response
end

def login username, password, account_key, uuid, http
    account_key = AccountKey.parse account_key

    # Step 1: Request to initiate a new session
    session = start_new_session username, uuid, http

    # Step 2: Perform SRP exchange
    key = Srp.perform username, password, account_key, session, http

    # Step 3: Verify the key with the server
    ap verify_key key, session, http
end

#
# main
#

http = Http.new :force_offline
config = YAML::load_file "config.yaml"
login config["username"], config["password"], config["account_key"], config["uuid"], http
