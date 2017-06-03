#!/usr/bin/env ruby

# Copyright (C) 2017 Dmitry Yakimenko (detunized@gmail.com).
# Licensed under the terms of the MIT license. See LICENCE for details.
require "hkdf"
require "pbkdf256"
require "securerandom"
require "httparty"
require "json/jwt"

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
        @json_headers = {
            "Content-Type" => "application/json; charset=UTF-8"
        }
    end

    def get url, headers = {}, mock_response = nil
        make_request "GET", url do
            get_raw url, headers, mock_response
        end
    end

    def post url, args = {}, headers = {}, mock_response = nil
        make_request "POST", url do
            post_raw url,
                     args.to_json,
                     headers.merge(@json_headers),
                     mock_response
        end
    end

    def put url, args = {}, headers = {}, mock_response = nil
        make_request "PUT", url do
            put_raw url,
                    args.to_json,
                    headers.merge(@json_headers),
                    mock_response
        end
    end

    #
    # private
    #

    # Log and make the request
    def make_request method, url
        if @log
            puts "=" * 80
            puts "#{method} to #{url}"
        end

        response = yield

        if @log
            puts "-" * 40
            puts "HTTP: #{response.code}"
            ap response.parsed_response
        end

        raise "Request failed with code #{response.code}" if !response.success?

        response.parsed_response
    end

    def get_raw url, headers, mock_response
        return make_response mock_response if should_return_mock? mock_response

        self.class.get url, headers: headers
    end

    def post_raw url, args, headers, mock_response
        return make_response mock_response if should_return_mock? mock_response

        self.class.post url, body: args, headers: headers
    end

    def put_raw url, args, headers, mock_response
        return make_response mock_response if should_return_mock? mock_response

        self.class.put url, body: args, headers: headers
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

class String
    def d64
        Util.base64_to_str self
    end
end

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

class KeySet
    attr_reader :id, :aes, :rsa

    def initialize id:, aes:, rsa:
        @id = id
        @aes = aes
        @rsa = rsa

        raise "AES key ID doesn't match" if aes && aes.id != id
        raise "RSA key ID doesn't match" if rsa && rsa.id != id
    end

    def key scheme
        case scheme
        when "A256GCM"
            @aes
        when "RSA-OAEP"
            @rsa
        else
            raise "Encryption scheme '#{scheme}' is not supported"
        end
    end

    def decrypt jwe_container
        enc = jwe_container["enc"]
        k = key enc
        raise "'#{enc}' encryption scheme is not supported by keyset '#{@id}'" if k.nil?

        k.decrypt jwe_container
    end
end

class AesKey
    CONTAINER_TYPE = "b5+jwk+json"
    ENCRYPTION_SCHEME = "A256GCM"

    attr_reader :id

    def self.from_json json
        new id: json["kid"],
            key: json["k"].d64
    end

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
            "enc" => ENCRYPTION_SCHEME,
            "cty" => CONTAINER_TYPE,
            "iv" => iv_base64,
            "data" => ciphertext_base64,
        }
    end

    def decrypt jwe_container
        cty = jwe_container["cty"]
        enc = jwe_container["enc"]
        kid = jwe_container["kid"]

        raise "Unsupported container type '#{cty}'" if cty != CONTAINER_TYPE
        raise "Unsupported encryption scheme '#{enc}'" if enc != ENCRYPTION_SCHEME
        raise "Key ID does not match" if kid != @id

        ciphertext = Util.base64_to_str jwe_container["data"]
        iv = Util.base64_to_str jwe_container["iv"]

        Crypto.decrypt_aes256gcm ciphertext, iv, @key
    end
end

class RsaKey
    CONTAINER_TYPE = "b5+jwk+json"
    ENCRYPTION_SCHEME = "RSA-OAEP"

    attr_reader :id

    def self.from_json json
        # TODO: Get rid of JWK, it's only used to parse the key
        new id: json["kid"],
            key: JSON::JWK.new(json).to_key
    end

    def initialize id:, key:
        @id = id
        @key = key
    end

    def encrypt plaintext
        raise "'#{ENCRYPTION_SCHEME}' encryption is not supported"
    end

    def decrypt jwe_container
        cty = jwe_container["cty"]
        enc = jwe_container["enc"]
        kid = jwe_container["kid"]

        raise "Unsupported container type '#{cty}'" if cty != CONTAINER_TYPE
        raise "Unsupported encryption scheme '#{enc}'" if enc != ENCRYPTION_SCHEME
        raise "Key ID does not match" if kid != @id

        @key.private_decrypt jwe_container["data"].d64,
                             OpenSSL::PKey::RSA::PKCS1_OAEP_PADDING
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
    def self.perform client_info, session, http
        srp = new client_info, session, http
        srp.perform
    end

    #
    # Private
    #

    def initialize client_info, session, http
        @client_info = client_info
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

        response = @http.post ["auth"], args, mock_response
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

        AesKey.new id: @session.id, key: key
    end

    def compute_x
        method = @session.srp_method
        iterations = @session.iterations

        if iterations == 0
            raise "Not supported yet"
        elsif method.start_with? "SRP-"
            raise "Not supported yet"
        elsif method.start_with? "SRPg-"
            k1 = Crypto.hkdf @session.salt, method, @client_info.username
            k2 = Crypto.pbes2 @session.key_method, @client_info.password, k1, iterations
            Util.bn_from_bytes @client_info.account_key.combine k2
        else
            raise "Invalid method '#{auth["userAuth"]["method"]}'"
        end
    end
end

class ClientInfo
    attr_reader :username, :password, :account_key, :uuid

    def initialize username:, password:, account_key:, uuid:
        @username = username
        @password = password
        @account_key = AccountKey.parse account_key
        @uuid = uuid
    end
end

class Vault < Struct.new :id, :name, :accounts
    def initialize id:, name:, accounts:
        super id, name, accounts
    end
end

class Account < Struct.new :id, :name, :username, :password, :url, :notes
    def initialize id:, name:, username:, password:, url:, notes:
        super id, name, username, password, url, notes
    end
end

class OnePassword
    CLIENT_NAME = "1Password for Web"
    CLIENT_VERSION = "348"
    CLIENT_ID_STRING = "#{CLIENT_NAME}/#{CLIENT_VERSION}"

    MASTER_KEY_ID = "mp"

    def initialize http
        @http = http
        @host = "my.1password.com"
        @keysets = {}
        @session = nil
    end

    # Returns an array of Vault objects
    def open_all_vaults client_info
        # Step 1: Request to initiate a new session
        @session = start_new_session client_info

        # Step 2: Perform SRP exchange
        add_key Srp.perform client_info, @session, self

        # Step 3: Verify the key with the server
        verify_session_key

        # Step 4: Get account info
        account_info = get_account_info

        # Step 5: Derive and decrypt keys
        decrypt_keysets account_info["user"]["keysets"], client_info
        decrypt_group_keys account_info["groups"]
        decrypt_vault_keys account_info["user"]["vaultAccess"]

        # Step 6: Get vaults
        vaults = get_vaults account_info["vaults"]

        # Step 7: Sign out not leave stale sessions
        sign_out

        # Done
        vaults
    end

    #
    # Key management
    #

    def session_key
        @keysets[@session.id].aes
    end

    def add_key key
        @keysets[key.id] = KeySet.new id: key.id, aes: key, rsa: nil
    end

    def add_keyset keyset
        @keysets[keyset.id] = keyset
    end

    # Decrypts with one of the stored keysets
    def decrypt jwe_container
        kid = jwe_container["kid"]
        ks = @keysets[kid]
        raise "Keyset '#{kid}' doesn't exist" if ks.nil?

        ks.decrypt jwe_container
    end

    # Decrypts with one of the stored keysets
    def decrypt_json jwe_container
        JSON.load decrypt jwe_container
    end

    def decrypt_with_key jwe_container, key
        key.decrypt jwe_container
    end

    def decrypt_json_with_key jwe_container, key
        JSON.load decrypt_with_key jwe_container, key
    end

    #
    # Crypto
    #

    # TODO: Remove account_info parameter
    def decrypt_keysets keysets, client_info
        sorted = keysets.sort_by { |i| i["sn"] }.reverse

        if sorted[0]["encryptedBy"] != MASTER_KEY_ID
            raise "Invalid keyset (key must be encrypted by '#{MASTER_KEY_ID}')"
        end
        # It's encrypted with the key derived from the username, the master password,
        # the account key and the salt received from the server
        add_key derive_master_key sorted[0]["encSymKey"], client_info

        # Decrypt the all the keysets. The first one should be decrypted by 'mp'.
        # And the next ones with already decrypted keys at that point.
        sorted.each do |i|
            add_keyset decrypt_keyset i
        end
    end

    def decrypt_keyset keyset
        # Should be encrypted with one of the keys decrypted at this point
        aes = AesKey.from_json decrypt_json keyset["encSymKey"]

        # Should be encrypted with the AES key we've just decrypted
        rsa = RsaKey.from_json decrypt_json_with_key keyset["encPriKey"], aes

        KeySet.new id: keyset["uuid"], aes: aes, rsa: rsa
    end

    def derive_master_key key_info, client_info
        algorithm = key_info["alg"]
        encryption = key_info["enc"]
        iterations = key_info["p2c"]
        salt = Util.base64_to_str key_info["p2s"]
        username = client_info.username.downcase
        password = Util.normalize_utf8 client_info.password
        account_key = client_info.account_key

        if algorithm.start_with? "PBES2-"
            raise "Not supported yet"
        elsif algorithm.start_with? "PBES2g-"
            k1 = Crypto.hkdf salt, algorithm, username
            k2 = Crypto.pbes2 algorithm, password, k1, iterations
            key = account_key.combine k2

            AesKey.new id: MASTER_KEY_ID, key: key
        else
            raise "Invalid algorithm '#{algorithm}'"
        end
    end

    def decrypt_group_keys groups
        groups.each do |i|
            add_keyset decrypt_keyset i["userMembership"]["keyset"]
        end
    end

    def decrypt_vault_keys vault_access
        vault_access.each do |i|
            add_key AesKey.from_json decrypt_json i["encVaultKey"]
        end
    end

    #
    # Network requests
    #

    # Returns the new session
    def start_new_session client_info, retry_count = 1
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

        response = get ["auth", client_info.username, client_info.uuid, "-"], mock_response

        # All good
        return Session.from_json response if response["status"] == "ok"

        # Out of retries
        raise "Failed to start a new session" if retry_count <= 0

        # Handle known problems
        status = response["status"]
        case status
        when "device-not-registered"
            register_device client_info, response["sessionID"]
        when "device-deleted"
            reauthorize_device client_info, response["sessionID"]
        else
            raise "Failed to start a new session, unsupported response status '#{status}'"
        end

        # Retry
        start_new_session client_info, retry_count - 1
    end

    def register_device client_info, temp_session_id
        mock_response = {"success" => 1}
        response = post_with_temp_session ["device"], {
                     "uuid" => client_info.uuid,
               "clientName" => CLIENT_NAME,
            "clientVersion" => CLIENT_VERSION
        }, temp_session_id, mock_response

        raise "Failed to register the device '#{client_info.uuid}'" if response["success"] != 1
    end

    def reauthorize_device client_info, temp_session_id
        mock_response = {"success" => 1}
        response = put_with_temp_session ["device", client_info.uuid, "reauthorize"],
                                         {},
                                         temp_session_id,
                                         mock_response

        raise "Failed to reauthorize the device '#{client_info.uuid}'" if response["success"] != 1
    end

    # TODO: Think of a better name, since the verification is just a side effect. Is it?
    def verify_session_key
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

        payload = JSON.dump({"sessionID" => @session.id})
        encrypted_payload = session_key.encrypt payload, "\0" * 12 # TODO: Generate random
        response = post_json ["auth", "verify"], encrypted_payload, mock_response

        # Just to verify that it's a valid JSON and it has some keys.
        # Technically it should've failed by now eather in decrypt or JSON parse
        raise "Session key verification failed" if !response.key? "userUuid"
    end

    def get_account_info
        mock_response = {
             "kid" => "ZIMW7SO4URE5PEP2KHPZHWMRMA",
             "enc" => "A256GCM",
             "cty" => "b5+jwk+json",
              "iv" => "aNWI4jZzNdXUWQR4",
            "data" => "r0xKVXot9CpZdOrpy9r_FY5uhNveWSfwWrn8bhTAQy_fheTv0d16WYoFy7ITz2mat8IH0KTq8c-74hfSdHIyZHf2GyZi6zQZfB8HdtNtn1mmBVDiGDEUyBPT7qpNoBizhQzR3gsI1khNv2KyfwpF4SZg_Amul8Vq0GcQn6s7GjfijQzoRDEiTEEfqCpPpTlN3KjFt4c1Cv-W05a4W1YKvDm2KFLbmWmGMYP5HXf-ngAkEofPlHjuCWK5punYWWg8w2x4hOQ6yeiGrFxF3uQS7HXbV9UAnQP2YvfY80bWc-tqoP8qpPkOe_4CV1dRqkaOlW5qFFpz74ObGwDv5E4nq06PQ29kG3RV60a6lnyk59XBRpRr5IUy0Eg64Otw-vE1fe3MqycSw_ouc2uuuq9WweF4C2i4JUQ2fr3v5J5tDGX__cHerniA6nT9bwujSPiPlrNdfHAVbQ3GURYHvnoJveHketqhd-ayTnZascENEfGRgc-MMpI3vK-aN-HV78z0jI1_JMl9lhbu6ASNXKXuwcrfO8MFf8hDa6KvneSgbXkwF0J-gIjJ2nsw_f9UPS9ceJgbfLK5SvQ72uqW5pFJUxJuIisLobER_zGoqdolKt4lef7qFbO4Qn_SpjJ4nBdssLWX6ghdrmqNpGumIMGojGayMCO7SUGqE1dEsa2jzEKp5ht15NFVhJAxgOAtTZOulOgzLMZ2n0r3gz66msRjKYTZ2RA0eox2lyj_hpSvW3d1Xueb3UMZmi6VgZBZ_ziC6VjebO4Ni17dIgRIzJSu7XKXxW5xUBqVtiAdkHfax_2e3X3orUkiU2HJGXIgJjW34j5vWvLzNgN05AtcSxBwhEn91SwuHOB_0moQHsOZJFNyoXaZ6vgtGR7xdu2cZkiOrIcuVl42dg40tBnoXYptUwLMD5x3eu6xG9tBapPhPUHy0tI_VypMQyLs-4XIPVeFRfDZw6FrQXOQfhKWrGa4H_tNtefWUPJ2d1cTYut3_7q2U0LaYz1npdaZ1KUc5z-VrSDKbEt0GcwdczdcdDe3sNtAasySHM0JpTP-uwpfH74IkRUy4x4hiB9x3NnTcImwmPWy-2ce2U3wbHYpXZyp7Vj6_uBVI6E3-1mJaVLuO-oPZjCLiV54e4_xJIxu66BkeqytWfmOQ9tswGaLKxLBXpdV_NFs4O-LXwNpIYOS1EiRbjvc90q5yVMJIHOLGJ6jJnCWkTyPjQflIIi6FGXR6TPuALVaJroISjUzS3SyMWau0BRlUaBQ9wDM-m0EBJiZ0yTmm_Y79qU7WZ2jlHbfuioJwkwhFKdcixeopbomaspiQBVtfYAqbkGHwdRL_yL4igZpxA_zoAIACYQp8xQ7KIvBrn5WuELUZbBp-3chLKdW6PTWOZvh-BAjzGEIsxO92MHFhtL_brIfmTvT2nBwPMKmFa0VpiuN66ZhOi4evIB7B2IGnRO-2SyMz6RE9WAKg4f1k31WHPZftMFMuHj3vhohWKpGDb_IFjLTL9Dt8sirxaqHfN3W2W30Gt7Ldz6jvAcC4oCI2abd3f_YS1Im8i9o5YgQp03vbtifJ_6TSNkH0nUn6KbgBK8o-qJH1NiwvKeXRnfwY9KzdseHlGCPeV-hhHEfg6YpW_P0gA9cKYn30UVS62KUeex5tM10aFeWl5WyvjXQPQLu5siZl45CO3svq8K34GsS8XutZuKIQKQaAwk73_UdEDHPHiS8x4VBxiG3GN7DnXzbDa4FmDwRcvASufvzAS2XiCXuCAP8CkK9dZrCHRc-1D8qaSWTzLW7OhCGodvYWwL--1gO1HiGE-r4oeHA3wSZilX-3zEVUKdqAamvTgKphRDkRaU5-CeC6jE706xlk1-tMKrTr1SfkzMhnPFTMEy_bOJ-stYLJBMbQY7sPcHDgOjMhtNyizmdcnLGDZgfKivzlwoptNQO7M1X-A4pWKG449Cnqw1t4zyoYO1G1wsPTNx2ccJpUv3VTAPJ4fPgZ-xJVW679SSd6LWXHR4T8k1NbLsNQS739Ol_r1oTTHTXmixEIdOZPwCgXVp0RD9-kuuYOOYBBKGSPjw12WjFYIU3eCZYjMBoHgLWVM4bd5ErkGfVw7BmYJOIxf5M-Qb5yNh8ruK39aeAsK2umgBuTWRrcs-HZIuyxGP9yibVWuG5eu2GBKa-Min4OFBGXE-uoXH8GUHZ6_G3WEkckH-2DlX5U0Li1xVlvu8V8sHyINGHfMbW1-9VyBiDAJVIZ0fldZt8cTZuFWOReZp1XQfHyo1_uXONdMsVNHJPCNoGaD3xOkHyo2w5iwOSqjwV4dmkQB7SIxf1z9dUpiKPzUjrSX_6698CPm262d8Y-EqF4C88QngDInsKIONoFwGwZYxMgY27CZAyLE65vecXyScUmWxx_GchSyNsM5iWA2XYwkcMgwMxwHRrTAQOFhzWWvKVBMMJOVtwqsC6Q8508-SpTGtnjDaiee_PtH_fy_aLZnyoSBYA67Y0imB1wXptvZ10VW9ELVSMVF1c8tL9_bzwXiKkBxQJ7XjIMcQ_pOXgt1LJRmsYqCTF1FdCyx3WpkEpqkqWZdU4K9PDjLy6dwjEhJkrGE6Jsb0IsjWAuYeK5Q-GrceILmBkweBhOte9Zj7OnKEHeN56VzoBTB9z0aQhTowfhNjWNrXykn3cTOaRYHr2nX6mPP8r6ukBCdCNpl1pDs2o6B6E7z1oUdswLQnduSn6WGNqVCZL9JJ6DsaHC0J7cwOs-vUgEuKiZav6Oa1SBytKT4j4Dv-eOKWbUAlVe4zZJfBrN6beBDhoy2UNoHZz9KtpbYDXTIu24TvdNPQIu3Svpu8yKnflLQRpOlm8TAmLq1ggEaKmjLfyW-blyXomcQh7tssgdmwcoT99NKK4UxTVKVrNW5NkbZIf18uxtS075Be0z7xuauNsq2aFqXKaNpleVB5dRWah1dNwhxNTrEv_PhwMBzTNkUj6bX7hJ4gPxdoRyuC99GkAH6eXGwqrzjZo9rvxVBKHFU-DeX52gWbZqc5N4aPdtOI8B4cqtUJeq_shmrzHfRiQn44lg0f0unypRxs8iqsHKynF37FHJEAcs3nxr0EmHKKE7NLrLYZtAkGrN27Vd7rFrcGJr7WMay1EfjiLfjhY6YwfFw6dQs5emy4TPhyyEXvd7-AXO2AT1EZ_uygFFwqQxyVGMfrkguxv07X9Cktg-MJHPJOvwJfQHnSOYyM6d-bC-xMaTLshGTlGPwnJxVvVh8yWexE0KHsVRYvk3mx_PVZG9fHhpOLLIpeQj6U3QG7iOh6-sATjeC1q0mjW21FbAnlhc23gMEIZMWb_ZBbNGzj8FfOFS6f9YtfQmFUGINylTRNL5YkCBvT514_HAI1RmHWm5VNdg7Syp3k4u-4gVB2ZS8LdC7fkYp8-nrAPnHsTmtCFeIwgbx3xo_UvO2p9LQTDD7P-GxFGJzrHfAWfJIRl8IeLMuumFhcqtIiiNciuJR4awZkBHrdpUfDu7afCDHRhU1B9hIv4bc8u6BpvFloZbr-oyDM0RoVG_yZHsoNObCZwIFn_Spvbl_xFxlu5oX4vPJXyW18YpbiTEOMyWDE44MrLd7baVH0umSVvGXmQ2en-bGPRZ0PQi3D2_xELWA_7c6Y3oQQuoxy-EjiHiOZIaJ2yw8zCV-FRovkYsy6qyXAyznBVOLjmX1nITyPNMsdlEviuyzzZ24yHZyW7E_xhXYd9wIN9TTsyegI8D3J5Lnmli9ffp6XM7rsC0OkLB8Orswm6CPRXtcYUDhPbj6zQs9LUL-KpbJXTS62VdJQeEzLSvWQ2WHq3nAEmbd7coH7Uyzpmorv6H4Zf0Va0TO9W1ze9V979XuB1mV4Z7onV2hZmxXI5JXIz8oMcmYlOt_vP6nZIKnnal7YSH5i9UBvwYmfphKYQc56WeqEIpEf3ndMdFy3anDrxGj7TJ17hEgzLZwRkkCyFWu9tivS1YUYehPp0KcvEnzwY3W0gvlXJT25ybgM-s-jmoNgh_gLmkTRXjiIEl1DdEgYU0UwrL0IaPyvwukvMI6pRrCcrULamD-lj_5qtNxBSuFgI5ibI2FbZOcn2JMJ1xvwVCWdi-4wwPGEesePXQGyYv3togBkC_vEfCJ2XjWAXwXA25x-g_KbPVUqjiwnMUmrRlkLCQk_PAvxQgpdh0NkuIhUdjw6WcvQauyWpmJaw_3qP5WSc8R9gJOlmDFWVr8oMOTDSW1JrXqDUpLqzrVPe0vWSjp3a1yUPryvxD8Nhf81M68twh8HumwR0LcG-P9KYVToEOxC9lqHQI9cCdMV25rOA8qPrQnYkOV0uRU-zIkaqma6Ro7_OZa7M-mt5wDvf3bftIXhiKYZ1NmptgOpK7FT7lrNCT9P3HsOKq5QyIjdFKgGIxzM0auBnRT3o0DPBJL3sjBPBTqutCMLTv4uTEw85PVrTzpr5eVcdYsAF5bzsotdWQXev7xvmr3QpbQTZeOLanJay0P2BMHvTfQzW1YmRt_ul7sXrNCIrLXGTHe89TJsQk99orfH2XMpD6XluXY6HoUBupd0lVNBEknoi_Or-U3TbMZBQ5OoT9rYc_E7KgnWMxcUfeTtnHGb148VdiclGjd5JNh0qE926ciy97SO08pFs5SooRRIJc78Yzv9cgYelsi6zff88UdkLWzpJjR0pDW5BLSiBolNGv_OEq8x5O3Tshfr6U9wCjpPI-QQgwXHElu9_o4BOKUkQuB0tDm3uAPJy2hUam66Fm5-EuVJjnzw3ClSBK5qz2--VC3jLNaWvA3oxao8WoeNtW3NabHYvk3eKrD9HJcG5YYDrf-GjQX6KWO7yim7iZCqWRz1WXXfXninBb_cgyOBFEw8K-bbkspYx27Vn-AbQCoyepbml521R66-lRx_7AxYzsIr148a3IFIDhHy8kdtWQnsB6IIjNRTkz8n34XAhDJJZbu-FMPYmHQd_jwDQM3sKQnUWct-okrtg95XGbN4HUoob4i39oqRKRy0ZLMvgc5K5n4fPBOOIqEt-nrfAS6_WI-AHvmc0BUZaY4OQ4sz7uvDh3JVkukUKozTS-qDYTdqqKlpKjL6TaXrR6yLDnHN0ymeYgrllSchbaTSlHPSjhi6_vxuAmvXaxMGE2P-srDwf6AqvxAv07F0QZeA_CqZDUvrFzyI3U43yTbx_QyTFE3BAjKNjSawb2YuXY_XtKLURwPvUqbh10JQcJDtxHStdnQmWgIG-wkRbYuJJHygyV4tikYN6gKiZst2RTiPPNyTVsFjdakbkAglWvatazydxP7BNugtEGwWf1Lj7MqxDdtYMM_dZGaTD_axuq28hB_Wj74ibrOrQg6dzMP3ZIGaaM0LSK3jHsbVicp9UF28PR28uplypo9oYJiVBai1JxDuP24gEQjafInE8qa-iHsa8BOF7uKqEHl0n_RUIgpPiRfHczAKdtIf1MlAF-tr8s05GpOzS9TqBaRR2BlqIYIMynlnDHmyNB9wySvP0IpczNHc_puOUyqDg1Efzu0BumGc92rFQZLQSX_VYAEBCELDBeJqhmpY8RPNIkuGpqukAJBfJbDZIxvZDHCVwpPNOB8bHOjO8K3dsrlVdCDg13hOAixp1DArFKps5wTTiTgUPkpnEdGABZ_G07z1_oo9uDIt8ZZ5yRseXVsI68DJiwX_YQOw8DCor15BAzgdDkocANZR31k5Uaa73R8_fcec_Aa6-AF2WiQovHQSOBL5BaiEu9cXbcPNI2hXl83phAHgdsYaG7QY62lAcw6dLrGmNSPZg3xq8e1KAEKmd5_euIGGRoVRAPcPwtSmqKW0sbn0zS5yaF2ibKrv5TFwYKAiC42ofjcAfD4fgM005b8eQJKyWNIjKE7Ubmm5FlkJN5-Eo6rECp80OLjjn55uDiBJYiYG9bYgmvOS5oBaiVccNZV3FeKeYKcAJ9S1jaFmZLfvX3EH6Y2cP27cnYPQO3DdUsj5z5YI5UWopCcIdV597CIb5CPODUYm35NnO_2l07TgUPhGMuVSn6rpmgvFDoWdsZ0vaSXh_KpoYinVqKfJOhRXF_BABvh7XyLpI0IpCUhsbc0KYYFuxxX6g3gD-1Wx0MrJSP0CJN6rHftlIrH4sJEeTJfG73zTA4hCdyRK9IKna1IhBHrWQyVNd1KdRwB6uTBuIjMZKjZW50hlld74ujvc3XiQZVrOX0n2JSCPgPTzGKjzeCd7_GX5l3MTWULBG34Ljo7gcw-HaQFY5J22RAvA6gzTeoQTV7qQ_u_vyL4iyIoEfKZfcb3Uo45hTJkUyxJ09kL0Yn238X0ARYgIGYyCEK5t4YzFlyshwdgucploh_n41ytzrAkldlpVsJcRVUfruXcI2tVda5hVQd-bbaue57CQV4KTO_6p3u8QXqP-ev_ZufrmcEbtP1BVHnhDc0PHmeXrJDzA03SNdzIIJK_x6JeKh9ugAEuHnrmtOQD4p9aCmHgru296VfSM_do9JZTaaFKesro68d2Gb-FMSx5O_Mv5pt7tekDKPkwa5totcuN0_h3gvm3puzZoBO1NL0Vo09DEnVG2KcRMR6Q_kK6CCtbucn9H8vEAKy91UN-DMr46K9LuRgBte7mUXor87ei-a4zhWUMZQFZ8oSZO7VHewYnPthAqpdnWxOV4HC6FY0Vmv-QS5w8e4xQHSvy_PVJkgeOx0rWk1fJs1_HPwpDIURzMcVG1hzN5KcwSPD-IAP-LCD3rFFMLTmClswUHSmRKr8ttz2t2PDO-Z7Mqk6PJjoKLdxa-_qwZ4gLNxOmfOOpGVSUUwc6aM8dCT8pToISn11HDb5Wms5R5pIUr_dkmIIze7pu5HOSfdbsoBLABG7PYLFAeZoQcW2GggTJp8ROr4k090BVmVqRDdl5cMkZlyP6sjv8gJfLCkCiyn9PecwC7sEP-q7kNOVksrw3DZd7_ded1_ZN0Y8mucUtKArnluWG7CmS67ed5K-ztw8r5L4LB67G3RWfFuFFfXNc_SnJNZP1me_qZMeoEDUk6VhgjH6U198RcucIxeGKmbFJdwKax8COcNifRGDmy1kuxNyIJ5NRgmEwksc7z3Neri-pNyffI2E7pxICVjkKkK5gjzqeUg7nylPnh8JmXk2r-UkmMe794aNBylXKS_b4KtuII7w0KstwLYouz7q-8eAbgbBHd9nPkV8_x5XmnrOE00qrKLmLYvYX61ce94vsqs8gFLwL5NVEXmCpdgnDHUVfBAVnc6Y-Y19PuPuH0y4BWJUgbbywKevyC7oklefTZww0j_8UrgxinTK4SFDCmM5NHwZtgcJqc6l7TctGbe7bTUw7nbOYfc8-BZZBBMH5K2paupTpCsY2gmtN4zYaCLUtn9qocW7a-2dE_jzXYbFA9v0VVOa42buY3g2NtiMXIlKMOxMd-nsq2sgtxXdWQvPDBdjuV2vwoveWbO9At1u1ks0dQZxNtLNzeliZldt2YYjC_nNXslfs4XBKzIgCHyq_LXLbFDMBxVFAjaQHnCQN2EAMNk9uskRtV29Cax_KvCfgWXhnaINRppiG7JR6o9CfQlU5tlkgp3ei6VnujaYTgMCjyLjhtb-GKLBOFUUmuK3gQg6RWN8Ou670eMR7cxYadX6ExpvzFvLIboxmqPFxnjlf3ci8oME5theeLalvGERIKUeSjFtI2zyMJnGOBe5J2g2jVMbFLVFwhnhXjaUc9Bb0cMvgrVG1PMrRQYjVFZDkGaqeuP7LDpMW9L0l1hY4oM0XaLQDUT-2cSmfuMFm57bh5uEWlmc6RgEcZHbAeUZ4koU_I8KDrEVMXvHwzFkc8VDlzNKkkjykQ1DugoEmL_UB8dLToveUQRdF6cU9X8AmgveFUq5IZXl9LymewnIdDfd8EYEAObEQerVTjl0s_VpvQXBqTemUb2dpZaPRaoD8mo7_o2ULA_IJKupWK6XDt7TIHIkbDTEXvbfmELh41jK8oe0svHYukOwtk4wcXCEqr3XnbESWf8E5GNSmoBgqdF2CqxFGpLdV1uFeW7HkssVN1I0lqB8atyd_A3T9RD_jUWDnKGLdyTHUPly-neKGAnJ9pRjYq0dEQ6JMGyqm-KWxNL28sQsEV4zrXq8ssnMQOg_93DTpKJ-RCwTgjH4z4o_5mz5BmWaoC1hIfIMKFQLhs5CLknBgqDo9-P918fhXEzpi1zV_DaFzYsvCym-rhyeG3ZHJdLj-aAox4TnEuFHBFxnoTku9qmAJDaz_sRd97jXPf7KBRzWpwsPaZN-b-LFnFztD_GCGbLhRwafF-ckglJ_n_kX392O2Guu6aQWvR-kWpB33YCFT-TQzKlf1py74JopAINVSX-HQ8klTPCily8rFyx618TiwU7Qu5LUKJe7VVy2bBFY7endXnZy-lDz3elefrmGaL8YRjkMXktX0MteSOTUw02VCt7SRyQxR7v2VgNfVprazQlLSz3wYibU3ZjtQn-vcArFdkcPxBGx11x61op2yussk9qPLnCv5wMEkv6D-C7pBmqCaQqRszGKPsCxqugTpU8jy17EdnXeDXw-DZ6FO0ggnnfY33t3mEtL472g7UGGaU7_L2R2A6_No6QOdNYTpPtd6lb_zOEfIUt24oyiLfTsWk_KHZOP09mS1vv7i5sHvRxJEuzinvfDoCVluCa_Zc4HIV2xihBP4gXaEOPcFmCQvphPDeoHA9-0pqPLa7IBPoEL14B3iQdptAehCtADrYLt_2_bzBNMcBWcnRCDyu-bCGTw8-_iCpGL1UsdO14podxY0_tGeRMuMXMbonhsRSAu_O2OpRQ0le9JloZx5sfpgDDFYrfKldLLvuPqfG4xyyi-1yUopIk-_Ov187jSF1i-VviXaiUQcApgaAa6A5tDcqFWswcoJ6GtqVNPHKqgRf2cC9isU7Zj5VeikQLJgJEYnZKMEWP0po_VyzI_CxjUZD2wj0nJNm1t0hCiVKeOSAoyeK89PIqUwzYXwEnhOL74j9aRTznoUnR4ivKbr2jdEbOaAqk_bl36d0tGoevaGzZ9OUsAUZPpUz80Y4vY4HBDck1Oy_sZNhBlE2ocuMMgYhJMVt7gs8qRPSRsUw89gkw0D-8E4tYSPpfdXRDjJoePu-A85hNgM16kMV1fdR3Vp8sXzxyfJqdtp5st3vP0fbu7qYFIQT1gBny3SdpFpgQqn3Z532xYr9z7JNWZsuvfSygV4JCllzoAx_J0FRZOz6uzG9sWM9zfr3wCMoGtscZZjZo_boTDqXmb1kzhe041SaR6R7zonvhcZKUrHD_MYAnakhN8U86TPPMcMXW4X9fPWqwWZnbcxBy5nxy3eWkc8EmMGvEV_GLOO-skYHjhemMZ7WklA4zHkV3pFA2LRsfJLRoKfP-LRFwUa_KHG1ytiCENjFF_F1QjPHSp30pY9daUmciI2trBw5MHWASEXyjP6Omy-slVWUzfOYUMR7-UH2LbUB4DbSBtEMdgJaU39UtfIA8Cm3iAA4PQWINbnCLNtYzbyzfo88wArA0tl4H7FO9d7zSzLHp2TxGw4dJe7jQP62ndU_N_IBLIrtRKy7GRHYxPd_B9-XigXylGvdjJnI4pEDtLUFtLnxN4ge7htKW4mEWg5eeOEd6VKKasj6Z0g6l4Ez5NrY3AfoNgWadp1fBy_TkCQWdx76zfw1q2pBqzQmt3YJaNsgkaYjihFFq8tzX825bDrkcL1avzHHjNRzobOENtwdcd2ug4qqrZpjC5gxyNxvj1uRJQ5KuKhMVuRZCYa0sF6I_NKEMXQWRbm8oOjIk5KGN0x8h9olOLH-e0Nnxo5AbCjFuqhbIdwmiCTk_eGnuKfx6zAEhKt3WVz227NVXNeKRGiOdpMNbYCuLUirNO_mwpRuFAGndm2OE0n7AX6UUb-lQxh3LLjYzT3GaIwUStqPk3Y4Eu-iBCjrmcc3CsJmNBEtRQcZvDJC8yUp0lvf5wjWjXxdkL9FCDo_6RPgEmGaj90QCPyZou8Wy0KRhXvkZZDav_Gp97eF4KFSnvpS2XGWoKjp_4LpQkfDiNSExcVa6W8YaGgnZ1y5QzPyuY8kOxw9ikTYO1hvyxZA6Ai_QV5m0LxtPINFXtr72tagn6JYoguKkLOKOlk0hKyecZZfJzTJJhclghORl8_kwj-YwpoyZBRRHEGech58FJL5Yybv4B7Y39Z2xChEs5Hbc2oRyEosK8oBKwYKiSkmqMzDlca_sGpbiOaoKyUPSenJBXiWmLBBnxDypuNklqGpNnqEgYmAehE2vrJT2iKbwQJ40ccAELEcN3cYdktD2qXMr540695BMQHrUQFFxbOZrJlZs5mgr8nnKmOTCNicypWe9fgkxwh7fML4t3uINxX3OVPVAcH_pS_MW9lScTq0hSJZN6VpL7tnapZwzaaksuvo0OYsJ9Nk2Izjwe7LlXM6xTPlyCtSfgQzjw5v35_nMLQ4eqL6voW6Q3ke5DtaIkvuVIxkbr8_TdsajGGoL2kmtH_EvXCWNxsTSoDxCzuGsBWFv2gi4moHQu7iUBVpTlYacrix4my0SUYgyMJ_KY6ZS18LwC9qtbVtOL4UGrFOZi3Gef3hGTBKW_4OLNw-L7tQwsSZ2IFdyQjhp4JQKA6H29y9aopMhuLrG0dMuWXLmQp-AnBckpW5tShy7bT1EFQyKuGAMZg1v14ej3ZYmdBy96dn3f4WXYfzSBxFzlIC_22vmLCT_2jHZJdZPWWMiOpEtMjn0dH6Xvkz0F9TqNSfMH54m-NIQqCIb_4VzlMUwA-A58hv1XLDeLYB0Hl-ldRAoI1N7dcr4I-_zwRXGYjtGco09LhQnZZE5uShCT7oVwr8Ymmq3Tev7TZU_6UjxvCbmqTotlRsfhGdf5_7PDb8OgdKKgVeEpd2N0FY1TOhD9MBbOQvSRwA-4C51r2qQ1bbIUUOSIZfdDXaNUFo86qQlaZyEIggI_USM5-qdZ5wLrAoMf291uprxNKNbq3tQv0c10ps94Vr8iQX9jxnLd__WeGYqfBNzE0ct_NLst381aJskdFZS8_efNMPuWmdyKTv16eXpGpTTtWNOO1bqtXhNlcLDlPN0jiM-jjXhvHzqQtBxA_1n2cO50QMGEE77L0k4YfU7iGMcnOUxrNVGpuXKtDpxu-NJgQRsj4EZRjTsYoej9zStP2GdE4lA9pqTJ8PuS111JinXOvmXfPaFfARph2L6ZmyMUfM6KqC7T-UVlZz5dMS3Sn3rtC_mMX0OseQef8Tkj4eHd9jOPfjC-7cjFvXWIGovJe8dCiHFnDbIeCwP4GLl02b_0hLXI0XCxKccbWTwq0a32aHO0F-Es9gcUj2iujuRVBCt5kQDoEAYhl9u3TlPjPl4RzJRTpBAhCDI3qMR-dnWgohziX5VVND6q02DCRVBpS2B1V9L8LhsG2Hk3bEh4S2HGVA6Ef3RhpnVNJRDJhWSKEwHfaikR98WWSnVjqXp0WyEmx6Xg1KwbFd-lwJiGTw6pAijQT-r7JZqCy1jfnlv1PxkpD-W52Vn8Txr5KDAwV5CgobZW40OiBF3JgxjvgnWXIbm5JW1VE1ilT-2foCDJXzsHJ14kxtBgRqG3r3y7wSIIPsUAJILD12vS2cdZOzqQDqBP1L1beUxUUUHKhJHCKXTPws2Z_TW6krYeLoqHjXG0doS9UUC4fcZWZZxi9U1NSvG4T1h4KPqIgxwrSdvJbqhfLG_Du-o8ARJx4a9-TvKO_NI7tX-i6BmbWS85ld3btHEtRqU4wIWOU4vXhhKY6MAks8ErVsrJa4L6rObouHPbCe0krYEuoHnWhu-hY4BfiKkj7fjtMU5Fa0bU9bv6u5wwCMifQTTNFa5lJf7lhWnWl-wGMUzeF07O1zyzaRgN8ZzDdAiB6eRs1jBs_PI5y-IYAeNf-qte-Px6FXbIswRTYJCVQQVdmUMEu-E7BYZuCphCWxVeUJy4_EpV4HCFrixjxehE01QdCNAJ0h2VWBrOiU92w3KtmtWaKFJu_L7cEIgD15j7GGOKm1-4tWvWn8Zr7y6Zwi_J-wcM0OcPYk3uFem9mhYPV9VoHF8yCPeyS4Mwp-MkOhH05UhrVRkmV62M_HdCe8Qr9IoBet3-1Dx1E1lVze2hCMDV_0aMIMQsflgjPyHjXBZ2ucZ8X0P3u-_GGHHkPLhvmRd9i_eb5eAxNYLfXPZm6BqtCzRQ-VEzqWK0FrVzX53thCeFEB3n1p0MNvdj-FeHu4zebCnh73CgGY17Bd1L2nHyl9j7cbJiRVVzzuF8G3t8S4KMBoRaHxhQTUX3q8Co4VbiDx0OzJGNKFAvQ1tlZsrnLe7HkDUz6fROQkIvRTqmqG5KPsuDf1ZhncnwWZZaaOB-V1J30DkqkEIK91cJMI0KPAadQmSZMYfxSBi4iPhjH4A8Iy6TTwKLLOEQxdcvUQVZE-q4Whi1zxrDxTyBSywnLc_puUpMmJqipY6Sa-pgatf3378RU_TFz7ezHzj8--3oliEQBmyz3Dzwi6FqcLNT-GQz6CUIKVm97PtkM9rphO_1CfuQ_6FpLLNFNjR8mzd0gD1ADi87kkOU5rUrFDdH2mdxvsEYAOKPeRgV5o_uAjtBW5Qg8WRga6QTcwhOVLljfSSNUMf5uCgEpO1a0Qe114CR7bEvlCnyMkhReknFwqPfV_TtvyJtA2_EI9qTcxQJopwQ3K-RrQh_paJKZps7ptn8PIeOGAyt_8G8agjePuO-bRP8FDl79F0g5FtAXriJpf8meIz1w3To-U_6VfXhiJEKNv5R0HT1c_A0XqTURFj2RSPzDOtuXNDMJ5NBuWh0TuJ8AXJ7j5qboZTMB2KZ11bA6NAR2Fds8Kwd9PMWvqwSwl4l8xecWitjCkpoCpqnATa05B7cDlf-F5FcPGB_7UT0GgUpm1wxRID46JVEQAGj2vUX0bDL_xrfPgedvN86qjJUBri-JPAjJ9lN06jbj7otj0bWLQD8S5jGq_7OVmUqQFN9-O_Qk3OxWffwEqHVRHw6CZjoM-ua-fnFNEFfVTRK3-l9GhAS1VkxXbXwgBO2o5FIkBrDIBco2C7XPYckzgCg6QgMo69U8P8Munc76bNGrWums-zWJdcurNib5V2djQmRa52bptgdV5zXMvR60roe-GMQneluAaNmfb442UUzsBhN56c89A5n9zpXrkWH1LBB_fTQhOUmeYwJQcwJ-NlD2rOkCKP4mLsFJRfLMg2p7QcR-X4VoTCfI2vceK8zgLBFRQyglcxo3BZZGKJsnxnIm_UN2XFvqVCSDbm8LAlZbCyeG6GUHr_HaGOjiOLOtR6whliUrl--C9lBFoFan6z9aCOHvraWyxjJaDT8zX92OOITu4vPWr-juOfFX0vbqLCcVvXXSRhj4RQrq2sO84juHEAAlPCHGOWJviOzSiI-Nf1u7fzXnjC_KnDxuWwKjI-JJCbRr05KFoyUDzU_w6rgeRQYoWhzKFHEdQHQYgSkdN1ZJEEYtYpeEOHHpC8ryKAmfKxHrD2vG3SFw3Gt40sw52AlySEftqX-3Xo3CM7kt6VyNEjy3MJUnoRzc373aP4Rby6I4N9WeoMWd_DFccJLtU5GPaqn5EM0lJNYBmXW9x2IaqsRNO5l7RCrckZQKHeQjEEt13NAEaUbmgmbHnFe8ID9JUk6uLG6v7WNIDunMx5QKgSkYMtRLfSfmoEPRcK9IermP_NCxQGuBrjVoyZpjIgp2zb9KtceRqGF0VX9Z2OoZhIpFKuwpQUqGEKKYj32WjWGZ1Y_EAQSKTH1-h08L7FHuCizBVUmjUqPCMKk5HMt_SbV0oZEmZPuKp6NDhCdEw2GwSS7dw_vczgI3gG7JzOOaJCQiHyC6tY1MOkPtzVOwt4bYuplfomOgzHhryXLXtlrJklzZyyCuQAFAeN-1-oxEVgiOuCFbF4MAYYMTQ2OtV4FhLFQ3Vs6NP2wZ3NQJGHZHqF2RSB0OI-vjtRNn9L_CBYvWxHKr2t9adX_GhfN76ADVyvB2OT_QpSP92PoNJkI5jcolvzUr5ZddQ2xyvOzSRQ-GWO1WZVJzTk0MHpqu9Oc1j6g36FLimCtVof0QXu4dPnKdjLtiiQ-Xbof6UaL4GhQjeWrrV0OM_Yjo43lAN16dg7jgO5zoeZkvmlSEU7kCQHKmPogrWDRtO3ZZKSXFaB9aMWpHamLdzw_PWc77O_X1g8K6JAMpY9xsgwugQ_90FpM0D4eB3jnI80SixnGzt2FZ34bYUjL2nzvo5w8QoRXdjX0BCj-cTG6szl2nl3WChmG_hKjVv-2GaLHGKzCHHB1MhtrcqgWg06_iuvc_jcT-3lWdav0MM_yVtDDgvZat5gEoQjZeNZIXzzPvg2_anY-BpFWW2z3ZWmuIdxkY8DA-_fVXrn4unlbaw-YAnFnghQuVveO5Kvje7efJs6uuPh32c4HyG39uWl0DgrPi42pexMb-sJujGe8ef6VRxIbCKvwCLN2sayLsIopwyQjPjfd4GCpWmNVKbwPg-6j6WffvC3FPbysdpNsrOtodLR2p_aw7bI0hgcxaTkqs6ZBTzMlkxLkZHlcwp9TdOhJgMkCVW2ctQ8wlfCEU-vu1pkMMz0Q7FRNShPPtmR6J6OUFrStbqo4l_E8dEFZb818qGxKa5HDKyUm2aVNMfgVLCB-HvG956BWUsJTpXitBKRrNiGB_B5jBKTeP_mLd9lw1qc0NfGGy2shBwLwD4mvQsge7p4QZr70WKfVm3Zj4f9BaEeCOdAgAb2kByXgWFO3cCL4xK1pikZPndOc1283Lxcu5KwhYwEW4LeHoj3favct_UvIWXl-i9I9kVcGU_7S1I0IQbvIU0Z83jSSVJioQFafJ6nD2DECP4RAobqqrB9aSjsMoL3FhYs9w1crXUHRj4ggCefYUswEBK31Uafvp8vEIvuzpmXu5wdCYZPFPiuumXmmjA1ViyfsGZ2l_qc5uEEHUy0X6jfzxydg4SBZcYMI1-Ckt9SWxpQZzIObdL_vaYJPMxTNmP3whnchlVnoDW9yfKNDN6yuCNdFvpCGp3LrQgYEUFc9CE4ch4aHQqWkBUIzkCiKDBR7ApROmk73bzexXU7jRhldxWpEJzIFRayM1SYwgMg7-7-tfD02UAUJAVvGL0Uu237WqYRimRmkCXXx5hZ0iBl3KOeeLSoK69BEtX8ZNMLokfWaaT67lv_lWnzTcgv5EWXJRARHgTIiRXjcTSjFMvvd0CQlLjeZc3tBkJ3i750XjRTjvs3YUd637Bz0u3R6mMIhRGKgIziXzUJbjK68OUFm0rR831mhGvufRGTV9b--Uxm9nvoa30hV4Hr37FynPPp6Mp-MIH6yKpGB1I2uIjEZX0ggJ1Pq11wk0QPjPxqrNrMrFj8GHYKqb0LZ8HyQx66-Ap-jI-JzwEcN-CJTCf4PzpKOJVMSh8q5cLDYe2pVMNHQ2IbrSCuuGBgqzXTlUnMl_5hKbDhhbIL3-8WH1pmrpBczMLjGxry_XHiMcEnjR4_sJOfHSVs7DkAj4utwGfvELKPuttgJ_pP_7IcN5mR2uNjg94dsTdfjfYBrc-OWyriY4aXJz61qaTDCSlcmxi2M09QrJ2fnANpVKSWwd2fa5E5oEV5hSNsTieSbFGbFrspmZVobijvcqJWaD1odnwjyQBQsUoBdVlRtuY6wpHIEPiHEi0FRfDT6Jlk_zLuLTjD_QB22T9O6LR8NGNlhMJuE6yzmmhl7IeK225Dhpp19hp3RPMD9Pq0jwQJ2GviHQlz97h0ctvA4lMe9mpE4IK083AKv3gdcFCMNRsZ-Zn7O-S3KLfgpM_LRN0JMi1E40Bf_RN4L1DCI-DlSPp-H41GrVYgf5AfFs2t8T01MpyEVmICBoJQBZdnBBdhXKpcmJ7NX6SPZ42tMS562bHz7_Jztr-_a0GyXwT1X5wDNUBukYoL_1uxi5uWRy4AMZ7Fugr7TmSBb2X4zVVqNRgvtnMJ3-eMul7RzXB9vvG5iY4BmCAbIEg5plNBKghR1b9xqb9gewQHP9QRiKrgrRA4C1LqNC7wlWx8AsZdCDS-AT73Z5Um_5dbapIUQmSD112pduHKrh_UF662YWw0cGXQYonR_OOxzJErKaWUJ-fych3gBcmHvWHx_BxSc6t6Bj5eEjL8-u2WPX2KVRs5ZYxn2fR57F4002hurUDKVnNbp1jOJec0eApMekZbJwV4pSrzyHqthTcBl1ge3Xzcazhk6yzMHYnm-J5yO0haVZ2MAvvh_I_CHRxmlgRosOwuOD8IwrsNDffFQFhYXHq0VNpSAko2EKoCSj9XPccpJFp_L0EzS-5iboV4pXsLP7LyQbPbi9NkpaOaSow9AmDl8wamjnrpR2qnGPvUZcqLhlEjHkefdmT4G7xdOp14wmt7yOIX-FGPJJkJD5VyPR-aMtR0JYQrwlAzkNH2IGf2GoGLWKwofDjVfVhPMtpoUMG4eHN0iYLHJYKVi110JMj0bKmubURWzuhaR0LPP85IQVLNic-gs0Lyq1yXsaOcxOHsGGPVNwO3iWA2LNoUaK0ekV1BJ9jXrzVHQXqyqqbyARMX7oqXYYAVPXxs2LQVA9H4DeOPLGwu0RN3f3KDHjJryhYzMUeJhsJQakfbqQREUpv0s1VbRP7JH4WQ_6XoA9dNgUoG8pxY20Gj3i5wT5XC0Vo9noHVwqAMR0qQDkG46bWaJYwZP5Bog-3KjpmRaFpdkPA5C2YstzqjmpHRpcNcBs-hJl72LBcz3DWcraA3FGfRnXzqMEaQ3CKY1mU-f0yAP0OPwf-mpsNdpQ80OPgN6Kn8IuDTDiP0yKt8BlwXwqaAPZljhw9Z4g1j88uSHyMh7NL0xMtA2JjWm4sTJOu8vtv6OC4NUPSaKhjj2wWabgi1cDHyXpRG9MK1O3ByFgDsSpvZ5IfUMi3d9KlNLvYVp1hrtTPygNc3QphQOCoJxXkWdB3IzOx_dGe1A6AvBPlyWy6hvzKX-RnxbbLnGst-oKM38l4GmKg_ui-w-CxcYD5H6UVvDIbRMkA0i_d266XQNn76QxfhYYgRTEBKaHGLU7xeiLZNJPZBndWt-YgXT5xXVDxecCTCnLJyuhVumimVZzqSC8aM95C9MEaVB5vMe5vAg78t1OhtsP8CrtdxIBb4rUbbc1uEl6j9rtbU3Mbo_ewxiejKW8VttWb0GwKuZ5n_Emcoatckd5z8QPmCWUuatMkROJTOz9LVDzI99Gvg5NVmhY7nP6Qg5Hl3LptzherKd9ahHhQxDx-1NqmOzlah4-fdI8FiksrTpRzLIhNcDfmBhVJYVoTDktl3sJF0mKHZZmrEruxOpvRpS-aRqBq_PzywnAE6rOD_KCyrV0MTl0iaCukeMPQydCuUqAWApij1KOhv_EzkfmLVpiYn0L7nIkmOH_6LVNqNcB-TOwHVkczb-gdfuQ6yzDS5ndo2KfybJkpDOp24cjUqjN7-WvwuzKVgmEuqtFTh6fsfAccBJGCkWmFO1V6gFopTPk0hFg6hrRibf_0Pgj0ketJdRHgclTrXU1d0n4oAMRMK5UyR7mNNjV2y7U9KbynENxba1dZcl0LHPYE8HKGM5dPljXG6Qh5XzKVPZbyi9WlCNVB6nfWLUdqkkocjmCN8ujAvHCDoaw0OnRMkd8pUPjnJrsuJQuN85yUfQN6VRKWIlNNENj0wEGt7tjj2PoYngbaDWNFM8YtBwS9GrfNefCISUepDRrOptwVji6rDYi9QYWQUiaOVEZKwD5rz4LkwYv-cIJ8eEP7Qt18VjQG-4YvXgNLP_LxGKGnjSo-xpGdPQnBsbsI9k1P__RWnHoaXm7Tup3xBiqcgQQ2QM_VQZWLYFpiMZL_Cb9xBcuoOeRHLVoKtssA6_MzKT60YfL0oHWQT2EGCwMQrynJS-dbuD8G0PnxWn1bqtb25i550_ltb8D3pY7gyg7V7Lxxb11R5Uvjj7ga1gkcYRmQ67yt8Fn0OO5oVbCrTxno3aHyuvzCWMFraZsS1veK3zMsLQX9sOMWH4ak2e6O_7RbzlCOmth4rEUMXyqpRQDIV_qkk0XzBUExYcFcFfFY_ercB6UEnU575QNp2_AYX5fJAIhCmKFaDRVA7xt7nPvFwROmlWSp5Nk6NwOlUFU13mUHcMBSK1usYNqjyLgYLmSMRt_9F1BGp-7DeBoHXY_iQpz19aH3zXID4OJj80yNd0S9slleq4OIUO1BkKhhAb7dyXLF3qEEPD5K6bb9gbCymLTniP538z7LCrVct6QOJf9WXMI8dWjgkHV0ssII4WvZ4DDDHwPp6HEAH2NfAjVo6b8ag-L2CqjPi3uxfAMNc8jwqKr8TUklihb8SMqxXBxx4mtxjmslBTyrVW1RkQkcwiYMb8bV176K7nmrNq1ziRA0laJkNAldGIBK4Ax7Tt2j8xi7weUXdmEh4y8re-dtmpuTKpH_LWFpEo3tM1FCF6PcIUIGeOvrrQrNViD7X2LRmYT0dgqGTyQ1Ic0YTMDTTQvB5IxRceNohixknruMWYzSHYslxVZz8q8xREE7CvZMgCjPz8NY9HDz29pQvevCW5eRxjMBpVO0MyAr82yn9VfhSo8r7eTkklhwAQuak9i9iV6nb2IvnLw4XLyZdiTDjOUy2x4k5uiVk1a-0dkcEBbLsodoBb357ntE6VLEZNV5Rk0nEJp2BnAXM3iNUBaYhRaGUnfO0nw5DQfe5g0ysO0bqaN6CBPCI2u_CkPkyqVjknTkjsxX2mFRUqxPapU2ynrEXPglY0HgnmMOeNeWLxd0eZLljynwaf55T45G2qcO9GRUdqfH1CNDtda5D-DOtO-3VcjIayCi-8k22biNkWNcOz4LuJ50zm-cSQ4kGFXzVK18G-wZhF_60w4x4Ka2mRDAhjuwSG0KQ8zIeG12zYbkbTVe8GX18s89MOqsi4Bmi3jIJr2qlwYdWv-SqqgFx1wvxuzdCHf4-sxaHWAjsH53y_l4HA2R8IAe8pnZ4T7tKP2AdYDnFStoyGnB7flPAglxIUh2TlhGosGENdxRxQ7nUw4d8wdlq_MCOdDsj0tFX2LlPf4VmbCA6rOaM50WUl5X1XQC3ad0qd6PftA0ZI6svFRfGpsq8UOl8CbW8APqP5KOtWcvx-Zr08tVZFFxCfWFbULenOQsinIabqj9aPlVLUlkdPiKqkCCRstP9VugLcdKlQhX0iktLIuxZpVXn3Cm36yMN9q5zcq8UrNJoRfb0qyTncXgcBEyzptHYrHlWwAeZHaGK6o4TOsLGzRb4WRXDefut-SplNCnBWOEJOXo1IHz5YLDAe7CD50lcptbOCY-nZA1UPuxBsaI2sxGi9X0oLdZjT7HHh_xKt9kfVCLPvL5uCp-F1UfNiLO7hF3HHceuqsrM9HkvoYTNt1aaAqo2Bs7y0YuU0nerZ3ZhZDwEy-XTxAbluYtacAb_UsxizQRXqYFv1o_K1WySkuE-Xz_E-BU49vB0rSG1uva7uF-ABviSu9noWy8ZOqAeuVctIjMOLmmJ7d5uqTje5NMWl1lWeMVMa1Xmq_XVwnBTvfH_dJvrK_FyT_u2N_M-rgk-ir1WiLFSKn4MbXL4f4wN5GDbJDcBwYVvpTRdk0HUyiN_VvTPbV_TCadEHv-GxwPr4rj6K9p_D2FWSFMgZapAaF7CJoppO_FG634qkisoBGE0N7ljx9LPm4Wh_QO1C0CXD0CtX9KvFDgCnsXR2l4Q3fWMIyHxNT0MDJ1Sy3V3vE1fLg9tvueOQjp_qYsnK_HePtsrOpTNNIBOy73cJEGHnTX0lUVnCfR1Vn77yIUGhq1nfNo2Odpgh4z56XOpCJIxV58Hjiscx1YXRKK9jifd2Y_vuhf427GM9Ik0hij0GirXBfkMMHvKhWZB7eBIHwuK0I4Zlf8gzam5x0ymokzcZ1_T-_nFlHcV2O1FM4BkzIzB6XkZR5pQjJyEHrwhQYm6BUBZ8xFQ2NcufY55NBW2aBCoHxCfVW_yYqy7G3e0PquqVchBwNluRp8D5SYFjAuJu6i1cbw9cyMWVlI9AsmPt6W5N9Ha4crjEiFZBD0n-EOl8De3W1wsW77zRG0DCimtEZB5RfMFcY8KcKWbIDnTv74gjJtHE3MPZPvm3sTD1Sdsnf90dQzcbM8jYiMM00sfYk0g8YYmOgBGpvr12Kg_eI8GWlRnXW8mgOsOX5hAFQnGOb5xiEUuryVLwiZZ2WkvQSb2WSbWldu3uQAtvteDxELDqnQjGl9BM2zbcDoWI4PYFR4vmYuBRnDASu4vR4SNiy3eYGFpFvIZv_aKy1MtbxKPTH1DbfGbKpKcXdqcwMYRU4ABG2fkN-IN2Af73FDesU84KwSbs0wC3nZBJiXIelzV7XyHQ5Q4Q0w7RHGKfuL2tm1zhXGH1E6Uk8Nn4YSFCEPKy_aGsUUBnLeVMI_VHllXF88JkDC5N9QlqrD8QpCAcAd-JbTs5yOi87RFZuM4Y4CkuToY2jpxOCujPXHh-M3D5kd1A_3Z4vyQNoaNwY55GBQ2iyRHDfb4sqdnATHIZPFmX6gcruob_LbNsxY_JL-peOeHB0QVk5xA-cNHEaVhcDgY6OKkbeiGucSJUaKO5JxQx66kNxBk2JQ0NZ5wPn357DWzcQ1fGFaDUBQ6_n08zUHwdUUo88Lv0ic-aO_oQljzfERTtmSCBQ-Cs-Gjq5iYHOlHzo-akLN5HBH4r_hRbrekdaZyXcrxbICjttSVG5zo2BcqjJWtx2KhbDLIo8skAiRdY0aJFGTtDk4mxbdWxmSCy7AqATi-hCKkD0UPmMIGBW-VeLy-CTaytcQCAZeKIyaMXZ2ffH2_ivxdis-6v7BDa2kopwkG_WAvALSLZvBcr4I15dABtSyuL7sta8sWcrZRr6TvPbvFXNm9xKwpVD_Y86V_SSmHqn8YF39l1Yt9R2aYtVbQFkRDcrn05l-u5wtnVlwWNO89Pko8unClNWV1uUJ1yjxdkc3LJbmZPpOqJsdXxZ4soe9D8wH-RczzS3okOKKj06z_NW5jd3RO88EZoXbDN-R9nh9hQCeVtnfAaToKz-1SRHr9tAMclpjWaUXTxCaXYxxTzh1798lFbrSxQXPvIhmQ323483G0HCVMOracDH7R1ROkZ-2IH3ZMayRWhP62QDpscou0r0oTeK8L7E-ex2HfLR3cMc-Gs0LAqFaBD8hQ1z5m60CoduGT7UdCHvJJDLUwkpVsT_kaynThsdPnXEHZnHO-VtIsv6YhknXd5W-qsHFYyT5quOe4VWgdKAOl7uNgkWe1ZQB_TZ2Z_-eS4HZLsuzu1996EJk2KvMldimX5zIjkOubKaHokkARwOLRucJpkd4jx95lJEA68r2fyKTIHp_FBbpZIs_NlDAqCoSQ4xD3v2tA_7_SQpEpGd5oKHKqRmRgtBDkHBRGu7RM9w3NyeVP8-PRPGbeZ2qvENp6DTM30EHvOWGBJAj63i0pOOg-AYCoyzYVBfswG7q_3vIkPLMW9D2MKOPx8hmqRYdlep3PC3oJONaC1cV70HAIjv0-HjmRqwIQZX9fDN7EjOfxTLMUO6_1mY8McQemKLJG8XdqD6Q977345kpElPzsw6we_MG0IuUjyIcCsx30w4aIDNopHectbO7J03j4_i0l07qh5v03J8i7ll01HFpMEhNDes240HW1TwSgEak_1qIb-Yv50TcLY9ZU_AKOFGELK854BnKyaqyJdwj9RAO2rgfgkjTJV3jmmJLvK7GUuCBCj7nzsVFyYCBzo0-xA5DbkPHUgAMEq33MhLM7SIzsgCs_O6N4-aP_50RrXoMAckJ-ljl0NUAr-l-j0WtFgqs_TWu6DSN5KH6P1t78Yk7bt_TJBYQJHfhGCpgRnrI5UrbY1ynv1KeRw1k8N2CWGE66GYK1o9DGUXR5yYRNPepmVd40inx0u3PFSLaNk_6E244A4GYrIKfnwufRDeTCKD5T-vVJvGLhP3uXpZa4PvZvuI5-4vUzA7qykFBZ5LG0IsmaAl5E_SHDqWsfOAHqyYfeeClW1UOQpEUQir9KDELxOlPeMfxDZ-n1ZpEwO2_V-tY8ijGSOQgQ-zEFpR6q1XOMsEMe0kwELGbuBmcv4nAK5OdqjJARhhnHC8kUIwnplWXE9RIj1A8EZucugno1yAEbsvvXebp_Bn7uJiIDMLDY6cSVfkYjgRrWy1E18qTDm45gkupASVpgMFQyYOltqbJartKvqaWvGK8l8LFVyutVmJANKxgvANd1Rwsz8SGKo5FQeh6wLLNrQMRni8O-y37oZqbZm9o0-ZVDUlaTPXGTZPpUFdBWdoO43w9K9EULZ5ZzReJJL782EgqM3FOCpM_qzm4OuhV3xQaeqkBJCUL2p3Z1QX6FGVcRkztjLZ2mRezZ5CW6XWynoHXXL3RzAQ-4ql6VyV0olwdWkGP8AJyJfLlb9_KOrSIgvnLAWDcYPdlGt9aVNJLBFsSFzoQ5U8-V1c1CpA_I0GCriPk8npo2JemFp6Zg4ZY1LAvURJkbQjy9y_w-xQiB9Ox1pWyuOt6KuaRi8ADpZUWg3SRuXMBlCB1AEa80uS0dgVz5jPz8wozkaLs3CvqzkSr_S-ZhcWjeYo4YRtfkf3fMUj5J30pMXW_NGJV48hHsH3UEzOi0xdCbj1EfzRL4ZAJCWo2USt6XTZiqVMR1JV9_vLiSkhNhTTeNp_TOnE5brfXKB1dpiSsHP4Fe2cyKjR3zUt0dIMY1nUYLO1LhT0EP0pEsEtWIhyyZeaS3D4LDuIKYhbpKBPUq6p4ILFLPRpCYBCRC2M2gGa07IApXb1XXpPCgbpjbES_0-AzQZfazuxon5-_je00K3qDO5uCi0A86Lon2cd1AmfC6YyOtsmwztBfV42woIkkZyS6uZSlkrVoUWFEqXmLJfFPs2OfCg_aMWEGorXY4jOD83-BKU9am60ObeMmtZCBE4fKOwwMPpsKJVt3q_LDlJLgIjvx4I3hFJgOu4DV-_lMxnvTecn_HbR_Nxnhg2bX_Jib8RDd_CzicZ2vWiQL_xe5P0v1Y9jZQkYSlFmv0yneL4sk7ABGC6ipfVfosg_uKJH1bw1SySEvMfx_5RpiWwoQqqUsR-UBPUpY6xZpWPLMnqIE9L1PMt1G1t6sRHbRw1OJ7QbBmbzyCo6fuVFbrkLUJ_6IesPq_-LcfbKnOj_6YQX9mY631H_dunT1clOq3u-BbKn-Ucd43ZufiXnwf0amaJ_nQLtyL9_p-0WNSCcV0pgVhCKEDRulci6tZqwLFk6WwvVSc3A74SYchCtbxcsx4KsVAT_EGYMSpOg3j8XzZEckKE-4VMpyNWYIU4WRySjxz0DTl8lgnDo0LlpR-vWCe3WBLrqaAE22IB3_btvPjP6N9E-8zF6PVK_dHqx72ZOhLY0gybF7P9nmD6o8aYo7Gj7a-DUfVD-YNh82CINIL_IIVmtlxXisLOFaFjY5s3zxHo3vT1K5z2_PlPJJFdMz5D8aM1_asxoXWHdeLvpjTgY0uncdC8tNs6r4tv9EOzvva_JryNIrUgXgt_vJyiy_XIbqWF5iFs8UpGQaNdwQgdAtdvWViMc1puBkLbewbwVGvL_blRkBI585BW7Ks4cdvelUMYVRLq9nWMrz6nzemx3G1DrsFy3YVu2TkXVlJl-FAmkCGmrn4-JVNR4dRiWnzgY2LYqGAzAwH2uCg39Tx0jLV0TQyCg7TW4QaJFsJHaxYbVMmIA0ITBQKZq1uSTEPMIZOnfnyI7Tmvkaw05REu75vd2uo1oB2M9Pmh2AshFjsUR8EYbJoW27vPZCqYV7wIkf4sx1soRO1JwHHIhzxhJPAgdgWfKYJnnFRH0mu6Ne8b-cu8sm7hehTd_WAUoIZiFx6v0r_MkpzuOrejVmBpNfewV5U2vuWmKhSaMWnXgi3SyR75YeGeR2Bx4Xj3Jb69eX5oPO0sLmDNjJs2-MlLAZOpNQcbQKVhK-f5FqmTV_tpZRaMAlzAAF6Zup0zuN8MjAprUZI8eNZKWTEGZHPQZwsvjf8NJYuyz5wGTjibAoCH-wkV6DQsBE1W_P5dFvRg-wUqlfeO7G9OIQ4ZsnHDHvpyDIdZgroHUxUm_mv5tN_6G1t7TG5gdM5fokhXphPfgPT-GzFRZ5-5XUB0HhQkcTGg9FCvt2fUK3xdWC9pnQSr01x5_F2CAhApebQ41OIycTj_Vv_W3NeNX_QcH471cLP2jttsf-V_UbMHIULmmFMFjA8Qc4sCFrGh4PURFUa6L356Tuv-RqA1ABjGufzJWfk4RVUkrNdW164LOoEN5aMIOgE4elV-mNwsFckjWrGUOCGKpyfs3F6UykiT_zcQ4NfBilRQV9XK_ej515jp41ExojmsfXSlQNz7acuKp_mswUfJgBlXi_p5VQhr2e22l8QNXyqfNmLB4Khpi00Pa95Vr4LL-QYO8lXW1EGKk3k07q57n8BuN-Awf1va4pzHtbTxX7eyKCit5VTW6TLsDstYN2m8bDLnGL7yzNiRnSXIjxzQHl_grmPsqjbMiqAMhxgEaPVXT-y2QYjueBSzyhRqUlIYEXxaYBjUkpYwqvRoN8RCdmwE3IOAbJxq8W8-wfQaS__r6da2BSkZw33zRwaFe2f8xqTF2dUhvftTgQNINsjKbIdbd9ZUoM7pUNkyNpADWUFDj3MCCNLdBM2HnehJ05orxbDigYUMaXycyAfwQbmhgsxZGbjF0iueyCBvwbXjWT6xaAuOCAUOvTH5HLBOWqMHdIXuYbqUancSc3FVFEYQ3_mFZbLAVDkq5E-9ON2NKe3NxMBr3CVYH4ZOuGxBFN2aU-7TbPCNZIWmvJeMEp8qYDkbProzeMIbtbMGXSurVP2f4wRlebuOBVFNmh72Q0siMlj0Wgu9M0RBOHkOY6mtms1iTv6wgZaddBiD_hJ2wE4ac8-3GB1oOew-mJJU7CUHJNGgzYgnWJ6wykYIUBwvSqn0Fd1r8u0BDCwFls7CYz5wM54MSmYWZXSYDCbR9YjQqeUjqwYNQqXFBL5BK22RjpvEjSoboULe2q0E7TUSpeVJlaRQQQGVDcpRrazBiC1EEhckgV-MNOl7V8-mQTAPJ4Yw4fxXIWmPARFIK5TvzOzZATHzwb5cF1RMbOd_G4Pzdgw3PZiG2q_hRSFhAwW_LTTzVJCsWIDX0YYNR7Z4xYegbFbsesNifpByXFxhFk9Mbk3NciTA3o0rU4BbIq8TcARlKLIwoBzelbRUF5oisv01SjzvSPi4-VfaEKIkHqYVRjDsn7D2QWOYeFjYY8sbSi6AC6AYfrHkSclab84FwYXi2fKcrP5dNc-3WAyIpunuMm-0kH6tDSfWY_yk3DbGsGu4XqC-z2E29ccnjA_rnGlJExYPDztdwdEAzmxO-QkSHc2zZS-tPu-5YKxw5i1-4Ot9o3kVNlf38ociaWUCygX4HliQNWAkbMvX2PiYJkM5TO7HwuylVzV0Ulmm6sHh8LD7V0Q2x-ufuOVTZv0Dw7JMrLhcTKd7B46NgxElvbUqWIvZJbabm51r74JHu0w2ofnZnxzuBQ-ui4ihQcvErubuuR8gqCOgNwonbWb1R1pUSiuV_UoNR-VkkSmbDEwN3cfEN1sh5_fNH2wjtN8SB9vUCmq8Ri4U2epWpvp0jX23OWKWfI7NkHvyarFfrA_OngtlliSchxDAh16OzzsJX_tdmI1wpyFj4wK3DVsXM3cbDRc5DjZvzK1H565UPCkdB55k4PmSSxxpUA-Hu5r33xYMhw7uzhFRkHdl0Z0JXdCvkWQ48vJ2OTyWOPEhw97fqb-90ppeVpZhV_Y30-QPu9gMUAj-9J7bFwe5_kke3qPaSiYf-uO94cF7RqcE9_VTZxaqpbXXjwJxjLKTd4kp-nRa8a2LOxB6JKHU59deqsgq7CI3nJ4BgbY62FxqRI3YtIokblktg_loD9ALqF-WFkWxRTEs4x8ZnJyXugji3-RQf6YqefhFE9KZ1MTAGCdqtrF-vUEHA0FgtemhClTeuPrkyC9w6rWiUxOWR1ITr8BvxBFeZpQ8Tqg_bTNw3leFQ26uvCXVF9anCgtdWYOed0rvI9UakjcgijT-CElQSFSw0UJzRkskHICiv20N6hFoSPYn4M-gyM5BOGxd4WwIJp6Oz0QjhWMYaPYoFzCN5VjqIvPppZk74BLgH61doU8C0UMEGlH4L_bLsXKC6HvnckMVolgcGOgmQubTmiLlbRuUfbx6nTRI0wj3eg_m5Y9xarL50ZJI0BpC75QvUdK3VMErupTze6aVUM2Xvh8hwxgt2ZOibCRZo7LMwv8eYTRqGs3E8pmpZzkoCaCbJwwYckgk1T6TSpKOR3Ae2fW-XU91UQSiaUhzb7SgCoIx-MaKTsGDABKUBlXRlHLBfWL3Fb4ElWLdeNLmQkaXjHD6xBalsJrQyli7s7CKYvGHvCqRZfCktjhTxkqVhLE-J0wPW15V35Zi7AxEjtMMgTUwaGdD47c17_YnW29Kwq_Az2jwipkjiY2xZxum-Qy36R7mKsjQrxZk8D-Tzbe0lMbZeVwsgKG-MJ_0wxbTrVBvAiEUb16gWGmKTqvfjW_RWQQSq_4pVYy9-MQ8HUYlrihBbpgvDyr2VKN90cBvhyxf-LL8mw8IYLilrPe5jANpF0Z8ij3dNirQu7oiHnQj4a6Pc96uppOTfEzJ1Az6l_OK7RzlooZVFcLxV_tGCr_wngygylnmLo7U0Tu38Gy-EnH7Ba9D3oC0zDpNkcboKtImX2D7DDGcYJj14NB-fkHMHZrfIUtlk15bTiRnsYNIqsuFE6jQOBFVVUf8Miw8KwMTaykc5opV3ryFgpqKuHqch7_7eqjuOmymdGO7sOlGR1P3cykwijQT4_NBdPaAj4H8xV7wG9w7zB5xEMIlz8jmE7eJLKoIU8PZyCeo2GdybD5G9P3ZUEYvZBQJDtcEYse2OGsbOhS_qYn69Y0cv7izX2kFJluw24EWl0nXOXE_UvYlGbEXnNSBiQkrSqaRkoPFgGm04tatnopeSRWy2wqRJJgly1J6jcsnNfRG7RY8yJyAAjuYAXOCFGpglar5IOQMbkLCvfxwjCQWSt8uQznitH0LvpMtfCha0VUmg-IUFn5R8jTXajxddl6jswzIpzMyoCIWeP3Zwxa5Nw8Gnekn7NtI5-ay-yCDCvJz5i3g-LPZPM-TuwddSh-muxPjxxMhqZYhMcYf1Q-x9xLfvNcnwHFsffTFi4dU6AjzFQAoD30fCayzalbv-W70BDC6FWR1EdDFofmLAbErHGxhbEQuIwxxbUKrR1JZogVObitHWW0yspTpQiPaUygA6c5zRV2Q8zoud5SiJjrwdsSv2qF2886MCz4odSqZ5LoU2CQ9USQlFqxG5gs26WOqCX64tYShEgzKz5f5jPK3_GRmuTpSiPUzCBsdCVAo3rlP3vRlZ9EdtYClyndHoI4TJqrohF-42mBHOj7n4Pqvoql78nbhd3iYSjCmSj4lYbXgvvwBtqH39g92sgASZoSY5GSHWlw0F-nQ10O6V5Gx0_MCKULi7FbT-5CjGb7Z87GLPvNTNdVsYTW2UKKU3IGiZPvWdOPDs0prAApH9lV-JCipfO4_mOxGWKj675g96L9yVur8Qyc433hAGurzSz-JdIXJEnxl627teALfaHlo6jMacY-R5EhwYpX180eh8RZNquDahjdTcQtB0J7Trdw9qsTiem07c8YiP8rVA1vPMR2UYhf9CUlpAg9Y_MM1zqgzQLJoASs_-I05W1fw4UMVREbuVM_V0GXM__00CW9BEGmbBIezjTRRfFBsyqEQ9vmSo55gi84BBSxIZ_mrYcU6jLcEb7N1MtdIP8SsU1X6t4u7QwypZCsTGQPMsmWLKBQbrih2SG_F5ZMDUKVYWsBhCdb-chUwQC5EgaLbkWA2xFaB_0O0VI9rC50w5y3CNUcTKnh9xoR1pAFRyxZ50dgw6AWrnBZszuWHbg95O32eSJYCf3XnsT-flTgao8wYX26vOhcUIRWjHMXKLVVr1iZmQaNXDVMYAx9Px5fcvVU7eX6_-7q2jiiwJoNcruDfze6fYK8yifrQlQ0a3NBxfj4odB5gf3aOz3Vt4nxWvCfvDEFWVtITbcmWQjP9L2CeQdQFzIXZuCOIV7G55MxFTO2Vu5cG1tvJB3z7KvWIwHsdURiqwXURFLzejHbgvn660WHqqmMHIfojeFFE7GBg5Kf5RdXfRDtlVEBg2APtoYsNd4T6YzBfJOKnSr-TfVKLOhx2BLTiAyPX85bqXbu_RzV_oVUr3o8smR5YbO4ORIgQL6sXCPmPMkdUkDL6GOswpWhvkKAKKFpWX1TnZksCGmWD1TJLvW9kQl_-euONoRhodL3HNfSYw3an9tTniGIQAkIpxP6-Cx06m-kkiZ5D0zLBlEjmr4ynp5P55OXj4ItAeH18b-3abLgtgHypa7zw48AbrpyzDNZV_iQyBwGd_VAkRcROBSO86Uau8Nl-kO97RONYhwFoJ-16m0RP7OrxHHJandoIR14-kXdgvCUdJ2kEHR4uFkgTaw9aJG3YmWu1etcRQlDNFT7nbSBCRTllUzZsOVrmMsT9d8SJ2H81YxtnLiVPl6x6SThFTAsubWYuxZN4czslfSRAaa3PIfqGpeGXqGgX59SlapAO2kV1nSB9xQ1Y4TJraondsJLCBUEoJBDl1g3ukEvADbfrpKQgBUrFDfurD513JwWR7Hl0cLRlQV1XkrPMDVfb4SvTqxgQXYRSdLb2DMjwggeigsRI553y0TbZQG_l4jMNi-8VrcGJGCSVQHmatBcBIyGIEyFkE8CBqXpF9l8tSYaxoQh66UhcCmLuNvWzdeKGAo2jC9yzfTkIzFpHoUt8HGWQ8f0qCZWE5axDX2CYzxxaCiyAsZficCioqTH-pxinDsXaZn1iC4xIwWZG1nW7wKa_Kh4PvzuZpNpYolBa3cTsNl1zPaYZnrcvDa3CzFp6ZqovyDDn_KL6K8XoSsHOEDjG--AOk2jCmB4NGFWLQcnYQShLmeru_8ulXVE-OuVMW16c982cXfx3oE9ZCMTu-clYeh4Pk28jtNqk_CoLM6dFKUvaOGokz6e45wTf9tXmEE7aOuIsD1dl0-QDK-cihUAGcQVXqWXlB7PpNt9pFx9bld-g_KBhzwjAmiUWafZBZ-DxdMFCrU3QH4K3-sfGnTaNMsgGVCBqvk8vIsnxvFWuWpCDwekjtb_QQ5R2yFGKjF1kuy2jXXD1slouP6SRPCHG7PbVloCUo3OG35x70zdSS0FcNbH8oboca_ZHctZLPTGWyzk7Q4UIBtCFmhcj-JGOlsL5GCzV6A3DMroGQylaLmoV9kcnA0nVfjI4JN8sWu126jq8t354d3dhFEJmx7GEqX3QGVQ5XWBeBIo_WawAh8IaXd0rhnSDkZZyXki2DHDJYPs3TttGePuIL-mS3r_iv7J2HLHSgilwX49r9RPL4Nx-93eUOfaR0b8ug8TFcGfDaBqjA_105eyFNxThmuTb6ff-7_pikHmC_Td1rCgpxBlqZyAhpIy4vb2L94_eKX7VldQngJaV3v9vWmyy69Nd2bMMdK5kNRTDY34tU0ZUvjLmUjLgsbutO51f3HMpvCEuWGvSSAqKOWB07NHRpbpbeePnrBxSsqqrlh-cHJp2MOiWAzKG5JUUoLRu0MjZiw9jZI7bO-xln80HJNmOxngcQEEx-Bj6CTDF_IerA2CJKgyL3e3fC2HCvItHCqzRc1SrJ5n4HsWFz80-v7hg-TPiIaGiXkIHT_By7WgvXavntYG3GFg0Yu4lewenZ9jNnf_NJWVtYrBApHIldlGWDHiOXsF_-kfSCk8UOqJTySosZ9xPasUaOwnNxrRoB8ScwibunDvEA7d67bIsWinXgd-HYmDCWDwo47AmGhO3Es0R0K2eBCO_wEZsXRW77SegfoiBw0hKCZVb8lYjKLGib6oyu3qsXW3zvzldwzCJ8uIE2k1Hfm4TGDjUq5k9Kvf8bvu50s6FywhFXI4aqBQ0vnj64FhsD8TzVQRDQ1Oo4RRv78JWROtZQ1nwcxlpNvm0zTdLYXDQvhE3NfuWTanLvmT0VPQGGBqZsIbpARds1JX6FHDUbzQrPnFCHTfMkdQogGePI-ilZqfW4TDWc0pGY5222ylSr5kKsvs8-J-WhU2RFbZdC1ldlu39tKoQEbcs5-HcJ7oDix8nKJsx9RU8GeXsrob9n1gDYiqQkuVU6aqOJnCGKBOXazuOQZ5cDY-fiHrnTUH4QoH5Qbo0aFfM24HEwSOQYb4UXL6KbE54UhLrY-41AJk8Pml6RCF3s2HRyWMbjT1wonLnQDkHHQT-YF4mdQ2_ApIh4FfmszDj7G0um1bN63A3YbSoRRl7LLmqihGe7V9mN8xNbxsrHMqqZu2E7Y9NYyv0muCcSOoE77NNblp5XsPLpinjXC1ED4eZArDPHcHQwr-72OMGgCv3Sz27VxlhNzcv3Voce61yABH6-Z2IyHme6kO97d525hSJkAaUc8gCds7wALw7o2IugSiJkxy7B3nx2wHb1iKPR1-UQVYIhxpl3wJjhHSXRLDJ-PBv2NpdxIGYENuZHVlcCPdx2gWHVLoOh2vW3X3_5QlBWuZPQZeIlMzEnLdbXWSBMjhGfCK1Kcd1Cc-tqGZcO6tNpMUfl-1NoJPd4VKTuBqtj7RhmaZIXUONtVcyDN4GIytbhT4C6ArdnWmIwRnt8rra3tFfUMuQudiwO-MCncfOh4q6KcchzRdWcOpD69phQ2DSC0pSIcC5PxiheOd7uoLJLp6FlNuS3ny7LMa1cY7bMMjIuOqjGPwpnEUcMb_DE6lG1oeTdLlDxAx-UPR4e4rbsyu1aadE5Qsfd0gmgPXprDnoFSwmk5nKzR0MZev__DxsX6SBK-i6cukV3BsW2NftafrcY5sfOpjTDCu8bMWpGQHGpBZXagO0cSxRiG6_iQ-XrF1FDM2lToGVHVZdjEZ-59Bme4_vo-TBtBo1lVcQChtz1YsgSAnjaft-1bzHTVIvMt43Ft40avma5AmINPCowYS4aL8zDqWLRhrht3jOw2hjtRzVCShQGIOZwEA8SWWHMCUUTUsEMN--zCQvbDVK4ZgBIZ_tS5wnJaCdQmzJTXkl7VX0U_3R1JjMgQaaEWMbfQN4r0DRJ7-VIvs0_vJLjVYANTLGvigYHTGnX4wa4Ff3qMrvXHKCUGDFNK3Hlxv0E34_Mj60gusdyby-iqXiUATDjWd1wYOLzgRG138WrobkUL_SPhq12RigMI_5QmMySmmny4dBN15rIZT6SEq59oT-x1V1LOobbNJW3AQFBUhllr2vuAg4bGRrLz569nD6kaTozSURz8Xe6cgIoseGDh83AAQ7KllpIXkVAiEp8U2Lq4OjpdvDI-IAAAIXRMhEQ_ux_lUs2CTsSwcKjtpl0oKjHI-9a8HcPi5VVB8k3mldiBgO6m1qMJJxY586OyZ0BIATesZwvBrq-OwUvlXJyl8P0zPSkIAIV9m9mJUci_F_UradH_qSuLJMKdQLjQw38vcjkDcnS6lNg0o9rEayBn1MmN4ZQ79w2UPClh1EomBWusI4b1aCjAgQ4f-coeFjehV11ad4qIzkBorBYB0KL-9AgbJ6acTcRyQUL0NfEUnngaR6UQkElAwPQ4JolNf3cU93RmFk3shSvNpWBEmlO5r1p3rZJReMnjuu-3yvniHcg3o1otIATvdp571Oy3_LNvj2oOLLDTXVswcmbxzOaihbxQzeSV-fKWT-xUxnf91IUV-5VGoGPNvBjgzSNAAcEC9112-xRl26mrC2CGihc76hCyaLwFFrGef3VDY4CROcxy5q8pCuLAjWEzlqiWFQy4jHG2zjtliRBmlQ44mRpGgSujNlPvr__a0YyrVWF9Fn3d25iVIn6X_n-3Jc7PvYw5YLzhUQaXM9C7fI-FfAyzAiGZAhxe7dYkITD3SOJmEoI2g82sQ8qGUVEC7-jae8_MeldLLtL7edRZKgS1SV6V0rrgAFYZY4hQLW-cGBvfB_mIzW5YH2q40F7qZi2eqe37bOqlMcs0SDktIHpFmLDbv1aUQs-GXy-CYnGUQ2kacPv_54m0b1yrXdevYgi4pMaPGjEGqIetSKLbFdPyMaWNv9PJRB3mwaxTinxG0YsL2ABpY4egi2symx7ESZIuutGM44gvK3iINaH1ic8WaQyV_6s3NjyimVj3NydzBmTSfNomHHG3MOUIRvaZqFtV6yJKl7yvcKSBO5YkxFEYlV65uF1Ai-EeOG1dO3YTX612HDjdd-s3xY_lyWJqkx_9UdTf5hLkiY5-4SDaZmoc3sACDNAOO2nIzNaMRA8QcvwphCtdMfNilaqUoXWDZyArLGvx72fds5HmoplQLslktlBTuKWW6cP7UEBkp_uLEvTPEWuKo3azq0vhWClkD_ED3zUjZOFGPCHBmbXt_birFbuOGy7-LtiiNexq7VJhRmXJjrWGgAdaJp7aAd1_1FjKCgQgyEIlva4pmJiEYtKqXBsykdKyzfkpgZgE6vGMFFnPo4930W9KcaxUVrCMnlOwVF2uJfGBILr7sTClSzSFejHX09HaXpQPnrO_TPW549TZ590qzI64dd2CWukMAQ_yZnLJgvo99pguClpuoSoLON9j9RwDfZbom5PHBKW7tkH11m7bCln-t-ocmJ73fRjBr8e_ZVdZTGGs6IIoerQPi8GxC_7Klp7UmhUyYWjccgzGHs71h5t4Ajyat-1mMw9QJXMV9kSgBQ3r-uITuxSwXHikEQo3MrxI7WnLUceHfPZh4gfDfd455obK9jp1J0jtjv4uDLvAX29Dv4COess5TdqH2LdveVZwbrAoCsL9q6L260BouGeipx_ddFNBp4IRHxfy1D55KD2KzbCEoeUu8W6iyEgizKAZAj0roP6nwk8gyvpOG4HMJH0p-jgDxFifDMXX3OeTwGbziaWHOJ8DnynR7n8H_NF3RZq5HthXduI67TrWIVPouaIyNXxJv_BNHyzdKe3WqjBJH0Oy6adzBm6vKP0RI9YnaGdxmO6ViS_zVBJmkouFt2XP9WlDLqmu62cNZP0euwd21y8IRrK8m-uYzfZYj7mvKNMyEAItyNtyuIEIbcfrZtNX1XZosvStejpkodDL-sTz6M8M0O2ZFyAeZimBK-qM13G_WdbgMJFksTZdpdEfMxQaKC-CAD2SxJJg6fXORyFlKC4aIzjEb-ZHWj2QDfSwoEstTLh99ugAayt6OpQG-D5oN0pvgFKza5_X0Jc0i6Lgoxnjym_rAPK5abFb1Ux5UkRxYlC10Ilyt0Yuu7JI042GlwzkmgppKETojpk7ovoT6hbHjBy_VIAMaomV5YFxZO-YADSTVLX0RYfaTiJqNP9nrbs_IHKX12a6DKwBogqBc1a9kPcRYYwZUj4E1KvwsYDcd_7EFgVF7eql0OO9NBKtj_u64lpJZjqi_h8QBKHBpoam_D1EY9rOQb5GoVGDUw41MnzVPwNTm1BDDrlCdh_QLZpxMlOMnPd8ZExEQ6VSYAzr_ggA2i-l1vGTVFCM6Sn0X9jnR-cEoK6j7tmJlV7WT5wZsmF2Fs-YcksBPDV103TE8YxbEUavOYJ47KOwn1k2WYiWYAP0K_lC9Hlrj0mnn9O63IjAyNUavt8yLtN8h8sWdIz16Sj8geplFW6nHGd3OfHwTy4VZnVp-gGqGIzQ2Of4kBWNviWXfD1lHNWZW74VoMrY1c3ycH6FJINzEXb1FNIzPS2LGyls8uz61gorexA4MCsaJ_scqoJfmNUG4dVCaA42NPLiIVqE8A9y8PK4Dfub2HvDQ_gNTCR9Vn7YnLaGzcWkafkK_SY_j7ERq5XAQLDeGBbkgOsBYpuyTQYnhrF-5I4MFj-4P9GHGJq2rPQDgKCQ5wcqkfmH10gIdFAEoob8vGj2wUKc68XsS_YQsbxj42TYzcr1lY98740bczOaqxCswp4Cbs9CkLerMR2R16p7l4uR6PbBzUtL3OgdtZCH41TRxIr_yjulz_fl7oLciJ18QNFA-Y1nGHSAZNDuKiPG91oA0PFlkGypSbzcs56dG_Yaas4s34s9qKdYp1ZMM-Zt5i5Zn1gZ0jhjnrQYBskC39kYlAb29pI0_gdU037BxDyhztZvvcBZnGBIBjjhm2SASqcAt2wMw8l3Yl-7ibZmYAzxj_go-vGH2BvAtAigwFMjuHa9XBYPJ94uywyJxKPX-buVtueRP5wE8f9o8TgwKMU7d25v1cUgRNA9s3ANBydVToSeQjSsOMlK0ed1VpV7Ym6R3QyBfEX2Ku0QLk9pY7nvbIV4AMV-mCvUeaPsb2xBmVn8diiQwCnHWuBXHDlJGZFYXaFFYgYRv53ycTQF9jMJmFzL5780PU3ZmcJBUKRW65BpECDrg-0jPCGhckzSVjxD200JOnmvyrfoy-rQUMERdOCTntYUZLeKlucysnYntq72DJqqxy1i956JUbXb9afR3pAm-kqW4OQ4hs7XmDjdpcDs4JtDozN7b0DNRd9eVgSBGbJFWXj88RxR82ajoehf8OVIyPbVkzyFY5ZUUSA9ebMDtriBudc2pzijHGMjc0RZ_cfQgdSsivvJpgap1HfB9Rcqs1lYzMTy0_IPWPKd-QfKU-nxvOjQzzxbUWDi19FMX0kTgChE7t9_3YO3RG2Rcj91O-dTXDnbucnQkz8AUtcp98VuVg77gf2W6fzWfW9Y4aJchrmBaE9uJ8cHhdih8dtw4o31HhWW4dcCTxjxEZ_Ao9zrH7LD3vadsKq6q1qidRj1Bv2Iuu9TWiVHfdgv5Qo9_61eE0gGh7L6O6ujO4eIWyl7I_TA3R2VIls8MRLI9QAD8HpwmvPYyne0sb4u-9gF2addJb_HfpuVgfKbies58h3hUBDf4x5CPfmzyyKp6KpKJZkeyYNTHullRrNQijiYCN4xuUS1-ll_uirrgh3MMrpPtQ2H2JwC3azPS6eFLO2_kbD9Z8zeSYTN--TB70HX-qS-iKp_KSSIDOsTuADMTmMGbuLFlf9Unpn-5pFEbF5XK-nifDBiCM2A-cQZwU8INV2WFOK9sy-5tkleGLeMr-dHuXZ7pZApI8ZcolxfTskRpofUKDCLj6I8Vy_yXxzhVYuJSeF5S4XTGcydiTRktN68344YegnIkuo-MG3pZ2l4yx7ueDdyhFdWh1vwtSPYRp5BRStaeBoxSnDHMLRTYWMNA6fLmzXztn_K6iMLk0-ZhlPAzERgLMa0JBKlvG9FS2IC5f6_6VuE4w1IKfjmB0pKAL1Q1GUHUxPWecNZq_uuhT1hCJNnu9Ma9jDy2EB4NZP52oFfLWTe5-tSndYMIUeO3HH9UztC9EHeIOZ9cEOlWbfQUPapI9nIQrHsPtvk6D43uSSO4D9dbH0Khq2KQDMrgkmKR_hzEQV1DseC1eNYgUFApHPIkVs63I9Tp--4Kbv__P4RlOUgktuXFBRG1sA-MpkOoOw_i_csz9UAtEurSaisw_Yyg0IwLrtIeeVcKGnnDA6VACbhpEMqQjwgHz66fhoP1gglElPvul8cfEJOsBguK2Hi7MQYq6ZeFly-BbOSK_XL3Y-dg-YbYcGlOpUhkdO6FAZMsdIx-cj2fdpLlO8ne8vY2qsdoQOD5Qm91Zq3LTVxbJKVpkATVo2o85FC55QYKWyRinNqWOvb3u5hxpv8Yi4_ulaR0jY_h5smhT4aaADkXzTJ-S8HP8BPKBo4WzF2A6x-yd2VSLCuVE4fSaGj8a895Rpq5gVSP8_3PUZ9QO9JnMScpjVEniLk8xSy_g3Je6NV5EIM_liJPEiGoFTd1xW8dBywasHofKiiZqT_FV2X5K6HRapAZf4x9JpkCFoLbThY-PwfNnP9KwbDt7YHqxvqaRcblZwbR95cQ8WjlEKHzAJdVWzWEJKEhrn_a91xGm8lB1f-aMUR0qwWK4GNV9LqslOa47s4ZkwONqXPxIBifDsfK7JTIgjsWMt-4OonOx0Sd-Wk1r37StoxxaAX0PlFOXleXdkUgX3FVVajrUn0F1GxmT2gRC6afFem7u_Kix0haPyXEXmzYhvHEUSsGISvqMrje62BweD5k8a3xrpbWrgJR7i3i8eRTB-gZ-OPGfEcXORwn_hpA8CpLh_388GoIwhkSQMY_upbinCw0oLvWFzUPD9npwam5cAoA5yB7uZEIkkUuMsf_bgq4q4hG0zO_Kms0hOccEO3Q9xXW6X_GC01wJbbECnq0Ek6MFzJATRhrh3xWnWRtwklm-lyRdan-Qr9a49z5iZV5YF385B6QB-edn_ne5EiHLIEMWblSoskF8PBxg8YPXZHFtjoUjjurj0V9MO4UMb7jQFsA-TGoVYnPVXxBpMmkDeF27XopiBMTJr_liJ0S3lxiPV_aqMD4FUaya1SPMVTAQqbKoP5g0jhXzEKxVPPxwG5QfMtTeX1T63zSM9ky_m7_SI3iPMaCZXrfl_U6Q8XLjPWYW4ZPRi11BOoOQRE4wQ46SW-Sntdtp3BzmxmWJhjRXBYVRHa3DbrxKwYCRsvLPwvPkYwJK94gSPTmhV8Dg_GvXrfHpMX18JZynMwRWHZ1GeGmBRr2fYF4S97xwNjlTZX_1SATk8exJt60SeQ8EvJguOaVu2uNxDHqxFU1tR8KH02Wm3FCCNJphiGPafs1i8AN2Di6keERt9IUgKcUui-pIDfYO8MUoD0xp2O8mCc71hhf_oj9YVAbuc4uVwOyG8C2nLA3mYbP7SHPbaw-wxJZ-A7dDC1LVG5Ostsp2PxM4lK7Q3nGdVOMs0FoMTdkVi7oKYUygK94Slz7sGIY1oeDwMyATk0Fhqrg4Qdf0dj6Jml-if_LJDqwz6aPH7BQ_ABMimzNkTTI2Z69Izt6G8maBDcPvM5mKpQtV6s-67_15UYijdrL4qaSpW3VYXfZhkWeh-dyyKXfeZ5qwQOZcT7yo7s4X-gbNa0mAz-0DVlRvLrNRNlG6Cehj6qqXfsp0YvFjuDqUT6d2FLvR8jZS2m99AmTqsRDKsPSYd1ddVSdg4MjttYVd06ItIntoRnzAJ-iXIcijf-KKClI7k2br5RsMY-ZoFy_bb89Ryk-vT2JF4uxdlAM69K8efxniQ8M7bLtWSmA7PNfcLhiMsd-_H2GOqFexHaz1WY5fmY_dPUtuJS_B47ga0C7-Oa8c82vExqKBbJZW6EhpBoesuJPNQQF3jrE9XD8vJ2ZxyYCXW1feoWqTs_5zyxSeEEfbIRwoa9RlcLYzEfise11NBGOCYH8fHvk2LnzwZijt0akd2NiHRYH8TRcGmQYB481_Ek5rK4rNnSb6W0qQa2ytQYeH58U9uPa6c4WGhMi-TBxEn-Oc0XXswq1SM0pmATHgTmVpW8CVCXL0p_-2yDNO5cQ1QSOM_lMviJvOgZSKvt-GdZhRqhNRHoZgXqfa3cRUuCDrmSPBZ4_SG4WawBXEoMvg3Kb0Oqp2vS7Fx-vTUVIfaRUSeBNaoHNWDStN__qX6FZ8zOS7QFt44uUUimDIu2a_62X_qg8fui7GA-HgIDdOxU-VMpMITomNpdquOMkkvcamRQec8OcYjZkdH4VXz7Wz7Wj06kOIEhIZRFDE9UuxOqKNuqv1yfGV8-GC8niM69RQIPKPTR6Y_MsKfn_cqMsLAmsenf2a1Lbi-TOrrDWkdu0TWzAfnvZpqGoTnILNfsmu5O4SEYWVUaOG9kWpB1x1j_bKVEJbLjEbmGjoCU4tGCZ7dt5A92f6MUDd_ibxXRYk6DuKJKmJxAXMjqiuFqUBk_8qXform4chjOa043uXHeUFtapSSUkSMcM6fvcO02ka4kxFsnavrRM062l89IXMHFISj4bog1AqMBvs7cVLCJFROga31hxdbWCmtKjAMlEh-MIxMy3j_9asSk85QNpVukIbNw3M5dOYtVMPWXUsSTPLtdV_wokj6jF96irnZzftZ_hn1fqYyvDdZ7WFzajx4TVOdO4gHjrv7R49Of3iZGmApNI0r7TB_-f8Lj5T7igOYdNSHFzJXbKyrFFcXpTe1eKtOmJ00Ek56FPwg62cpNtrowN1zt78R98Jcf2EKRNXe3YlcbvjN6VREin0_EWWfqJahDmYOufKd8hJ6UycaosDc9Fe66n3FT3lmY9vJwAZ43p0wWFJdSPzlujH0rHuV0eYP4qxRAQH-T6bJlEo-jPXyIhmkOdsRrMc1pOULgZO4693gyXoXGXmXtlMrWYxEj_BvaX84S5QpEPBRos2O6gZD1r6CpKA1UDlcMZRZ3LJRUd0i_B946acl8VzHlfZAqvWTi71upV_bR7YDyROZk25UtgGevkWAWIWlqelV4HfFn21JB9qOVf6N6IRsZe0eNmY3nrfPjLqHFeyipkxvREz1n97nCwe_FyKn0OTKHCOzWt6FUbiGAGdqGy6VQizWScBZa3eD1gv7IS4FXX4Qsd5sS6PBRm1zVdbYVtEvmQ5OOwPJ3N4LvtGVfIs7zvC6ganhgDzlfcwVwzIUTcwqMsLe-ukRIw9EfRs-tXGNvXipsZnW0iicgjThYC0v_OIlIbeUHhy0Hxr73pn1IIvkfE8ye_Ry50TD-lEVU019p0RXblEqdJP2tY9_cOUBbzdRy3AtQq7YtU6qtTBkOx3WkhLaUZxocmjzw7jM48FkCATLvgCW5xeeKRG-lkiAEwf5BKcnKRjGga9sgJfpTlYzUjyunw-dQ5cfpLI4R56gsMgFwonUfDtVXE-tYlty7TtflM-yzrZ-8fq28yfYHfN9qT01WFTi1xYyp5tVlzvo8NoDRcGtveS-yucU8mT0GlE6FiaeHRHH4SePE6G_qNUOAdQ4mUwfT4eM-pBFzPaFK8St68xRi6Pb2PTq4f2ZgtI7RvGDYYT3rxWmd-QtY3JgMcqeu4UK1sG3amjVgQw4GdfoiEYzRBz2orEmsWNNqGzoQkefR4TJGqc5bl6iyyH-8o4Nkid8r_Gtm5Tarlshxp4yGMr8_JZllhRXvuhlXbeDD1ujS1h7AXFQr0GwOglb3HlvYkuuSlQZZTdaLTs03S-ZFj6tsS9-YCop6vXoGd3kzqZBof9ibDx4Xf23M4LtuhysMvhHvhtWP7MW60chZQSNYgkuwSxdJ4uE9BTqEK91ClbEmi3ngMp0CSVIXBOszFBQLllWfebqEPQe2HVeW0OLOMZXw0_kxugjm90D19-sIjLoET2g4aJIS7JV3zao4BA5iSbrdnqwExSD7SI1kr-1ed6j9rw-tDociprh02OkqIwnK7rQBhzZW0Y8FSZ1q6SYwBNZMBUrOUSmOUEh4KhciKXxUKmxNWNmSVfgRQJCoVopRC7Cft4f6d-DtF5Ky4u0vawsIrwxpPZgx0Zl-g5w5Ssz2tysVydSImhinYbhp-q6hWw5I5z52-V9NtOo4qsFD1i5LN3FxWo2yLTsa9pGaKDtdNM9PNsxBkPQXg-Z5Zj1HubMDrGQRfBV4JU5q_V1bRj4gYSMP1VCcrjTevW4xT5qsINNj95SWJta7OHydFEUYxhWSp_Yb5gxxQCZf7peo2D7QxiUnkCJZZNcEjzZuMgROuvZcRoQERqIIMpTa07kxA8c6aVqB_9SfLCAF6lO2_-zZ3_BQOwOVP80qN14lUU1oyqmI2huDjCz7mhbGxZnL8i18FVfbPRYDj6FIQ58FkCVMNsku6kWlEGGwZ1UcyGwT5FeBQ_AFVOn4JVnDeY7qCq12_O5wsY5kXPy-BXiOMkE4Y2bN-rNle272kjtYJhqKNS-J04R-4Em_EbnIW78yb-XkvEHOUmCtqOX0yLziAmzgQKJL3C39SquSCmjdGWUCnnHmfMkWq8OI-Dhmzh-T-eXpQh35EULBPLvLSakw-Pt5vgVLT6_a20jOU8lkZu-keAY_pesG1j3LF1hRArKRoyY9SCQmMDQ-aFBBJaQ9-1b-1XMVFE2VSkGfovWzDjsYp6blRV612TKX9o7mbnCOjakZNlWWZQvbRfPMOybRfjiSOgBUe__6glXg0szUe5vmkgGr7oUABtBJaGPkry77fVZm5LnWRj-JSLTQ0ksCUj3sxRFJouUve-iG4mXtFvE3T59y5RZ4hXygnYNOOR-n46gdkrodvQP4huuuCj_aoBHbYQAKVOR0NHxiZNJ6ntsWbVT1rLBrZvOizFkVj9vRRepcMGc0n0sQkHI1GiYYGt6WXErlmz8uv1dlSOi-sBu43alWc5hgX2a02sQb8Xi-kzgIgq81zcdv2QdqZCPK4E7fTglrXdf0q1KHkMHDMqi2qNQD4HZpoVsBJUUnikUYqCOww0SiEQ4eI1BMG74cMpIBRttU03vdm25YNxPfqJ1vHOXgcc_2SLeMSzSiAt8_KDz12gXt2tW3ZcFi2L_HM2o08Rr7lbwVCktRj4ZiTjgQwllp5ll7252FQCJsa-iNb975xpHXWCryxSifQ5hMMo8qPgYtBf7C_2V7Wa9nKbUR6bgBsBYZyRXjlCrbLcRfGW5IpLu_R53Fi39GNBA-RdBJKt1zK8kEBDS2wCwkxGCEcE9MpZfT8GxcvTeCPCxI-_gAxXuqEY9gxuX11KBBZtttWgtUZgrSJoIv426CUyF0njZ9ortD01Mj1KdMzTEVv5Cr6vpJpzzitK8DhslM9jUTCj5OzgVLuWZwjX537KBnOyxxfjAGHikdMJb8BpFBRKoyfwrQ00w4gsaKA1fbYGvsUytU6kt3SngEHKUBohIeaGH-z94c8d33DD8GQMGHr_O-qhpE2yAqk5URGpQ3EciK4GkE3ErpStQq9gJeKWMr3qiPaEWCtS3Sji1t3de74d3ru9O93pZxiLEzgRAQRVkUDJbBAo-3rLAtFWpPDvDG7WdbWJ5KLH947X_JN98UppWt8gKMaPu9S9RRsL1YZdchh7_TZE2CqLJpDmgFKB4OZALTmSp2QS_Mg9AKcFKcXzVUEgvUisip4CsI6aO6jNn7CEvqS15QvuvMQn8nImJTyBYS7AW8uCbsCZtpMmIcH12G34WnlFy5WchMULMkhSYTTE6bQACPTr-uHV253J1d5ZbdCjrJCNl_VGGJ-tN6ORKJguNxNRQDw3dLbdDdtjhfXqB8vZlqsFHtZBgY2KxbVIjwTdw3tC6EBGJC_VKXNZJpvOvG1LSR4csq_qjplBg056F_awxKsn_A9h-OTC9MhDMNjrSi04kTmPhDkJKNpjwZVWftmm2WOSCo1ZcN8Rf5nP6Vy6A26Wofazq-diKYY5vdcZV3lUrK_Pru353IcGXBs0C5Ssq8E9cB-7npvzwZnzuh2pe4FHPBA9uyVdm8pPOLrA5pTad3nYXzn3OCvoSLbDY0Td3Es2-i-k4sG0FSSIZ8L4NM-9_Q1omPuxs9aK79bP6KfJ3H7TJqEiJiFIuvlrMYXgwMmwbeTd6WxFK51pg3L5kiVKdjNmrNxWZCR8xg6Ax864DUa_Lry-IcmNAZx8M3Pkxq3UYEEhHeZHF333xAcrQWY5RGZURMCc30B2S6LbFksRK37xahotPovE0vNCN-cWmKXES_14UsyEVvRwScgMcrv-vAd1P2t9NfYAOOQSWPFiBb6rDvGvnFTZ1pM9b1EKCLdLIrVKXnMN9gXuQ0PVnkKE_dsZMtJFDQTAP4NG47XPhkyiUQ_k5q43VdksQ2vOGnVeyoBRXshS3HV8pSNPQIHCa-WScS-t8B6KVP-vPP9lEjkvE4V-jchuK9s-z9VNNZ7asv19WbpCbUnZQ_jVYhtE4Wha3I69rFfoqBbTHCxAKPaPZlXGBwJ6VktdHRQE9lHx4mF_5gR0SQ1EQbZ73KocqcL7vuFU8riAMkKPgkU-p4rUMIiu-n0Dh8TDMvSWiTG2ePLTEhhJOFs8qjR6-IfZS6TqyH_O9c3-LTCtFx7MB6smiA3QHWs-xeYHcjlx8vxvob4QqGV8csp5tlErkacyVJ7TcyVFTkW0dnM2irjIxWKWtad8a98j7IhCM0GqU6SwBfgA3toitE8Z4bWKXQONOUKUSiHTxm6xu0gf3x2l0xc8UF8PvVtrpt3Z3gQUqpD6P9kCptM-vBPyPn6ogeirr-fu_mlEIE4XtHtgv-3ootd9RbsZjn0ta6qcpbQIWxE3wVyDTVPxMfCUU14xGYc-o0dQnFiyD099DIp3cOBa4zzcvSozBfnCSzR45nJMg_Cdzi52wpKOiSC-Fl5DKcJiOrrK-6c95Gs4WJIm6JTMtDEkuyH4y1RAqj4IZm70_OsP3bRxDmwIwCNF0Z6V7vC_O-5z3Hhil16o95BO9uAS-xVRYZyldt9a3HuVMQL7gjOVYzlexxgax_u56nq4esCN1ie728P1ZJWz1Zzi8CkbQtEAiJYVEzStG6b2UuaKXXvl9eRuoYpvkKP_--UAcI_kEiXQ9SoWpqxxBzBB02HkaM5KDtFgi21nvxIqsPdfscqQpzcpGBhgckLBEm_PUZAavIkM7btQU_GUzH7p6ihwPyM5bv6Hv3N1j5Gu_VP9GETHcLn_RHn1MziV7voASwvMiN2QvLImRzS1qrgnpCm8WwDCT_x8PRIDps4S0gDFoemTELS5QbcNYP7ohyGdLzA6GJ1XEdzU9NG1zvigjwwXocqJm9SkaPV9Y1q17pEKpD42_fXiQWSY4zqlgkWFrY5YcbwZkzAaHGtc_DrKQryMzKN4tDWcC8mOwVTJjTPCNlN8GOpFyI_KgGaWM4Di50NsxAGMpYtaPKEdNERmyYy1UXTbAG95UNP6lFJkEBOIaXpT9xcn0ZJVYWYHs8GS_YHVkbNNUXMn67-UMCOnESkIDwB0kfEZW2LK_jdX2vohzgRUHrzQlywYnGV_d-Lv6DIS5L6uzkTBkG3FTxuWh7Ll0tulNc9pQh9Jrx2L4MTf0IH9GoCIarFHZTWOxxMHHg6OOpNV6dbl_0_jWFdV6OwsZMsp91O4ZF9kz_Ipx1lP7c4ncWTioprlO2FYM71Ug3iHjw8ZO8R-Tq5dEZCZLg7nk17BDMeKJ-oELW-7XL_oe3pmOJbDBZyfD4YUQaHqSMcMorfNxDPzPR4Z5DFpPsBu5L9bzdTPRwEy13FvIeLpv_hj0xsT9PUWTP7CWGPcB_wwSKUBJ1lfQwOf21Qav6I0dUBnNu910JuGy57NOiv-o7NUAcQ3I5ND-O3wl9-Lfve6zHns0gDHxuBzVWB6Uh9A7qMy7azwJJmd9hwsf1SuoWc-fPgdKFg_OeSDTyrmWwdIZmO_rImyhO6YGewDw92g-TsbPncM8AqOfy7_Rs8pnEd5aCF8CrALRNYCbct1Gnrrikh0PlhRH1JPiUyzLxvHFfEJAGMEVOQ5jaTxXKxo43K_fpat8i5RyAH_9EVvh1h6Y8W53Isjo1_u3qnDDVSWjt64CNxT87sYlZps8XrSjmh9mgdzygIpbmSHK9vAQ3NYxhxET8Tl_SrCUUpyqcuzfN7TCtKldHIFi6G2FMgKlyhu5plznlfOZsqiaNimdwf5q6ybbQOYy6J-fmERTHF5QBWX1M_2pkSYBmLDtdSQnhlDI6Cp-FSkeosayOJiQ4bcO1PU-XiYNBoLNHTDSYE05hclISZZGw7VMEaDrjCClkU_mxBWZrorFbUhj-qcWfjlQ4AIiByF737ESfKS8OR6drvqKIaSxhNmn8hP_3CmhHKiC43b9y5ch8zmUEk4MaW_zOOcgDa81lgu23upVmDjlfCkDDJw3FjpDl6I-aGocf4X8Ph7K9TzqzVwXTczCvgTCyjJWCRSA9sVKwlm781vPSONgIDdShGaZsQGDHLllvAombjsw7Oo8pFNbZN-6kXNjwu4mX7Mt8Nn_Nku8XydoF7SmBZFZ8DzFmXQS5JGdU5q9Ij5i1uIug39K_dsFY1l0B-74E_E5ExJzxbZpqcTXo9M0v_eVTXAUcB4y0XIy3qaxXZniwU0c0BC78y8R0Lxq7hYHK-0O2V2JLpZaBUY78JCcWjboxCCoGiwmhtr6kXR1qamzakr24vXpxqv7SsEf7-NkhuGqJer98wHTchQzehd4pFS_K0kEGWxbr180HjXE-AoWvJ75CCdhzsJERvBK3GAMEG0lJiLFyrxx3ko36Wfg1AqcMJg7xKDS4LFUBwRfInR3xlqA2vhhUpPVUikiSNoJwByxc0gZIfRQ_bf32UgXGjCBpbF4C3RPWkihVXE1DJJLhvjMfOq1Hv7LHSOuVNeZDrc63Ac41_Tl-xVzODG3IJJws0WLbNiH8kdc-DKGv3WZhExcC9F9kXraufbA53gnZenQ7d4FxtKa9kxNgNkr0WDgD9SSLwLUOlZY_1Oo9-x6bo4WrDN92mv7woxnkuQ7AlamNdniRLujAZxL2Hz5H-ShJDAbB2DDzXFwJyk3aeUvASpqmWPli1hAmwDilczzzhZbd4CHYKRLCHZeOSdPuzpacFapEKSg9LlkU2Ejjnqtzxnp-_hbdnntp7f5qpPnvbMW7qdMbae1ZTq-cxJmrrUeKmQfLk6AwVXnw_mvHbrPSzjHOxmFkDI6E0LmSo8enc00ryJXg5UORIgSmCSpYvfVujd-qw72b0oPI0RiUox95akYrIuE3NM2v4vijQQVe0L_nzXu5aPvUsWinkXG9GdTxG7WaLYhhJSNsdT70YCeahW-7JC54AgnJaxBY9Hv4U9RiGTxQ4gIrgaDw9cQKtcTLsidm-onykiZC0P1KycoyxXB4yxzcrY3zRdq0gPYCIxYAow582yi3Av23mzOqk8GHwFB_5v8at0Q98LLFUsO8sTpdWzSHCnTUJ7jLccsqEDG8IBwvGdEkaQycx5rsEUOC1Y7Z2XI-rzwa8rHkJzgSCw8gO8dmiwqHeCo6-_P5PqgEuKx7N9TsV0P_r_FCVS7aDjXXaKgeqjd1ksJxlgLIRRForSpCeoMNaEnAHvD0zRgkdE1-SSoYuP1bO9UUcL0cxT0OwvJThDdW7mMxyUzkHTtQ9Jz8yCHNsXz-kMdiBmIghD5ZW9ukeLoxXjmZ6PHo8fuDjEclvQDTxhrIdSmJbpApRMxnQKf1vHIKREoSqOxxMN0G4g9U3dS1n1GOKqo-dudsSAHJWBh9NRViMkLWb-U9SI4YSm_Gh47uI1VYisfNSCINCvhojFgLyYw2mBZpNOYf0y8xoXIe2gwmXdOrCzUpiELZkn63TaQH-vXx5vmEiqukwsxWMRxYo9rE5FZbm4FMAFQERvAZfbeBC3P-ZbcYTPnjqxF5fqAxKAwyIc0u5KkzSl5FB5mZ52zme821dNeIfvz_asZJfa-wpQ1o1gnaKEwoy65W-H01PGeXkolIGNvKPj2-n_bp6ZKX4tKR1lJ82kEP3g3gsh2av3oJFGAiwSARJJ2z8eATO4oDRqLxQfm4wwwmDk_JXkUbzhvkPRXa18dEbU_0TgA7Xk5qHGs8DsIFDLAQdx79klZB_IyIhC7AyUPsx7XUCRKo4ocYvUUP89-pM-3JygbtPmr4c6QhxlNY0HgE2aPgsIrhwubnmD1tpHz6M2j4WLq1glbT88AF_HduE6Yih_7Dafhhd8pvEFAs1CABB5qTFWq7Fl2iSt-JjiRpA8kXClL6pGv6gWWpjpYjIWhucb3QLKjPEizqKTP84K98YySTjSqleLUQCaHXemyYCXMf_Cl-AkbbRaeY4rgmbVq2K_DbJyQyE57vS1Ynqd3Hg7M76TrGlZ8tq4ZC3B5ZteQW4fYobuvuXtWWanA1C6rMBZ-ZpTDWroG-wQs5njXoXfoV4ABhlqNh2Nujgp6h23IUZET51Nnvf9y7M1voGQ7e_Qt9nJoLBlGvL4ulw5O_fEXPf0ux-tN99xdafmbITOtJIDqNeDtECoGrHbTLBmq6hoE0KeEAY9jtjfkKEUMt8t0IvdlPHn-dbeyxoNvhqfDGo7uCKgagCEEw0AAXQOIJCNFEb4WuTC0-ZzhsMRwQTz-3-z-15Jl6k5Y_h2KHpVQBCYIfkE6ZosYDta0kK4Mdxw0IbheEPDJrnAhFXn9E9fepYGRQ3W3IreysuBnQh7VbXTeNTg_SAqO-kUoPQX02Jzvx38SjU2E61Y3BFVVVGIHV7boHLa5J0-_vv_BlKroqGDfH8Zc7swnyKNy0qYtCJRTBVx2jczxCgDvTyNp6wdEvbtoUlhnXMyhDto4OqEZAwERb6o73WkgSZSUp8R1Jrilm-DipHbLN3wJOG5HbIy1PyphlVaofILJejpGfitJRS2vkCF94ZP1oqjzmY7UAs52ajtrH0INv9ccmKdNZ1D9P4H_NCgqzJiyMs5oHGw7CTwJ54Vre-2v1VzdLTm_hFMlsIA6s1PY-6ap2XvUGuMU5GTP6xDrVq8Rch2Hl1kaBPkRUTHq6bh2aUfsSCcFYncJBYUF_MKhPJZeNPcP1DPhMDDMOF2OLlcH8e6dVvlqwsM24N7I4fjNX8nLo_4QhcUTKu1ZuQsjfXDOZSVoueyCx1mEpt-PwlL7zoH-AAArG8BNILZZjTZZ8PFXPg35bmwRYcth2_GOTrzJr3R3yBYajZ1qLLWl2KIPa5jOm6LRjmQX9q4mE8xetCnr5UW-sY21FN4rbP-iS8_Ba1lru4z6JYqKBqBhISx9OMkU-T_zt7MVMT1l9rD6I3cA_LW99YHc2T91J-wEfYhk5ZG7_RBgTstIyqdsQUOdxSjd0SSJcSAgi6bqBt-Lkj-_jBdyDX3SENHIu7Ir5bQ4F-VlXaaatXWTG7DUWlzqEymKD3heOAFw8TVSwxGA_yrGkgeUC_yooylLGJOG9OKDHP6-uaDpphYMTZ493WrPACZBAD6iJC2_flkr7PxLOudpjPYxRAr6A0mO35fOHYCM8LMvSkSUBsMY5vh768lHZ4VtUVwxzUg5AQ0gpPNo2pLjJ8iMAkBALPsFz08kyDeKcsTUOXFWNU46f_1j3v8skK0vq1Elb0dpu-rC5B6EkZTVj_fNO6FIh4TBTTaorVhXYEDWo7-y4nQjsGswbjGTqmBecv9uKxzI0N1LdODxdYkfuli95kofsuuPnAKifbsdUUArJBOT39L_m_ZQ-YSPZYljNdPQKvymOYPGNXXFXDUlz4Ai9KEaDZGrKJivppl6TX3-5j381LKdPDLP1wksBlReIr76BSnkU3jikKP7S1dmaVK1-dKtisvfRI8b4gk99SKe2KetsHpV1esQQfn77QGlKODbIyrGEa0AmrMlOkbV7zAk6jt3mWGqbDSHK7_-RPanbNfS2J-S6W6SPFWDQsaghy6wwpWuijlLk9jdZvuWIsWovBqBeU9P2CPgfGqmyTt5JLfv8wV2I0hpKOmza_nggUdPvGqI45Dctm3fkWUJDgiZFm0KIN6ih6pYKFif10kF96tYzcB7l67I1ybOuO3ZU0wfPURJ9dhv9I1FS3n7HHCvRvi1Vz8LCikNU6EIe_wSdDNXBNLbIemvY_PMRDC6Ldr7xeeCVQ5WePbU4WvDeevbjRsJnrB7-H0izo9TgLuW7a-RP-GoH6ooobuORshfdYCJsO-wJt-0ihG8iwQy3UeNdDj8Tw71xmbc_itsEJaeyQeGZK5-paUM8ZTojpKylPURQv3vka5QuR0WOZz180uH5TEwkqmYURVm7Hinc_kjj1XD5fIm1ZIsczxhTu3krT-4EWMgNTk7hsxEOgGuNR2cEuGcDSbKHZcX-KiGbq9BmBzcu9ZD4ifYt_lK7oy3AdOAy46Ch-j4wpgxRPWaJpPrSkY2IeL2WSCEXC976z4DPfVXvl5cTtRv0uvJK1NEfpqDP5UhkwYDi5r6rvw1I-94FRRuYOP_er2jDfk-ZO1k2uviNR5CJFi1zbAQVMYVON7-PgdHNsQUaI2n09BdpnfXmtjiWT6ZsWxuESLGLSct9TdJvZ0Tlrhq3LllB9TuepKVR0lu8Dhg48iN3qicy1dcPkSqwGiI10Zx9nDx1fux3U6hfC6RFjloIXD5rkkNy06ooeplsK_SARQH2_m2ngWYcErwPhbv0hvZhJA9YRyLjyzPldvrronylk983tnwXghD_cyOc83-LOnDAqxcbN3Eul5ab8x9ygf_4pqz8IA7jsjgZF-S6a_6SaY0Z-lRm76Z_Nx_NKt2mQslrhEeI6bpnpcovQsfepwYZCdfniQsUAK7uo9rSuZdTOygtjTBYs4CqJ5s8ow8c8iHghSSKrRXDj5D6S5dmUAAPGn41kt8Ty5EdUyKqbsn9yJ2bMW7hzd9BY99PxfbydXJxm2oRygQBb9z6Y7Tz9V3OAbh6FWpeU4Y8qVl2aEZtouIckIzqeL8u8d47OVLUKEBnu77SWvt9Np7k6eq3jcpOz8EekvLl95HDYZQs0RLjZfHID-VZwfrjpW5IqMb6eg2zcWtDKtrLBWlrKKC8RVCI_7lpG2Madkp2wUbiN2gsk8LmjOMQoiiks0aSAUP1_UkN3pusU_cTP_CTYZbiZAHRoDSz9WS4mQKJs8_iYjI-gLjk0IfcwsLitAtA52_dzBVxu_5zj4Rp-jrH7g2nX1deePr2NnU9YGZ3wWDfEgLhwIXdKbYAhWknYM6pn7MYgLLE8CRqQZXuaBaZc5ymU9QzZK0e4heSZ9jHw85IcPjDptasGGfGokFroWDb961Gwjs9NEGf5p6rrj_ka541ndNvGJZ_rdnHjCQLHga015kId0x8k2z7ButVt5skxYYVtCYSLYlh4ymdL6rN6p--JloqKTxLGBVxfHIiudCsd2ou9JKxf45LvaRp5FeEJgskOMCWKBHDRdGaNu8428wtDOwrcCg9B7Prihq143zx_WwdnHFcJv0J8FwANr_vkn8BeZEh_MBhXGeNHYJ4rSCDdAHyJsxUMiH2yf9Uw0qRUJxhhZEMHJKY1pXRzKaDQRRE_0VUxazE42Wr2AL0l8w17gB6oXSHhnl1rFbk63fmZxoUqzNE5YwTU70OeBYm67pj0UXfjiKRkenBbUAnNts2yPAmTyFZRZSTOpxwO0U6zNWqxvnw3zwXgwvHnCGPhb_PK2ZHdvbENyBTclzjnf6iE_4SBkF26KJDHtkew7nGMlfnOAODuZN-n3Oe9WUNGY35MeCyl5AF4BKPsuEFBP-qzcsATrZ5jsD6pgvPp34E3a3bUrcS3G4zlSS8izflpDaAV0EGa9cgm5rJSTPnD5DNgfcxvq1h_eb-i7HcQX0a-7CXl_2AkMrarpB7HCOfHWZNDtShJMGjEFo6XiauQXMZOqX1HNvSDlUdxw4C4vEvCmEun7ou_UXvwlwJDRdumdomuHmUhuOgXGuWNzis4U2Qymcs0SB1MZtR4Q9pLq3HizqgNdVYuhuU3SkVotZeRupPW4v-eGDfrA59lhRpRDhYqSPnnvnp1"
        }

        get_json ["accountpanel"], mock_response
    end

    def get_vaults vaults_info
        vaults_info.map do |info|
            id = info["uuid"]
            attrs = decrypt_json info["encAttrs"]
            Vault.new id: id,
                      name: attrs["name"],
                      accounts: get_vault_accounts(id)
        end
    end

    def get_vault_accounts id
        vault = get_json ["vault", id, "0", "items"]
        vault["items"].map { |i|
            parse_account i["uuid"],
                          decrypt_json(i["encOverview"]),
                          decrypt_json(i["encDetails"])
        }
    end

    def parse_account id, overview, details
        Account.new id: id,
                    name: overview["title"],
                    username: find_field(details["fields"], "username"),
                    password: find_field(details["fields"], "password"),
                    url: overview["url"],
                    notes: details["notesPlain"]
    end

    def find_field fields, id
        f = fields.find { |i| i["designation"] == id } || {}
        f["value"] || ""
    end

    def sign_out
        mock_response = {"success" => 1}
        put ["session", "signout"], {}, mock_response
    end

    #
    # Decrypted with session keys and parsed network requests
    #
    # All the requests after the initial authentication and the key
    # exchange sequence are JSON container encrypted and wrapped in
    # another JSON container.
    #

    def get_json url_components, mock_response = nil
        decrypt_json get url_components, mock_response
    end

    def post_json url_components, args, mock_response = nil
        decrypt_json post url_components, args, mock_response
    end

    #
    # Http interface (raw network requests)
    #

    def get url_components, mock_response = nil
        url = Util.url_escape_join url_components
        @http.get "https://#{@host}/api/v1/#{url}", request_headers, mock_response
    end

    def post url_components, args, mock_response = nil
        url = Util.url_escape_join url_components
        @http.post "https://#{@host}/api/v1/#{url}", args, request_headers, mock_response
    end

    def put url_components, args, mock_response = nil
        url = Util.url_escape_join url_components
        @http.put "https://#{@host}/api/v1/#{url}", args, request_headers, mock_response
    end

    #
    # Special POST/PUT which are needed to be signed with a temporary session id
    # This is needed for requests like device registration or reauthorization
    #

    def post_with_temp_session url_components, args, temp_session_id, mock_response = nil
        url = Util.url_escape_join url_components
        @http.post "https://#{@host}/api/v1/#{url}",
                   args,
                   request_headers(temp_session_id),
                   mock_response
    end

    def put_with_temp_session url_components, args, temp_session_id, mock_response = nil
        url = Util.url_escape_join url_components
        @http.put "https://#{@host}/api/v1/#{url}",
                  args,
                  request_headers(temp_session_id),
                  mock_response
    end

    def request_headers session_id = nil
        {"X-AgileBits-Client" => CLIENT_ID_STRING}.merge session_request_headers(session_id)
    end

    def session_request_headers session_id = nil
        session_id ||= @session.id if @session

        if session_id
            {
                "X-AgileBits-Session-ID" => session_id,

                # TODO: Compute this, at the moment it look like it's verified by the server
                #       It's not added to the headers as a blank in case the server starts
                #       verifying it when it's present.
                # "X-AgileBits-MAC" => ""
            }
        else
            {}
        end
    end
end

#
# main
#

# TODO: Provide a function to generate random uuid in 1P format

# Set up and prepare the credentials
http = Http.new :force_online
config = YAML::load_file "config.yaml"
client_info = ClientInfo.new username: config["username"],
                             password: config["password"],
                             account_key: config["account_key"],
                             uuid: config["uuid"]

# Open all the vaults
op = OnePassword.new http
vaults = op.open_all_vaults client_info

# Print out the results
vaults.each_with_index do |v, i|
    puts "#{i + 1}: '#{v.name}' #{v.id}"
    v.accounts.each_with_index do |a, i|
        puts "  - #{i + 1}: #{a.name} #{a.username} #{a.password} #{a.url} #{a.notes}"
    end
end
