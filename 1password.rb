#!/usr/bin/env ruby

# Copyright (C) 2017 Dmitry Yakimenko (detunized@gmail.com).
# Licensed under the terms of the MIT license. See LICENCE for details.

require "openssl"
require "hkdf"
require "securerandom"
require "httparty"
require "json/jwt"

DEBUG_DISABLE_RANDOM = false
DEBUG_NETWORK_LOG = false

#
# Network
#

class Http
    include HTTParty

    # Network modes:
    #  - :default: return a fake response if it exists in responses.yaml
    #  - :force_online: always go online
    #  - :force_offline: never go online and return nil even if it doesn't exist
    def initialize network_mode = :default
        @network_mode = network_mode
        @json_headers = {
            "Content-Type" => "application/json; charset=UTF-8"
        }
        @responses = YAML.load_file "responses.yaml"
        @seen_urls = Hash.new { 0 }
    end

    def get url, headers = {}
        make_request "GET", url do
            get_raw url, headers
        end
    end

    def post url, args = {}, headers = {}
        make_request "POST", url, args do
            post_raw url,
                     args.to_json,
                     headers.merge(@json_headers)
        end
    end

    def put url, args = {}, headers = {}
        make_request "PUT", url, args do
            put_raw url,
                    args.to_json,
                    headers.merge(@json_headers)
        end
    end

    #
    # private
    #

    # Log and make the request
    def make_request method, url, args = nil
        if DEBUG_NETWORK_LOG
            puts "=" * 80
            puts "#{method} to #{url}"
            ap args if args
        end

        response = make_fake_response url
        if response.nil?
            response = yield
        end

        if DEBUG_NETWORK_LOG
            puts "-" * 40
            puts "HTTP: #{response.code}"
            ap response.parsed_response
        end

        raise "Request failed with code #{response.code}" if !response.success?

        response.parsed_response
    end

    def get_raw url, headers
        self.class.get url, headers: headers
    end

    def post_raw url, args, headers
        self.class.post url, body: args, headers: headers
    end

    def put_raw url, args, headers
        self.class.put url, body: args, headers: headers
    end

    def make_fake_response url
        url_responses = @responses.find_all { |i| i["url"] == url }

        case @network_mode
        when :default
            return nil if url_responses.empty?
        when :force_online
            return nil
        when :force_offline
            # Do nothing
        else
            raise "Invalid network_mode '#{@network_mode}'"
        end

        index = @seen_urls[url]
        response = if index < url_responses.size
            url_responses[index]
        else
            url_responses.last
        end

        @seen_urls[url] += 1

        @response_class ||= Struct.new :parsed_response, :code, :success?
        @response_class.new response["response"], 200, true
    end

    def should_return_fake? url
        case @network_mode
        when :default
            @responses.key? url
        when :force_online
            false
        when :force_offline
            true
        else
            raise "Invalid network_mode '#{@network_mode}'"
        end
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
    def self.random size
        if DEBUG_DISABLE_RANDOM
            "\0" * size
        else
            SecureRandom.random_bytes size
        end
    end

    BASE32_ALPHABET = "abcdefghijklmnopqrstuvwxyz234567"

    def self.random_uuid
        26.times
            .map { SecureRandom.random_number BASE32_ALPHABET.size }
            .map { |i| BASE32_ALPHABET[i] }
            .join
    end

    def self.sha256 str
        Digest::SHA256.digest str
    end

    def self.hkdf ikm, info, salt
        h = HKDF.new ikm, info: info, salt: salt, algorithm: "sha256"
        h.next_bytes 32
    end

    def self.pbes2 algorithm, password, salt, iterations
        hashes = {
            "PBES2-HS512" => "sha512",
            "PBES2g-HS512" => "sha512",
            "PBES2-HS256" => "sha256",
            "PBES2g-HS256" => "sha256",
        }

        hash = hashes[algorithm]
        raise "Unsupported algorithm '#{algorithm}'" if hash.nil?

        OpenSSL::PKCS5.pbkdf2_hmac(password, salt, iterations, 32, hash)
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

class Srp
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
        @secret_a = Util.bn_from_bytes Crypto.random 32
        @shared_a = SIRP_g.mod_exp @secret_a, SIRP_N
    end

    def exchange_a_for_b
        args = {
            "sessionID" => @session.id,
            "userA" => Util.bn_to_hex(@shared_a)
        }

        response = @http.post ["auth"], args
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

    def self.generate_random_uuid
        Crypto.random_uuid
    end

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
        response = get ["auth", client_info.username, client_info.uuid, "-"]

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
        args = {
                     "uuid" => client_info.uuid,
               "clientName" => CLIENT_NAME,
            "clientVersion" => CLIENT_VERSION
        }

        response = post_with_temp_session ["device"], args, temp_session_id

        raise "Failed to register the device '#{client_info.uuid}'" if response["success"] != 1
    end

    def reauthorize_device client_info, temp_session_id
        response = put_with_temp_session ["device", client_info.uuid, "reauthorize"],
                                         {},
                                         temp_session_id

        raise "Failed to reauthorize the device '#{client_info.uuid}'" if response["success"] != 1
    end

    # TODO: Think of a better name, since the verification is just a side effect. Is it?
    def verify_session_key
        payload = JSON.dump({"sessionID" => @session.id})
        encrypted_payload = session_key.encrypt payload, Crypto.random(12)
        response = post_json ["auth", "verify"], encrypted_payload

        # Just to verify that it's a valid JSON and it has some keys.
        # Technically it should've failed by now eather in decrypt or JSON parse
        raise "Session key verification failed" if !response.key? "userUuid"
    end

    def get_account_info
        get_json ["accountpanel"]
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
        put ["session", "signout"], {}
    end

    #
    # Decrypted with session keys and parsed network requests
    #
    # All the requests after the initial authentication and the key
    # exchange sequence are JSON container encrypted and wrapped in
    # another JSON container.
    #

    def get_json url_components
        decrypt_json get url_components
    end

    def post_json url_components, args
        decrypt_json post url_components, args
    end

    #
    # Http interface (raw network requests)
    #

    def get url_components
        url = Util.url_escape_join url_components
        @http.get "https://#{@host}/api/v1/#{url}", request_headers
    end

    def post url_components, args
        url = Util.url_escape_join url_components
        @http.post "https://#{@host}/api/v1/#{url}", args, request_headers
    end

    def put url_components, args
        url = Util.url_escape_join url_components
        @http.put "https://#{@host}/api/v1/#{url}", args, request_headers
    end

    #
    # Special POST/PUT which are needed to be signed with a temporary session id
    # This is needed for requests like device registration or reauthorization
    #

    def post_with_temp_session url_components, args, temp_session_id
        url = Util.url_escape_join url_components
        @http.post "https://#{@host}/api/v1/#{url}",
                   args,
                   request_headers(temp_session_id)
    end

    def put_with_temp_session url_components, args, temp_session_id
        url = Util.url_escape_join url_components
        @http.put "https://#{@host}/api/v1/#{url}",
                  args,
                  request_headers(temp_session_id)
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
