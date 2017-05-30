require "hkdf"
require "pbkdf256"
require "digest"
require "httparty"
require "openssl"
require "base64"
require "json"
require "yaml"
require "uri"
require "ap" # TODO: Remove from release

HOST = "https://my.1password.com/api/v1"

SIRP_N = OpenSSL::BN.new "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934063199FFFFFFFFFFFFFFFF", 16
SIRP_g = OpenSSL::BN.new 5

# HTTP with proxy
# mitmproxy must be set up on localhost:8080 with server replay
# $ mitmproxy -S login.flow --kill --no-pop -s replace.py
class Http
    include HTTParty

    def initialize
        @options = {
            # http_proxyaddr: "localhost",
            # http_proxyport: 8080,
            verify: false
        }

        @post_headers = {
            "Content-Type" => "application/json"
        }
    end

    def get url, headers = {}
        self.class.get url, @options.merge({
            headers: headers
        })
    end

    def post url, args, headers = {}
        self.class.post url, @options.merge({
            body: args.to_json,
            headers: @post_headers.merge(headers)
        })
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

    def self.bn_from_str str
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

class Session
    attr_reader :id,
                :key_format,
                :key_uuid,
                :srp_method,
                :key_method,
                :iterations,
                :salt

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

class Credentials
    attr_reader :username, :password, :account_key

    def initialize username:, password:, account_key:
        @username = username
        @password = password
        @account_key = account_key
    end
end

class Srp
    # TODO: Use Credentials here
    def self.perform username:, password:, account_key:, session:, http:
        srp = new username: username,
                  password: password,
                  account_key: account_key,
                  session: session,
                  http: http
        srp.perform
    end

    #
    # Private
    #

    def initialize username:, password:, account_key:, session:, http:
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
        @secret_a = Util.bn_from_str "\0" * 32 # TODO: Make it random
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
        hash_a_b = Util.bn_from_str Crypto.sha256 a_b
        x = compute_x
        s = Util.bn_from_str @session.id
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
            Util.bn_from_str @account_key.combine k2
        else
            raise "Invalid method '#{auth["userAuth"]["method"]}'"
        end
    end
end

class OnePass
    MASTER_KEY_ID = "mp"

    def initialize http = nil
        @http = http || Http.new
        @host = "my.1password.com"
        @keys = {}
    end

    def login username:, password:, account_key:, uuid:
        account_key = AccountKey.parse account_key if account_key.is_a? String
        # TODO: Pass this in as Credentials?
        credentials = Credentials.new username: username, password: password, account_key: account_key

        response = get_user_info username, uuid
        @session = Session.new response

        add_key Srp.perform username: username,
                           password: password,
                           account_key: account_key,
                           session: @session,
                           http: self

        verify_key

        get_account_info credentials
    end

    def session_key
        @keys[@session.id]
    end

    def add_key key
        @keys[key.id] = key
    end

    def get_account_info credentials
        account_info = JSON.load decrypt_payload get ["accountpanel"]

        decrypt_keys account_info["user"]["keysets"], credentials
        parse_people account_info["people"]
        get_vaults account_info["vaults"]
    end

    def decrypt_keys keysets, credentials
        sorted = keysets.sort_by { |i| i["sn"] }.reverse

        if sorted[0]["encryptedBy"] != MASTER_KEY_ID
            raise "Invalid keyset (key must be encrypted by '#{MASTER_KEY_ID}')"
        end

        add_key derive_master_key sorted[0]["encSymKey"], credentials

        sorted.each do |i|
            key_info = JSON.load @keys[i["encryptedBy"]].decrypt i["encSymKey"]
            key = Util.base64_to_str key_info["k"]
            add_key EncryptionKey.new id: i["uuid"], key: key
        end
    end

    def derive_master_key key_info, credentials
        algorithm = key_info["alg"]
        encryption = key_info["enc"]
        iterations = key_info["p2c"]
        salt = Util.base64_to_str key_info["p2s"]
        username = credentials.username.downcase
        password = Util.normalize_utf8 credentials.password
        account_key = credentials.account_key

        if algorithm.start_with? "PBES2-"
            raise "Not supported yet"
        elsif algorithm.start_with? "PBES2g-"
            k1 = Crypto.hkdf salt, algorithm, username
            k2 = Crypto.pbes2 algorithm, password, k1, iterations
            key = account_key.combine k2

            EncryptionKey.new id: MASTER_KEY_ID, key: key
        else
            raise "Invalid algorithm '#{algorithm}'"
        end
    end

    def parse_people people
    end

    def get_vaults vaults
        vaults.each do |i|
            r = @http.get "https://my.1password.com/api/v1/vault/#{i["uuid"]}/items/overviews", request_headers
            ap JSON.load decrypt_payload r
        end
    end

    def get_groups
        r = @http.get "https://my.1password.com/api/v1/accountpanel/group/27tqtfrsxlzxyeal6rawfnwwhq?attrs=pubkey,vaultaccess", request_headers
        File.open("group.json", "w") { |io| io.write decrypt_payload r }

        r = @http.get "https://my.1password.com/api/v1/accountpanel/vault/4tz67op2kfiapodi5ygprtwn64?attrs=accessors", request_headers
        File.open("vault.json", "w") { |io| io.write decrypt_payload r }
    end

    def get_user_info email, uuid
        get ["auth", email, uuid, "-"]
    end

    # TODO: Rename this, the name doesn't make sense
    def verify_key
        payload = JSON.dump({"sessionID" => @session.id})
        encrypted_payload = encrypt_payload payload, "\0" * 12 # TODO: Generate random
        response = post ["auth", "verify"], encrypted_payload
        JSON.load decrypt_payload response
    end

    def encrypt_payload plaintext, iv
        session_key.encrypt plaintext, iv
    end

    def decrypt_payload payload
        session_key.decrypt payload
    end

    #
    # Http interface
    #

    def get url_components
        url = Util.url_escape_join url_components
        @http.get "https://#{@host}/api/v1/#{url}", request_headers
    end

    def post url_components, args
        url = Util.url_escape_join url_components
        @http.post "https://#{@host}/api/v1/#{url}", args, request_headers
    end

    def request_headers
        if @session
            {
                "X-AgileBits-Session-ID" => @session.id,
                "X-AgileBits-MAC" => "" # TODO: Compute this
            }
        else
            {}
        end
    end
end

#
# poor man's tests
#

def assert condition
    line = caller[0][/:(\d+):/, 1].to_i
    code = IO.readlines(__FILE__)[line - 1]
    puts "Test failed: #{caller[0]}\n> #{code}" if !condition
end

def test_encrypt
    ciphertext = Crypto.encrypt_aes256gcm "plaintext",
                                          "iv iv iv iv!",
                                          "key key key key key key key key!"

    assert Util.str_to_hex(ciphertext) == "94ae5caa13ff087e455691d8e5d38ee438e01116fde4341228"
end

def test_account_key_parse
    k = AccountKey.parse "A3-RTN9SA-DY9445Y5FF96X6E7B5GPFA95R9"
    assert k.format == "A3"
    assert k.uuid == "RTN9SA"
    assert k.key == "DY9445Y5FF96X6E7B5GPFA95R9"
end

def test_all
    config = YAML::load_file "config.yaml"
    op = OnePass.new
    op.login username: config["username"],
             password: config["password"],
             account_key: config["account_key"],
             uuid: config["uuid"]

    key = op.send :session_key
    assert Util.str_to_hex(key.key) == "d376bc3fdabc77d22ee987689a365c1ad58566829690effa1c1933c585c505df"

    keys = op.instance_variable_get :@keys
    master_key = keys["mp"]
    assert master_key.id == "mp"
    assert Util.str_to_hex(master_key.key) == "44c38e8fedb84a1ab5ba74ed98dde931f6500ae39c1d9c85e20a7268ab2074f0"
end

#
# main
#

# Run tests
private_methods.grep(/^test_/).each do |m|
    send m
end