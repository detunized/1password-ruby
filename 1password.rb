require "hkdf"
require "pbkdf256"
require "digest"
require "httparty"
require "openssl"
require "base64"
require "json"
require "yaml"
require "uri"

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
            http_proxyaddr: "localhost",
            http_proxyport: 8080,
            verify: false
        }
    end

    def get url
        self.class.get url, @options
    end

    def post url, args
        self.class.post url, @options.merge({
            body: args.to_json,
            headers: {
                "Content-Type" => "application/json"
            }
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

class Srp
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

        # ==== baked response (for now)
        response = {
            "encConfig" => nil,
            "sessionID" => "W7FLK6HU5BC7XP7PCHVLGTRSGE",
            "userB" => "b715a789a7d591fbde439abbc8ea3095cb87c3312ee450d491c46ecb43a58fb95a92402dcce2eeb0fe0cf2f3a007abb76aa343f51cd7550d96799fa9078dff185a444afe73ce90797c3c4a2b9f6f822a1ae64bdd6dabfb2b450a21c6c2d414bae35ebb3d02a6930c81d98d16255ba12db24904650d22e0c8b70b6382a96899a86e07eab970c5857919d81679556b4104045c33c0b116acb06181f0710f416bfd554e38aff7b723c9e4203b63a3945c7d1cd7fd736da5c8e9171e692e60492fcbf789441d2b6a5162740bcd1caa5ecd368c145db8d5ff451222d92d2bf74a77d92be69f2768047a6b4fff475a19529292c36d05d43fda71a5cafae1719b4b36e9c81830f8fa3dbe6fe61376f1332a28526aaceaa0196641ec9b96a734a78dfc4d2402d3729963c693390e9ea18a17bc51ef64e70cf10a1c1bcfda1f8f53d687cffffb7367b348c1b66f138266c835c90f1484e22d25f0b611d45f5599518589217de022e032c5af8567a14ac31da4b44fea07043042abae4e5a503e1731c219b08aee3d372b29164fd8adb8cac8770022732ffd58c604803fdd95a61e1f01a68fabf73a0b5b9aeb91e9cac867b9723649b99c47242c56c7e23da3a2291b3bfc102b252f83479c90fa04d41aae9b8adc6ef845fb1e5e004f01d436f9d3471cc17c3b038edff2a2ac1d1b06797bcbb186446a78c9ec49ef6469f34ec71f73c8f1ff"
        }
        # ====

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
        Crypto.sha256 Util.bn_to_hex z
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
            Util.bn_from_str combine_with_account_key k2
        else
            raise "Invalid method '#{auth["userAuth"]["method"]}'"
        end
    end

    def combine_with_account_key key
        a = Crypto.hkdf @account_key, @session.key_format, @session.key_uuid
        ab = a.bytes
        kb = key.bytes
        raise "Key doesn't match hash function" if kb.size != ab.size
        Util.bytes_to_str ab.size.times.map { |i| ab[i] ^ kb[i] }
    end
end

class OnePass
    CONTAINER_TYPE = "b5+jwk+json"
    ENCRYPTION_MODE = "A256GCM"

    def initialize http = nil
        @http = http || Http.new
        @host = "my.1password.com"
    end

    def login username:, password:, account_key:, uuid:
        response = get_user_info username, uuid
        @session = Session.new response
        @key = Srp.perform username: username,
                           password: password,
                           account_key: account_key,
                           session: @session,
                           http: self
        verify_key
    end

    def get_user_info email, uuid
        get ["auth", email, uuid, "-"]

        # ==== baked response (for now)
        {
            "accountKeyFormat" => "A3",
            "accountKeyUuid" => "FRN8GF",
            "sessionID" => "W7FLK6HU5BC7XP7PCHVLGTRSGE",
            "status" => "ok",
            "userAuth" => {
                "alg" => "PBES2g-HS256",
                "iterations" => 100000,
                "method" => "SRPg-4096",
                "salt" => "-JLqTVQLjQg08LWZ0gyuUA"
        }
        # ====
    }
    end

    def verify_key
        payload = JSON.dump({"sessionID" => @session.id})
        encrypted_payload = encrypt_payload payload, "\0" * 12 # TODO: Generate random
        post ["auth", "verify"], encrypted_payload
    end

    def encrypt_payload plaintext, iv
        ciphertext = encrypt plaintext, iv
        ciphertext_base64 = Util.str_to_base64 ciphertext
        iv_base64 = Util.str_to_base64 iv

        {
            "cty" => CONTAINER_TYPE,
            "data" => ciphertext_base64,
            "enc" => ENCRYPTION_MODE,
            "iv" => iv_base64,
            "kid" => @session.id
        }
    end

    def decrypt_payload payload
        raise "Unsupported container type '#{payload["cty"]}'" if payload["cty"] != CONTAINER_TYPE
        raise "Unsupported encryption '#{payload["enc"]}'" if payload["enc"] != ENCRYPTION_MODE
        raise "Session ID does not match" if payload["kid"] != @session.id

        ciphertext = Util.base64_to_str payload["data"]
        iv = Util.base64_to_str payload["iv"]

        decrypt ciphertext, iv
    end

    # Notes on the encryption
    #
    # It seems 1password has AES-256-GCM hardcoded, though there are the "alg"
    # and the "enc" parameters everywhere
    # The authentication tag is simply appended to the ciphertext (the last 16 bytes)

    def encrypt plaintext, iv
        c = OpenSSL::Cipher.new('aes-256-gcm')
        c.encrypt
        c.key = @key
        c.iv = iv
        c.auth_data = ""
        c.update(plaintext) + c.final + c.auth_tag
    end

    def decrypt ciphertext, iv
        c = OpenSSL::Cipher.new('aes-256-gcm')
        c.decrypt
        c.key = @key
        c.iv = iv
        c.auth_tag = ciphertext[-16..-1]
        c.auth_data = ""
        c.update(ciphertext[0...-16]) + c.final
    end

    #
    # Http interface
    #

    def get url_components
        url = Util.url_escape_join url_components
        @http.get "https://#{@host}/api/v1/#{url}"
    end

    def post url_components, args
        url = Util.url_escape_join url_components
        @http.post "https://#{@host}/api/v1/#{url}", args
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
    op = OnePass.new
    op.instance_variable_set :@key, "key key key key key key key key!"
    ciphertext = op.encrypt "plaintext", "iv iv iv iv!"

    assert Util.str_to_hex(ciphertext) ==
        "94ae5caa13ff087e455691d8e5d38ee438e01116fde4341228"
end

def test_all
    config = YAML::load_file "config.yaml"
    op = OnePass.new
    op.login username: config["username"],
             password: config["password"],
             account_key: config["account_key"],
             uuid: config["uuid"]

    assert Util.str_to_hex(op.instance_variable_get(:@key)) ==
        "d376bc3fdabc77d22ee987689a365c1ad58566829690effa1c1933c585c505df"
end

#
# main
#

# Run tests
private_methods.grep(/^test_/).each do |m|
    send m
end

config = YAML::load_file "config.yaml"
op = OnePass.new
p op.login username: config["username"],
           password: config["password"],
           account_key: config["account_key"],
           uuid: config["uuid"]
