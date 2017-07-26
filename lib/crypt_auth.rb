require "crypt_auth/version"
require "crypt_auth/crypt_auth"

module CryptAuth
  class CryptAuth
    def initialize(user_id, api_key, crypt, m_id)
      @user_id = user_id
      @api_key = api_key
      @crypt = crypt
      @m_id = m_id
    end

    class AuthenticationFailure < StandardError
      def initialize(exception={})
        super exception
      end
    end

    def check_crypt
      digest = case @crypt.try(:bytesize)
               when 40
                 # See https://github.com/CyberAgent/car-superwall/blob/bce56/media/php/RewardAPI.php#L818
                 # {user_id}{api_key}でhash化
                 Digest::SHA1.hexdigest("#{@user_id}#{@api_key}")
               when 64
                 Digest::SHA256.hexdigest("#{@user_id}#{@api_key}")
               when 128
                 Digest::SHA512.hexdigest("#{@api_key}:#{@user_id}:#{@m_id}")
               else
                 crypt_error('crypt bytesize is not sha1/sha512')
               end

      crypt_error(digest) if @crypt != digest
    end

    private

    def crypt_error(digest)
      raise CryptAuth::AuthenticationFailure,
            I18n.t(:crypt_auth, scope: 'errors.log', default: '500_error', user_id: @user_id, crypt: @crypt, created_crypt: digest)
    end
  end
end
