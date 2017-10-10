# Copyright 2017 Akamai Technologies http://developer.akamai.com.

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

#     http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


require 'cgi'
require 'openssl'
require 'optparse'

module Akamai
  class AuthTokenError < StandardError
    def initialize(msg="My default message")
      super
    end
  end

  class AuthToken
    class << self
      attr_accessor :token_type, :token_name, :key, :algorithm, :salt,
        :start_time, :end_time, :window_seconds, :field_delimiter,
        :acl_delimiter, :escape_early, :verbose

      ACL_DELIMITER = '!'

      def generate_token(token_type: "URL", token_name: 'hdnts', key: nil,
                         algorithm: 'sha256', salt: nil, start_time: 'now', end_time: nil,
                         window_seconds: nil, field_delimiter: '~', escape_early: false,
                         verbose: false, url: nil, acl: nil,
                         ip: nil, payload: nil, session_id: nil)

        raise AuthTokenError, 'You must provide a secret in order to generate a new token.' if (key.nil? || key.length <= 0)

        if start_time.to_s.downcase == 'now'
          start_time = Time.new.getgm.to_i
        else
          begin
            start_time = 0 if start_time < 0
          rescue
            raise AuthTokenError, 'start_time must be UNIX timestamps or now'
          end
        end

        raise AuthTokenError, 'You must provide an expiration time or a duration window..' if (end_time.nil? && window_seconds.nil?)

        if end_time
          begin
            end_time = 0 if end_time < 0
          rescue
            raise AuthTokenError, 'end_time must be UNIX timestamps'
          end
        end

        if window_seconds
          begin
            window_seconds = 0 if window_seconds < 0
          rescue
            raise AuthTokenError, 'window_seconds must be numeric'
          end
          end_time = start_time + window_seconds
        end

        if end_time <= start_time
          raise AuthTokenError, 'Token will have already expired.'
        end

        if (acl.nil? && url.nil?) || (acl && url)
          raise AuthTokenError, 'You must provide a URL or an ACL'
        end

        if verbose
          puts "Akamai Token Generation Parameters"
          puts "Token Type      : #{token_type}"
          puts "Token Name      : #{token_name}"
          puts "Start Time      : #{start_time}"
          puts "End Time        : #{end_time}"
          puts "Window(seconds) : #{window_seconds}"
          puts "IP              : #{ip}"
          puts "URL             : #{url}"
          puts "ACL             : #{acl}"
          puts "Key/Secret      : #{key}"
          puts "Payload         : #{payload}"
          puts "Algo            : #{algo}"
          puts "Salt            : #{salt}"
          puts "Session ID      : #{session_id}"
          puts "Field Delimiter : #{field_delimiter}"
          puts "ACL Delimiter   : #{ACL_DELIMITER}"
          puts "Escape Early    : #{escape_early}"
        end

        hash_code = Array.new
        new_token = Array.new

        if ip
          new_token.push('ip=%s' % escape_early(ip))
        end
        if start_time
          new_token.push('st=%s' % start_time)
        end
        new_token.push('exp=%s' % end_time)

        if acl
          new_token.push('acl=%s' % acl)
        end
        if session_id
          new_token.push('id=%s' % escape_early(session_id))
        end
        if payload
          new_token.push('data=%s' % escape_early(payload))
        end

        hash_code = new_token.clone

        if url and !acl
          hash_code.push('url=%s' % escape_early(url))
        end

        if salt
          hash_code.push('salt=%s' % salt)
        end

        if !(['sha256', 'sha1', 'md5'].include? algorithm)
          raise AuthTokenError, 'Unknown algorithm'
        end

        bin_key = Array(key.gsub(/\s/,'')).pack("H*")
        digest = OpenSSL::Digest.new(algorithm)
        token_hmac = OpenSSL::HMAC.new(bin_key, digest)
        token_hmac.update(hash_code.join(field_delimiter))

        new_token.push('hmac=%s' % token_hmac)

        return ("%s=" % token_name) + new_token.join(field_delimiter)
      end

      def escape_early(text)
        return CGI::escape(text).gsub(/(%..)/) {$1.downcase}
      end
    end
  end
end
