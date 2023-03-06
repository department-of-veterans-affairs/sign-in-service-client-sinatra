# frozen_string_literal: true

require 'base64'
require 'digest'
require 'securerandom'

class Pkce
  CHAR_LENGTH = 48

  def initialize(length: nil)
    @length = (length || CHAR_LENGTH).to_i
  end

  def code_verifier
    @code_verifier ||= Base64.urlsafe_encode64(random_bytes, padding: false)
  end

  def code_challenge
    @code_challenge ||= Base64.urlsafe_encode64(Digest::SHA256.digest(code_verifier), padding: false)
  end

  def inspect
    "#<Pkce:#{object_id}>"
  end

  private

  attr_reader :length

  def random_bytes
    SecureRandom.random_bytes(length)
  end
end
