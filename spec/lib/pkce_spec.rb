# frozen_string_literal: true

require 'pkce'

RSpec.describe Pkce do
  let(:pkce) { described_class.new }

  describe '#initialize' do
    it 'sets the length to the default value when no argument is given' do
      expect(pkce.send(:length)).to eq(Pkce::CHAR_LENGTH)
    end

    it 'sets the length to the given value when an argument is given' do
      pkce = described_class.new(length: 32)
      expect(pkce.send(:length)).to eq(32)
    end
  end

  describe '#code_verifier' do
    it 'returns a Base64 encoded string' do
      expect(pkce.code_verifier).to match(/\A[A-Za-z0-9\-_]*\z/)
    end
  end

  describe '#code_challenge' do
    let(:expected_code_challenge) do
      Base64.urlsafe_encode64(Digest::SHA256.digest(expected_code_verifier), padding: false)
    end
    let(:expected_code_verifier) { 'some_code_verifier' }

    it 'returns a Base64 encoded string' do
      expect(pkce.code_challenge).to match(/\A[A-Za-z0-9\-_]*\z/)
    end

    it 'returns the correct SHA256 digest of the code_verifier' do
      pkce = described_class.new(length: expected_code_verifier.length)
      allow(pkce).to receive(:code_verifier).and_return(expected_code_verifier)

      expect(pkce.code_challenge).to eq(expected_code_challenge)
    end
  end

  describe '#inspect' do
    it 'returns a string representation of the object' do
      expect(pkce.inspect).to eq("#<Pkce:#{pkce.object_id}>")
    end
  end
end
