require "spec_helper"

describe Akamai::AuthToken do
  describe "#generate_token" do
    context "encryption key" do
      it "will raise AuthTokenError if no key is provided" do
        expect{
          Akamai::AuthToken.generate_token()
        }.to raise_error(Akamai::AuthTokenError, "You must provide a secret in order to generate a new token.")
      end
    end

    context "start time" do
      it "will raise AuthTokenError if start_time is string other than 'now'" do
        expect{
          Akamai::AuthToken.generate_token(key: "asdf1234",
                                          start_time: 'future')
        }.to raise_error(Akamai::AuthTokenError, "start_time must be UNIX timestamps or now")
      end
    end

    context "end time and window seconds" do
      it "will raise AuthTokenError if end_time is a string" do
        expect{
          Akamai::AuthToken.generate_token(key: "asdf1234",
                                           end_time: 'future')
        }.to raise_error(Akamai::AuthTokenError, "end_time must be UNIX timestamps")
      end

      it "will raise AuthTokenError if end_time or windows_seconds is not provided" do
        expect{
          Akamai::AuthToken.generate_token(key: "asdf1234")
        }.to raise_error(Akamai::AuthTokenError, "You must provide an expiration time or a duration window..")
      end

      it "will raise AuthTokenError if window_seconds is a string" do
        expect{
          Akamai::AuthToken.generate_token(key: "asdf1234",
                                           window_seconds: 'future')
        }.to raise_error(Akamai::AuthTokenError, "window_seconds must be numeric")
      end
    end

    context "start time end time calculation" do
      let(:time_now) { Time.now }
      let(:time_before) { time_now - 50 }

      it "calculate expiration date from window_second" do
        auth_token = Akamai::AuthToken.generate_token(key: "asdf1234",
                                                      window_seconds: 60,
                                                      acl: "/plox/*")

        expiration_time = auth_token.split("~")[1]

        expect(expiration_time).to eq "exp=#{time_now.getgm.to_i + 60}"
      end

      it "will raise AuthTokenError if end_time is less than start_time" do

        expect{
          Akamai::AuthToken.generate_token(key: "asdf1234",
                                           start_time: time_now.getgm.to_i,
                                           end_time: time_before.getgm.to_i)
        }.to raise_error(Akamai::AuthTokenError, "Token will have already expired.")
      end
    end

    context "url or acl policy" do
      it "will raise AuthTokenError if no acl or url provided" do

        expect{
          Akamai::AuthToken.generate_token(key: "asdf1234",
                                           window_seconds: 10)
        }.to raise_error(Akamai::AuthTokenError, "You must provide a URL or an ACL")
      end

      it "will raise AuthTokenError if both acl and url provided" do

        expect{
          Akamai::AuthToken.generate_token(key: "asdf1234",
                                           acl: "/i/*",
                                           url: "/live/playlist.m3u8",
                                           window_seconds: 30)
        }.to raise_error(Akamai::AuthTokenError, "You must provide a URL or an ACL")
      end
    end

    context "output" do
      let(:timestamp_now) { Time.new(2015, 12, 12, 0, 0).to_i }

      it "return short token" do
        auth_token = Akamai::AuthToken.generate_token(key: "asdf1234",
                                                      start_time: timestamp_now,
                                                      window_seconds: 60,
                                                      acl: "/live/*")

        expect(auth_token).to eq "hdnts=st=1449853200~exp=1449853260~acl=/live/*~hmac=1b627fa0195823e738ff2b54fef06571e5f604e04c82f6718aa42ba5a0d00e87"
      end

    end
  end

  describe "#escape_early" do
    it "will escape token string" do
      auth_token = Akamai::AuthToken.escape_early("&hdnts=asdf")

      expect(auth_token).to eq "%26hdnts%3dasdf"
    end
  end
end
