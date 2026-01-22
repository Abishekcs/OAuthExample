# frozen_string_literal: true

require 'oauth2'
require_dependency "#{Rails.root}/lib/importers/user_importer"

class Auth::Oauth2Controller < ApplicationController
  before_action :require_no_authentication, only: [:mediawiki, :mediawiki_signup]
  skip_before_action :check_for_expired_oauth_credentials, only: [:callback]

  def mediawiki
    start_oauth_flow(signup: false)
  end

  def mediawiki_signup
    start_oauth_flow(signup: true)
  end

  def callback
    if params[:code].present?
      begin
        client = OAuth2::Client.new(ENV['OAUTH_CONSUMER_TOKEN'],
                                    ENV['OAUTH_CONSUMER_SECRET'],
                                    site: "https://meta.wikimedia.org/w/rest.php",
                                    authorize_url: 'oauth2/authorize',
                                    token_url: 'oauth2/access_token',
                                    logger: Logger.new('oauth2.log', 'weekly'))

        @access_token = client.auth_code.get_token(params[:code],
                                                   redirect_uri: ENV['OAUTH_CALLBACK_URL'],
                                                   client_id: ENV['OAUTH_CONSUMER_TOKEN'],
                                                   client_secret: ENV['OAUTH_CONSUMER_SECRET'])

        user_info = get_user_details(@access_token)

        Rails.logger.info "Got User Details: #{user_info}"

        reset_session

        session[:access_token] = @access_token.token
        session[:refresh_token] = @access_token.refresh_token
        session[:token_expires_at] = @access_token.expires_at
        session[:auth_type] = 'oauth'

        Rails.logger.info "Got access token: #{@access_token.token}"
        Rails.logger.info "Token expires at: #{Time.at(@access_token.expires_at)}" if @access_token.expires_at
        Rails.logger.info "Refresh token: #{@access_token.refresh_token.present? ? 'Present' : 'Not present'}"

        auth_hash = build_auth_hash(@access_token, user_info, '')

        Rails.logger.info "Hash Structure #{auth_hash}"

        @user = UserImporter.from_omniauth(auth_hash)

        sign_in_and_redirect @user

      rescue
        @got_token = false
        Rails.logger.error "Failed to get access token: #{$!}"
      end
    else
      Rails.logger.error "No authorization code received"
    end
 # Method to refresh the access token
  def refresh_access_token
    return nil unless session[:refresh_token].present?

    begin
      client = OAuth2::Client.new(ENV['OAUTH_CONSUMER_TOKEN'],
                                  ENV['OAUTH_CONSUMER_SECRET'],
                                  site: "https://meta.wikimedia.org/w/rest.php",
                                  authorize_url: 'oauth2/authorize',
                                  token_url: 'oauth2/access_token')

      # Create a token object from the stored refresh token
      old_token = OAuth2::AccessToken.new(client, session[:access_token], {
                                          refresh_token: session[:refresh_token],
                                          expires_at: session[:token_expires_at]})

      # Refresh the token
      new_token = old_token.refresh!

      # Update session with new tokens
      session[:access_token] = new_token.token
      session[:refresh_token] = new_token.refresh_token if new_token.refresh_token
      session[:token_expires_at] = new_token.expires_at

      Rails.logger.info "Token refreshed successfully"
      Rails.logger.info "New token expires at: #{Time.at(new_token.expires_at)}" if new_token.expires_at

      new_token

      rescue OAuth2::Error => e
        Rails.logger.error "Failed to refresh token: #{e.message}"
        # Clear invalid tokens
        reset_session
        nil
    end
  
    #   #################################
    #   auth_hash = handle_oauth_callback
    #
    #   if auth_hash
    #     user = UserImporter.from_oauth2(auth_hash)
    #     sign_in_and_redirect(user, event: :authentication)
    #     set_flash_message!(:notice, :success, kind: 'MediaWiki')
    #   else
    #     flash[:alert] = 'Authentication failed'
    #     redirect_to root_path
    #   end
    # rescue OAuth2::Error => e
    #   Rails.logger.error "OAuth2 Error: #{e.message}"
    #   flash[:alert] = 'Authentication error occurred'
    #   redirect_to root_path
    #   #####################
  end

  def get_user_details(access_token)
    # Option 1: Using MediaWiki Action API
    response = access_token.get('https://meta.wikimedia.org/w/api.php',
                                params: {
                                action: 'query',
                                meta: 'userinfo',
                                uiprop: 'email|realname|groups',
                                format: 'json' })

    data = JSON.parse(response.body)
    user_data = data.dig('query', 'userinfo')

    {
      id: user_data['id'],
      username: user_data['name'],
      email: user_data['email'],
      realname: user_data['realname'],
      groups: user_data['groups']
    }

    rescue => e
      Rails.logger.error "Failed to fetch user details: #{e.message}"
    nil
  end

  private

  def start_oauth_flow(signup:)
    client = OAuth2::Client.new(ENV['OAUTH_CONSUMER_TOKEN'], ENV['OAUTH_CONSUMER_SECRET'], site: "https://meta.wikimedia.org/w/rest.php", authorize_url: 'oauth2/authorize', token_url: 'oauth2/access_token' , logger: Logger.new('oauth2.log', 'weekly'))
    @oauth_url = client.auth_code.authorize_url(redirect_uri: ENV['OAUTH_CALLBACK_URL'])
    puts @oauth_url

    # #############################
    # return unless oauth2_enabled?
    #
    # client = MediaWikiOAuth2Client.new
    # callback_url = auth_mediawiki_oauth2_callback_url
    #
    # # Store state in session for CSRF protection
    # state = SecureRandom.hex(16)
    # session['oauth_state'] = state
    # session['oauth_signup'] = signup
    #
    # auth_url = client.authorization_url(callback_url, state: state, signup: signup)
    # redirect_to auth_url
    # ####################
  end

  def handle_oauth_callback
    return nil unless oauth2_enabled?

    # Verify state for CSRF protection
    return nil unless params[:state] == session.delete('oauth_state')

    client = MediaWikiOAuth2Client.new
    callback_url = auth_mediawiki_oauth2_callback_url

    access_token = client.get_access_token(params[:code], callback_url)
    return nil unless access_token

    # Get user info from MediaWiki API
    user_info = client.user_info(access_token.token)
    identity = client.identify_user(access_token.token)

    return nil unless user_info && identity

    # Build auth hash similar to OmniAuth format for compatibility
    build_auth_hash(access_token, user_info, identity)
  end

  def build_auth_hash(access_token, user_info, identity)
    Rails.logger.info  "I am getting userinfo #{user_info}"
    userinfo = user_info

    # return nil unless userinfo

    {
      'provider' => 'mediawiki_oauth2',
      'uid' => userinfo[:id],
      'info' => {
        'name' => userinfo[:username],
        'email' => userinfo[:email]
      },
      'credentials' => {
        'token' => access_token.token,
        'refresh_token' => access_token.refresh_token,
        'expires_at' => access_token.expires_at,
        'expires' => access_token.expires?
      }
      # 'extra' => {
      #   'raw_info' => userinfo,
      #   'identity' => identity
      # },
      # 'signup' => session.delete('oauth_signup') || false
    }
  end

  def oauth2_enabled?
    # Feature flag - can be controlled via environment variable or Rails credentials
    ENV['ENABLE_OAUTH2'] == 'true' || Rails.application.credentials.oauth2_enabled
  end

  def require_no_authentication
    return unless user_signed_in?
    redirect_to root_path, alert: 'You are already signed in'
  end
end
