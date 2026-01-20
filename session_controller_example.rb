require 'mediawiki_api'

class SessionsController < ApplicationController
  def new
    render :new
  end

  def create
    if params[:code].present? # got initial OAuth2 authorization code, can proceed to request user access token
      begin
        client = OAuth2::Client.new(ENV['OAUTH_CONSUMER_TOKEN'], ENV['OAUTH_CONSUMER_SECRET'], site: "https://meta.wikimedia.org/w/rest.php", authorize_url: 'oauth2/authorize', token_url: 'oauth2/access_token' , logger: Logger.new('oauth2.log', 'weekly'))
        @access_token = client.auth_code.get_token(params[:code], redirect_uri: ENV['OAUTH_CALLBACK_URL'], client_id: ENV['OAUTH_CONSUMER_TOKEN'], client_secret: ENV['OAUTH_CONSUMER_SECRET'] )
        @got_token = true
        reset_session
        session[:access_token] = @access_token.token
        session[:auth_type] = 'oauth'
        flash[:notice] = t(:oauth_success)
        #Rails.logger.info "Got access token: #{@access_token.token}"
      rescue
        @got_token = false
        Rails.logger.error "Failed to get access token: #{$!}"
        flash[:error] = t(:oauth_failed, msg: $!)
      end
    else
      Rails.logger.error "No authorization code received"
      flash[:error] = t(:bad_login)
    end
    redirect_to '/'
  end

  def credentials_login
    if params[:username].present? && params[:password].present?
      begin
        client = MediawikiApi::Client.new ENV['WIKIBASE_API_URL'] || 'https://www.wikidata.org/w/api.php'
        client.log_in(params[:username], params[:password])

        reset_session
        session[:username] = params[:username]
        session[:password] = params[:password]
        session[:auth_type] = 'credentials'
        flash[:notice] = t(:login_success)
      rescue MediawikiApi::ApiError => e
        Rails.logger.error "Failed to log in with credentials: #{e.message}"
        flash[:error] = t(:login_failed, msg: e.message)
      rescue => e
        Rails.logger.error "Failed to log in with credentials: #{e.message}"
        flash[:error] = t(:login_failed, msg: e.message)
      end
    else
      flash[:error] = t(:missing_credentials)
    end
    redirect_to '/'
  end

  def destroy
    reset_session
    flash[:notice] = t(:logout_success)
    redirect_to '/'
  end
end
