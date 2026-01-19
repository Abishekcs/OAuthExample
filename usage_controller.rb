require 'oauth2'
require 'securerandom'
require 'set'

class UsageController
  # helper_method :authenticated?

  def authenticated?
    session[:access_token].present? || session[:username].present? || ENV['DEBUG'].present?
  end

  def get_authenticated_client
    client = MediawikiApi::Client.new ENV['WIKIBASE_API_URL'] || 'https://www.wikidata.org/w/api.php'
    if session[:auth_type] == 'oauth' && session[:access_token].present?
      client.oauth_access_token(session[:access_token])
    elsif session[:auth_type] == 'credentials' && session[:username].present? && session[:password].present?
      client.log_in(session[:username], session[:password])
    end
    client
  end

  def welcome
    client = OAuth2::Client.new(ENV['OAUTH_CONSUMER_TOKEN'], 
                                ENV['OAUTH_CONSUMER_SECRET'], 
                                site: "https://meta.wikimedia.org/w/rest.php", 
                                authorize_url: 'oauth2/authorize', 
                                token_url: 'oauth2/access_token', 
                                logger: Logger.new('oauth2.log', 'weekly'))

    

    puts client.inspect


    # @oauth_url = client.auth_code.authorize_url(redirect_uri: '/wiki/Special:OAuth/verified')
    @oauth_url = client.auth_code.authorize_url(redirect_uri: 'http://localhost:3000/users/auth/mediawiki/callback')
    
    puts @oauth_url
  end

  def lexeme
    if authenticated?
      # Handle direct lexeme ID lookup first (doesn't require language selection)
      if params[:lid].present?
        @lexeme_id = params[:lid].strip
        @lexeme = get_lexeme(@lexeme_id)
        @lang = iso_code_by_lang_qid(@lexeme['language'])
        if @lang.nil?
          flash[:error] = t('usage.language_unsupported', lexeme_id: @lexeme_id)
          redirect_to '/'
          return
        end
        @lemma = @lexeme['lemmas'].first.last['value'] # TODO: support more complicated cases?
        usage_examples_raw = get_usage_examples(@lexeme, @lang)
        if usage_examples_raw == :no_enabled_sources
          # All configured sources for this language have been disabled in the session
          lang_qid = @lexeme['language']
          lang_label = get_label_for(lang_qid)
          flash[:error] = t('usage.no_enabled_sources_for_language', language: lang_label, default: "All sources for %{language} are disabled. Re-enable at least one source to proceed.")
          redirect_to '/'
          return
        elsif usage_examples_raw == :no_results
          # Sources are configured but returned no results for this lexeme
          @usage_examples = []
        elsif usage_examples_raw.nil?
          # No sources configured for this language
          lang_qid = @lexeme['language']
          lang_label = get_label_for(lang_qid)
          flash[:error] = t('usage.no_wikisource_for_language', lexeme_id: @lexeme_id, language: lang_label)
          redirect_to '/'
          return
        else
          @usage_examples = reject_unwanted_examples(usage_examples_raw)
        end
        @senses = @lexeme['senses']
        @forms = @lexeme['forms'] || []
        @lexical_category = get_label_for(@lexeme['lexicalCategory'])
        @enabled_sources = get_enabled_sources(@lang)
        @configured_sources = normalize_sources(@lang)
        @senses_with_examples = get_senses_with_examples(@lexeme)
      else
        # Handle language-based random lexeme selection
        @lang = params[:lang]
        # Store the language in session if provided, otherwise use stored language
        if @lang.present?
          session[:contribution_language] = @lang
        else
          @lang = session[:contribution_language]
        end

        # If still no language, redirect to welcome page
        if @lang.nil?
          flash[:error] = t('usage.please_select_language', default: 'Please select a contribution language first')
          redirect_to '/'
          return
        end
        @ignore_case = session[:ignore_case].nil? ? true : session[:ignore_case]
        @property_filter = session[:property_filter] || {}
        i = 0
        until @usage_examples.present? or i > 10 do # give up after 10 tries
          results = find_lexemes_missing_usage_examples(@lang, 100, @property_filter)
          lex = results.empty? ? nil : results[rand(results.count)] # Use rand(results.count) instead of rand(100) to avoid nil when fewer than 100 results
          unless lex.nil?
            @lexeme_id = lex[:lexemeId].to_s.split('/').last
            @lemma = lex[:lemma].to_s
            @lexeme = get_lexeme(@lexeme_id)
            usage_examples_raw = get_usage_examples(@lexeme, @lang)
            if usage_examples_raw == :no_enabled_sources
              # User has disabled all configured sources for this language
              lang_name = Rails.configuration.langs[@lang][:language_name_en]
              flash[:error] = t('usage.no_enabled_sources_for_language_generic', language: lang_name, default: "All sources for %{language} are disabled. Re-enable sources to continue.")
              redirect_to '/'
              return
            elsif usage_examples_raw == :no_results
              # Sources returned no results for this lexeme, try the next one
              i += 1
              next
            elsif usage_examples_raw.nil?
              # No sources configured for this language - this shouldn't normally happen
              # since languages.yml should only list languages with Wikisource
              lang_name = Rails.configuration.langs[@lang][:language_name_en]
              flash[:error] = t('usage.no_wikisource_for_language_generic', language: lang_name)
              redirect_to '/'
              return
            end
            @usage_examples = reject_unwanted_examples(usage_examples_raw)
            if @usage_examples.empty? # try again if we didn't find any good examples
              i += 1
              next
            end
            @senses = @lexeme['senses']
            @forms = @lexeme['forms'] || []
            @lexical_category = get_label_for(@lexeme['lexicalCategory'])
            @enabled_sources = get_enabled_sources(@lang)
            @configured_sources = normalize_sources(@lang)
            @senses_with_examples = get_senses_with_examples(@lexeme)
          else
            flash[:notice] = t('usage.no_more_lexemes')
            redirect_to '/'
            return
          end
          i += 1
        end
      end
    else
      flash[:error] = t('usage.must_login_first')
      redirect_to '/'
    end
  end

  # look up a lexeme by lemma string OR by Lexeme ID
  def lookup_lexeme
    if authenticated?
      if params[:q].present?
        lex = RestClient.get 'https://wikidata.org/w/api.php', {params: {action: 'wbsearchentities', search: params[:q], language: I18n.locale.to_s, format: 'json', type: 'lexeme'}}
        if JSON.parse(lex.body)['search'].present?
          lexeme = JSON.parse(lex.body)['search'][0]
          redirect_to '/usage/lexeme?lid='+lexeme['id']
        else
          flash[:error] = t('usage.no_lexeme_found')
          redirect_to '/'
        end
      elsif params[:lid].present?
        redirect_to '/usage/lexeme?lid='+params[:lid]
      else
        flash[:error] = t('usage.no_lexeme_found')
        redirect_to '/'
      end
    else
      flash[:error] = t('usage.must_login_first')
      redirect_to '/'
    end
  end

  def review

  end

  def submit_usage
    # TODO: handle new sense first
    #Rails.logger.info "Access token: #{session[:access_token]}"
    if authenticated?
      client = get_authenticated_client
      statement_id = params[:lexeme_id]+'$'+SecureRandom.uuid
      #statement_id = 'L123$'+SecureRandom.uuid # TODO: use real lexeme ID; L123 is the sandbox item, for development
      sense_id = params[:sense_id]
      if params[:new_sense_gloss].present?
        new_sense_id = create_new_sense(client, params[:lexeme_id], params[:new_sense_lang], params[:new_sense_gloss])
        if new_sense_id.present?
          sense_id = new_sense_id
        else
          # `create_new_sense` already sets flash[:error] on failure
          redirect_to '/usage/lexeme?lang='+params[:lang]
          return
        end
      end
      unless flash[:error].present? # skip adding usage example if we couldn't add the new sense
        # Build qualifiers hash
        qualifiers = {
          "P6072": [ { "snaktype": "value", "property": "P6072", "datavalue": {
            "value": { "entity-type": "sense", "id": sense_id }, "type": "wikibase-entityid" }, "datatype": "wikibase-sense" } ]
        }
        qualifiers_order = [ "P6072" ]

        # Add P5830 (subject lexeme form) qualifier if form_id is present
        if params[:form_id].present?
          qualifiers["P5830"] = [ { "snaktype": "value", "property": "P5830", "datavalue": {
            "value": { "entity-type": "form", "id": params[:form_id] }, "type": "wikibase-entityid" }, "datatype": "wikibase-form" } ]
          qualifiers_order << "P5830"
        end

        claim = { id: statement_id, type: "statement",
          "mainsnak": {
            "snaktype": "value", "property": "P5831", "datavalue": {
              "value": { "text": params[:example].strip, "language": params[:lang] },
              "type": "monolingualtext" },
              "datatype": "monolingualtext" },
            "qualifiers": qualifiers,
            "qualifiers-order": qualifiers_order, "rank": "normal",
            "references": [
              {
                "snaks": {
                  "P854": [
                    {
                      "snaktype": "value",
                      "property": "P854",
                      "datavalue": {
                        "value": iri_escape(params[:example_url]),
                        "type": "string"
                      },
                      "datatype": "url"
                    }
                  ],
                  "P813": [
                    {
                      "snaktype": "value",
                      "property": "P813",
                      "datavalue": {
                        "value": {
                          "time": Time.now.strftime("+%Y-%m-%dT00:00:00Z"),
                          "timezone": 0,
                          "before": 0,
                          "after": 0,
                          "precision": 11,
                          "calendarmodel": "http://www.wikidata.org/entity/Q1985727"
                        },
                        "type": "time"
                      },
                      "datatype": "time"
                    }
                  ]
                },
                "snaks-order": [
                  "P854",
                  "P813"
                ]
              }
            ]
          }.to_json
        begin
          res = client.action(:wbsetclaim, token_type: "csrf", 'claim' => claim)
          if res.status == 200
            flash[:notice] = flash[:notice] ? flash[:notice]+"\n" : ''
            flash[:notice] += "#{t('usage.example_added_successfully')} - <a href=\"https://wikidata.org/wiki/L:#{params[:lexeme_id]}\">#{params[:lexeme_id]}</a>"
          else
            flash[:error] = t('usage.error_adding_example', msg: res.body)
            redirect_to '/'
            return
          end
        rescue MediawikiApi::ApiError
          flash[:error] = t('usage.error_adding_example', msg: $!)
          invalidate_session # probably the OAuth token expired
          redirect_to '/'
          return
        end
      end
      # Redirect based on multi-example mode
      if params[:multi_example] == '1'
        # Stay on the same lexeme for multiple examples
        redirect_to "/usage/lexeme?lid=#{params[:lexeme_id]}&multi_example=1"
      else
        # Single example mode: move to next lexeme
        redirect_to '/usage/lexeme?lang='+params[:lang]
      end
    else
      flash[:error] = t('usage.must_login_first')
      redirect_to '/'
    end
  end

  protected

  def create_new_sense(client, lexeme_id, lang, gloss)
    data = {glosses: {}}
    data[:glosses][lang] = { "value": gloss, "language": lang}
    res = client.action(:wbladdsense, token_type: "csrf", lexemeId: lexeme_id, data: data.to_json)
    if res.status == 200
      flash[:notice] = t('usage.new_sense_added_successfully')
      return res.data['sense']['id']
    else
      flash[:error] = t('usage.error_adding_sense', msg: res.body)
      return nil
    end
  end

  def get_label_for(qid)
    z = RestClient.get 'https://wikidata.org/w/api.php', {params: {action: 'wbgetentities', ids: qid, format: 'json'}}
    labels = JSON.parse(z.body)['entities'][qid]['labels']
    lang = I18n.locale.to_s
    return labels[lang]['value'] if labels[lang].present? # try to return label in current locale
    return labels['en']['value'] if labels['en'].present?
    return labels.first[1]['value']
  end

  def iri_escape(s)
    s.gsub(' ','_').gsub('"','%22').gsub('[', '%5B').gsub(']','%5D')
  end

  def reject_unwanted_examples(examples)
    # remove examples that are too short or too long
    unless @ignore_case
      # Strip HTML tags from snippet before checking if it contains the lemma
      # This is necessary because Wikisource wraps search matches in <span> tags,
      # and multi-word lemmas get each word wrapped separately
      examples.select! do |e|
        snippet_text = e['snippet'].gsub(/<[^>]+>/, '')
        snippet_text.include?(@lemma)
      end
    end
    return examples
  end

  # Returns a set of sense IDs that already have usage examples
  def get_senses_with_examples(lexeme)
    sense_ids = Set.new
    return sense_ids unless lexeme['claims'] && lexeme['claims']['P5831']

    # P5831 is the property for usage examples
    lexeme['claims']['P5831'].each do |claim|
      # P6072 is the qualifier for "exemplifies" (which sense the example illustrates)
      if claim['qualifiers'] && claim['qualifiers']['P6072']
        claim['qualifiers']['P6072'].each do |qualifier|
          if qualifier['datavalue'] && qualifier['datavalue']['value']
            sense_id = qualifier['datavalue']['value']['id']
            sense_ids.add(sense_id)
          end
        end
      end
    end

    sense_ids
  end
end

oauth_client = UsageController.new

oauth_client.welcome
