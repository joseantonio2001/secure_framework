require 'rails/generators/base'

module SecureFramework
  module Generators
    class InstallGenerator < Rails::Generators::Base
      source_root File.expand_path('templates', __dir__)

      # Orquesta la instalación y al final llama al resumen.
      def install_all_components
        run_component_installers
        print_final_summary
      end

      private

      def run_component_installers
        # 1. Configurar Gestión Segura de Secretos
        if secure_credentials_configured?
          say "Secure Credentials management is already configured. Skipping.", :green
        else
          say "Secure Credentials management not configured yet. Running setup...", :cyan
          install_secure_credentials
        end

        # 2. Configurar Devise si es necesario
        if devise_configured?
          say "Devise already configured. Skipping Devise setup.", :yellow
        else
          say "Devise not configured yet. Running Devise setup...", :cyan
          install_devise_and_configure
        end

        # 3. Configurar Pundit si es necesario
        if pundit_configured?
          say "Pundit already configured. Skipping Pundit setup.", :yellow
        else
          say "Pundit not configured yet. Running Pundit setup...", :cyan
          install_pundit
        end

        # 4. Configurar Sanitize si es necesario
        if sanitize_configured?
          say "Sanitize already configured. Skipping Sanitize setup.", :yellow
        else
          say "Sanitize not configured yet. Running Sanitize setup...", :cyan
          install_sanitize_and_configure
        end

        # 5. Configurar Content Security Policy (CSP) si es necesario
        if csp_configured?
          say "Content Security Policy appears to be actively configured. Skipping CSP setup.", :yellow
        else
          say "Default or unconfigured CSP detected. Applying secure policy...", :cyan
          install_csp_and_configure
        end

        # 6. Configurar Secure Headers si es necesario
        if secure_headers_configured?
          say "Secure Headers already configured. Skipping setup.", :yellow
        else
          say "Secure Headers not configured yet. Running setup...", :cyan
          install_secure_headers
        end
        
        # 7. Configurar Protección CSRF Reforzada si es necesario
        if csrf_protection_configured?
          say "CSRF protection already configured. Skipping setup.", :yellow
        else
          say "CSRF protection not configured yet. Running setup...", :cyan
          install_csrf_protection
        end
        
        # 8. Configurar Audit task si es necesario
        if dependency_audit_configured?
          say "Dependency Audit task is already configured. Skipping.", :green
        else
          say "Dependency Audit task not configured yet. Running setup...", :cyan
          install_dependency_audit
        end      

        # 9. Configurar Logging de Seguridad si es necesario
        if security_logging_configured?
          say "Security Logging already configured. Skipping setup.", :yellow
        else
          say "Security Logging not configured yet. Running setup...", :cyan
          install_security_logging
        end
      end      

      # MÉTODOS DE COMPROBACIÓN

      def devise_configured?
        File.exist?(File.join(destination_root, 'config/initializers/devise.rb'))
      end

      def pundit_configured?
        File.exist?(File.join(destination_root, 'app/policies/application_policy.rb'))
      end

      def sanitize_configured?
        File.exist?(File.join(destination_root, 'config/initializers/sanitize.rb'))
      end

      def csp_configured?
        initializer_path = File.join(destination_root, 'config/initializers/content_security_policy.rb')
        return false unless File.exist?(initializer_path)
        content = File.read(initializer_path)
        content.match?(/^\s*policy\./)
      end
      
      def secure_headers_configured?
        File.exist?(File.join(destination_root, 'config/initializers/secure_headers.rb'))
      end
      
      def csrf_protection_configured?
        controller_path = File.join(destination_root, 'app', 'controllers', 'application_controller.rb')
        return false unless File.exist?(controller_path)
        File.read(controller_path).match?(/protect_from_forgery/)
      end
      
      def secure_credentials_configured?
        master_key_exists = File.exist?(File.join(destination_root, 'config/master.key'))
        
        gitignore_path = File.join(destination_root, '.gitignore')
        master_key_is_ignored = File.exist?(gitignore_path) && File.read(gitignore_path).include?('/config/master.key')
    
        master_key_exists && master_key_is_ignored
      end
      
      def dependency_audit_configured?
        File.exist?(File.join(destination_root, 'lib/tasks/dependency_audit.rake'))
      end
      
      def security_logging_configured?
        lograge_exists = File.exist?(File.join(destination_root, 'config/initializers/lograge.rb'))
        security_logger_exists = File.exist?(File.join(destination_root, 'config/initializers/security_logging.rb'))
        lograge_exists && security_logger_exists
      end 

      # MÉTODOS DE INSTALACIÓN Y CONFIGURACIÓN (SÓLO SE EJECUTAN CUANDO ES NECESARIO)

      def install_secure_credentials

        @credentials_instructions_needed = true
    
        # Acción 1: Asegurar que master.key esté en .gitignore.
        gitignore_path = File.join(destination_root, '.gitignore')
        key_entry = '/config/master.key'
    
        # Crea .gitignore si no existe, para evitar errores.
        create_file(gitignore_path) unless File.exist?(gitignore_path)
    
        unless File.read(gitignore_path).include?(key_entry)
          say "Adding '#{key_entry}' to .gitignore...", :cyan
          append_to_file gitignore_path, "\n# Added by secure_framework to protect secrets\n#{key_entry}\n"
        end
      end       
      
      def install_devise_and_configure
        say "Setting up Devise with enhanced security defaults...", :cyan

        # 1. Instalar Devise
        generate "devise:install"
        
        # 2. Aplicar políticas de seguridad modificando el archivo devise.rb
        configure_password_policy
        configure_account_locking
        migrate_secret_to_credentials

        # 3. Crear el modelo de usuario y las rutas
        generate "devise", "User", "username:string"
        route "devise_for :users"
        
        # 4. Modificar el modelo de usuario y la migración
        prepare_user_model_for_locking
        prepare_migration_for_locking
      end

      def install_pundit
        say "Setting up Pundit for authorization...", :cyan
        generate "pundit:install"
        inject_into_class "app/controllers/application_controller.rb", ApplicationController do
          "  include Pundit::Authorization\n"
        end
      end
      
      def install_sanitize_and_configure
        say "Creating strict Sanitize initializer (strips all HTML tags)...", :green
        
        initializer_path = "config/initializers/sanitize.rb"
        
        create_file initializer_path, <<~RUBY
          # config/initializers/sanitize.rb
          #
          # Default configuration for the Sanitize gem, provided by secure_framework.
          # This is a strict configuration that strips all HTML tags to prevent formatting.
          # For more information on options: https://github.com/rgrove/sanitize

          Sanitize::Config::SECURE_FRAMEWORK = {
            # No HTML elements are allowed. The list is empty.
            :elements => [],

            # As an additional security measure, ensure the contents of these
            # tags are also removed, in case an external configuration allows them.
            :remove_contents => ['script', 'style']
          }
        RUBY
      end

      def install_csp_and_configure
        say "Applying secure Content Security Policy (CSP)...", :green
        initializer_path = "config/initializers/content_security_policy.rb"
        
        policy_definition = <<~RUBY
          # Be sure to restart your server when you modify this file.
          # This file was generated by the 'secure_framework' gem.

          # Define an application-wide content security policy.
          # For further information see the following documentation
          # https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy

          Rails.application.configure do
            config.content_security_policy do |policy|
              policy.default_src :self, :https
              policy.font_src    :self, :https, :data
              policy.img_src     :self, :https, :data
              policy.object_src  :none
              policy.script_src  :self, :https,
                                'sha256-DpVt+Ev/lTHBvE9AP6MusgWkuqGvLlkqNGv2dwHVOyE=',
                                'sha256-Bk2Ki1XPeMQgcV8U6q5OUXYdrX/47R4L1F0tatGpT7w='
              policy.style_src   :self, :https

              # Add policies for Vite in development, if the host app is using it.
              if Rails.env.development?
                # Allow @vite/client to hot reload style changes in development
                policy.style_src *policy.style_src, :unsafe_inline
                
                # Allow @vite/client to hot reload javascript changes in development,
                # but only if the ViteRuby gem is defined.
                if defined?(ViteRuby)
                  policy.script_src *policy.script_src, :unsafe_inline, "https://\#{ViteRuby.config.host_with_port}"
                end
              end

              # Specify URI for violation reports
              # policy.report_uri "/csp-violation-report-endpoint"
            end

            # Generate session nonces for permitted importmap and inline scripts
            config.content_security_policy_nonce_generator = ->(request) { request.session.id.to_s }
            config.content_security_policy_nonce_directives = %w(script-src)

            # Report CSP violations to a specified URI. See:
            # https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy-Report-Only
            # config.content_security_policy_report_only = true
          end
        RUBY

        remove_file(initializer_path) if File.exist?(initializer_path)
        create_file initializer_path, policy_definition
      end
      
      def install_secure_headers
        say "Creating secure_headers initializer with recommended defaults...", :green

        initializer_path = "config/initializers/secure_headers.rb"

        create_file initializer_path, <<~RUBY
          # Creado por secure_framework para centralizar la gestión de cabeceras de seguridad.

          SecureHeaders::Configuration.default do |config|
            # Previene que el sitio sea cargado en un frame o iframe (protección contra Clickjacking).
            config.x_frame_options = "SAMEORIGIN"

            # Evita que el navegador intente adivinar el tipo de contenido (MIME-type sniffing).
            config.x_content_type_options = "nosniff"

            # Activa el filtro XSS de los navegadores.
            config.x_xss_protection = "1; mode=block"

            # Previene que navegadores como IE abran descargas directamente en el contexto del sitio.
            config.x_download_options = "noopen"

            # Restringe el permiso de Adobe Flash/Reader para acceder a datos entre dominios.
            config.x_permitted_cross_domain_policies = "none"

            # Define una política más estricta sobre la información enviada en la cabecera Referer.
            config.referrer_policy = %w(origin-when-cross-origin strict-origin-when-cross-origin)

            # Desactivamos explícitamente la gestión de CSP en esta gema.
            # Esto previene cualquier conflicto con el inicializador nativo de Rails
            # (config/initializers/content_security_policy.rb) que es gestionado
            # por el método install_csp_and_configure del framework.
            config.csp = SecureHeaders::OPT_OUT

            # HTTP Strict Transport Security (HSTS)
            # Descomentar en producción para forzar conexiones HTTPS.
            # if Rails.env.production?
            #   config.strict_transport_security = "max-age=63072000; includeSubDomains"
            # end
          end
        RUBY
      end

      def install_csrf_protection
        say "Injecting reinforced CSRF protection (with: :exception)...", :green
        controller_path = "app/controllers/application_controller.rb"
        
        inject_into_file controller_path, after: "class ApplicationController < ActionController::Base\n" do
          "  protect_from_forgery with: :exception\n"
        end
      end

      def install_dependency_audit
        say "Creating dependency audit Rake task...", :green
        task_path = "lib/tasks/dependency_audit.rake"

        rake_task_content = <<-RAKE_TASK.strip_heredoc
          # frozen_string_literal: true
          # Task created by secure_framework to audit dependencies.

          require 'bundler/audit/database'
          require 'bundler/audit/scanner'

          namespace :dependency_audit do
            desc 'Scans dependencies for vulnerabilities'
            task check: :environment do
              puts "--> Updating vulnerability database..."
              Bundler::Audit::Database.update!(quiet: true)

              puts "--> Scanning Gemfile.lock for vulnerabilities..."
              scanner = Bundler::Audit::Scanner.new
              results = scanner.scan.to_a

              if results.any?
                puts "\\n[!] VULNERABILITIES FOUND\\n"
                results.each do |result|
                  if result.is_a?(Bundler::Audit::Scanner::UnpatchedGem)
                    puts "=============================================="
                    puts "  Gem:         \#{result.gem.name} (v\#{result.gem.version})"
                    puts "  Advisory:    \#{result.advisory.title}"
                    puts "  Criticality: \#{result.advisory.criticality&.to_s&.upcase || 'UNKNOWN'}"
                    puts "  URL:         \#{result.advisory.url}"
                    puts "  Solution:    Upgrade to version \#{result.advisory.patched_versions.join(', ')}"
                    puts "==============================================\\n"
                  end
                end
                # Abort with a non-zero exit code to fail CI builds
                abort("Action required: Insecure dependencies found.")
              else
                puts "\\n[+] SUCCESS: No known vulnerabilities found."
              end
            end
          end
        RAKE_TASK

        create_file task_path, rake_task_content
      end
      
      def install_security_logging
        say "Creating security logging initializers...", :green
        
        @security_logging_instructions_needed = true
        
        # Este inicializador de lograge es correcto y defensivo
        initializer "lograge.rb", <<~'RUBY'
          Rails.application.configure do
            if config.respond_to?(:lograge)
              config.lograge.enabled = true
              config.lograge.custom_options = lambda do |event|
                {
                  request_id: event.payload[:request_id],
                  remote_ip: event.payload[:remote_ip],
                  user_id: event.payload[:user_id]
                }
              end
            end
          end
        RUBY

        initializer "security_logging.rb", <<~'RUBY'
          
          security_log_path = Rails.root.join('log', 'security.log')
          SECURITY_LOGGER = ActiveSupport::Logger.new(security_log_path, 10, 1024 * 1024)
          SECURITY_LOGGER.formatter = proc do |severity, datetime, _progname, msg|
            "[#{datetime.strftime('%Y-%m-%d %H:%M:%S')}] #{severity}: #{msg}\n"
          end

          Warden::Manager.before_failure do |env, opts|
            request = ActionDispatch::Request.new(env)
            if opts[:action] == 'unauthenticated' && opts[:scope] == :user && request.params['user']
              log_message = {
                event: 'failed_login_attempt',
                email: request.params.dig('user', 'email'),
                ip_address: request.remote_ip,
                user_agent: request.user_agent,
                path: request.path,
                warden_message: opts[:message]
              }.to_json
              SECURITY_LOGGER.warn(log_message)
            end
          end
        RUBY
      end

      def configure_password_policy
        say "Applying secure password policy (12 characters minimum)...", :yellow
        gsub_file 'config/initializers/devise.rb',
                  /config\.password_length = 6\.\.128/,
                  'config.password_length = 12..128'
      end

      def configure_account_locking
        say "Enabling account locking by default...", :yellow
        # Descomentar y ajustar las opciones de bloqueo existentes
        gsub_file 'config/initializers/devise.rb', '# config.lock_strategy = :failed_attempts', 'config.lock_strategy = :failed_attempts'
        gsub_file 'config/initializers/devise.rb', '# config.unlock_strategy = :both', 'config.unlock_strategy = :time'
        gsub_file 'config/initializers/devise.rb', '# config.maximum_attempts = 20', 'config.maximum_attempts = 5'
        gsub_file 'config/initializers/devise.rb', '# config.unlock_in = 1.hour', 'config.unlock_in = 30.minutes'
      end

      def migrate_secret_to_credentials
        say "Configuring Devise to use credentials for secret_key...", :yellow
        inject_into_file 'config/initializers/devise.rb', 
                         "\n  # Load Devise secret key from encrypted credentials.\n" \
                         "  config.secret_key = Rails.application.credentials.dig(:devise, :secret_key)\n",
                         after: "Devise.setup do |config|"
        
        # Comentar la clave original si existe
        gsub_file 'config/initializers/devise.rb', /^\s*config\.secret_key = '.+'/, '# \0'
        
        @devise_secret_instruction_needed = true
      end
      
      def prepare_user_model_for_locking
        say "Adding :lockable module to User model...", :yellow
        gsub_file 'app/models/user.rb', 
                  /(:validatable)/, 
                  "\\1, :lockable"
      end
      
      def prepare_migration_for_locking
        say "Enabling lockable fields in the database migration...", :yellow
        migration_file = Dir.glob("db/migrate/*_devise_create_users.rb").first
        return unless migration_file

        gsub_file migration_file, /#\s*(t\.integer\s+:failed_attempts.*)/, '\1'
        gsub_file migration_file, /#\s*(t\.string\s+:unlock_token.*)/, '\1'
        gsub_file migration_file, /#\s*(t\.datetime\s+:locked_at.*)/, '\1'
        gsub_file migration_file, /#\s*(add_index :users, :unlock_token.*)/, '\1'
      end

      def print_final_summary
        say "\n'secure_framework' has finished processing!", :green
        
        next_steps = []
        credentials_task = nil
        
        if @devise_secret_instruction_needed
          credentials_task = "Run 'EDITOR=vim bin/rails credentials:edit' to set the 'secret_key' for Devise."
        elsif @credentials_instructions_needed
          credentials_task = "Run 'EDITOR=vim bin/rails credentials:edit' to manage your application secrets."
        end

        next_steps.unshift(credentials_task) if credentials_task

        if @devise_secret_instruction_needed
          next_steps << "Run 'rails db:migrate' to apply changes to the database."
          next_steps << "Protect your controllers with 'before_action :authenticate_user!'"
        end
        
        if @security_logging_instructions_needed
          # --- INSTRUCCIÓN DE LOGRAGE CORREGIDA ---
          next_steps << "Lograge has been enabled by default for all environments. If you wish to disable it for a specific environment (e.g., development), add this block to the corresponding file (e.g., 'config/environments/development.rb'):\n\n" \
                        "     if config.respond_to?(:lograge)\n" \
                        "       config.lograge.enabled = false\n" \
                        "     end\n"

          # --- INSTRUCCIÓN DE PUNDIT (SE MANTIENE IGUAL PORQUE ES CORRECTA) ---
          next_steps << "To log authorization failures (Pundit), a manual step is required. Add this block to 'app/controllers/application_controller.rb':\n\n" \
                        "     rescue_from Pundit::NotAuthorizedError, with: :user_not_authorized\n\n" \
                        "     private\n\n" \
                        "     def user_not_authorized(exception)\n" \
                        "       policy_name = exception.policy.class.to_s.underscore\n" \
                        "       log_message = {\n" \
                        "         event: 'authorization_failure',\n" \
                        "         user: current_user&.id,\n" \
                        "         policy: policy_name,\n" \
                        "         action: exception.query,\n" \
                        "         ip_address: request.remote_ip\n" \
                        "       }.to_json\n" \
                        "       SECURITY_LOGGER.error(log_message)\n" \
                        "       flash[:alert] = 'You are not authorized to perform this action.'\n" \
                        "       redirect_to(request.referrer || root_path)\n" \
                        "     end\n"
        end

        unless next_steps.empty?
          say "\nNext steps:", :cyan
          next_steps.each_with_index do |step, index|
            puts "\n  #{index + 1}. #{step}"
          end
        end
      end
    end
  end
end