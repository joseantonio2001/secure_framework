module SecureFramework
  module Generators
    class InstallGenerator < Rails::Generators::Base
      source_root File.expand_path('templates', __dir__)

      def install_devise
        say "Setting up Devise for secure authentication..."
        
        # Instalar Devise
        generate "devise:install"
        
        # Crear modelo User con campos básicos
        generate "devise", "User", "username:string"
        
        # Añadir ruta devise_for
        route "devise_for :users"
        
        # Copiar vistas para personalización
        generate "devise:views"
        
        # Mensaje final con instrucciones
        say "Devise has been successfully set up!", :green
        say "Next steps:", :blue
        say "1. Run 'rails db:migrate' to create the users table", :blue
        say "2. Add 'before_action :authenticate_user!' to controllers you want to protect", :blue
        say "3. Customize the views in app/views/devise as needed", :blue
      end
    end
  end
end