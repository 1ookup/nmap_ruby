 module NmapRuby
  module FileUtils
    def self.find_full_path(file_name)
      if (file_name[0,1] == "/" and ::File.exists?(file_name) and ::File::Stat.new(file_name))
        return file_name
      end
      # only linux
      path = ENV['PATH']

      if (path)
        path.split(::File::PATH_SEPARATOR).each { |base|
          begin
            base = $1 if base =~ /^"(.*)"$/
            path = base + ::File::SEPARATOR + file_name
            if (::File::Stat.new(path) and not ::File.directory?(path))
              return path
            end
          rescue
          end
        }
      end
      return nil
    end
  end
end