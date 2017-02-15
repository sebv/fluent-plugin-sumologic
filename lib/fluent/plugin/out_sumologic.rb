# encoding: UTF-8
require 'net/http'
require 'date'

class Fluent::SumologicOutput< Fluent::BufferedOutput
  Fluent::Plugin.register_output('sumologic', self)

  config_param :host, :string,  :default => 'localhost'
  config_param :port, :integer, :default => 9200
  config_param :path, :string,  :default => '/'
  config_param :format, :string, :default => 'json'

  def initialize
    super
  end

  def configure(conf)
    super
  end

  def start
    super
  end

  def format(tag, time, record)
    [tag, time, record].to_msgpack
  end

  def shutdown
    super
  end

  def fix_encoding(crap_str)
    # Tries to figure out encoding so that conversion
    # to UTF-8 does not crash. If all fails removes
    # the bad characters.
    if crap_str.nil?
      return crap_str
    end

    begin
      return crap_str.encode(Encoding.find('UTF-8'))
    rescue
    end
    encodings = Array["ASCII-8BIT", "UTF-8", "ISO-8859-1", "ISO-8859-15"]
    orig_enc = crap_str.encoding
    encodings.each do |enc|
      begin
        res = crap_str.encode(Encoding.find('UTF-8'), Encoding.find(enc))
        crap_str.force_encoding(enc)
        log.debug("Fixed encoding from #{orig_enc} to #{enc} " +
                 "for #{crap_str}")
        return res
      rescue
      end
    end
  end

  def write(chunk)
    messages = []
    
    case @format
      when 'json'
        chunk.msgpack_each do |tag, time, record|
          json_record = nil
          begin
            json_record = record.to_json
          rescue
            # When a record is badly encoded, we try
            # to fix the mess.
            clean_record = Hash.new
            record.each do |k, v|
              clean_record[k] = self.fix_encoding(v)
            end
            json_record = clean_record.to_json
          end
          messages << json_record
        end
      when 'text'
        chunk.msgpack_each do |tag, time, record|
          messages << record['message']
        end
    end

    http = Net::HTTP.new(@host, @port.to_i)
    http.use_ssl = true
    http.verify_mode = OpenSSL::SSL::VERIFY_NONE
    http.set_debug_output $stderr

    request = Net::HTTP::Post.new(@path)
    request.body = messages.join("\n")
    http.request(request)
  end
end
