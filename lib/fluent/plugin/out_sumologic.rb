# encoding: UTF-8
require 'net/http'
require 'date'

class Fluent::SumologicOutput< Fluent::BufferedOutput
  Fluent::Plugin.register_output('sumologic', self)

  config_param :host, :string,  :default => 'collectors.sumologic.com'
  config_param :port, :integer, :default => 443
  config_param :verify_ssl, :bool, :default => true
  config_param :path, :string,  :default => '/receiver/v1/http/XXX'
  config_param :format, :string, :default => 'json'
  config_param :source_name_key, :string, :default => ''

  include Fluent::SetTagKeyMixin
  config_set_default :include_tag_key, false

  include Fluent::SetTimeKeyMixin
  config_set_default :include_time_key, false

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
    messages_list = {}

    case @format
      when 'json'
        chunk.msgpack_each do |tag, time, record|
          if @include_tag_key
            record.merge!(@tag_key => tag)
          end
          if @include_time_key
            record.merge!(@time_key => @timef.format(time))
          end
          source_name = record[@source_name_key] || ''
          record.delete(@source_name_key)

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

          messages_list[source_name] = [] unless messages_list[source_name]
          messages_list[source_name] << json_record
        end
      when 'text'
        chunk.msgpack_each do |tag, time, record|
          source_name = record[@source_name_key] || ''
          messages_list[source_name] = [] unless messages_list[source_name]
          messages_list[source_name] << record['message']
        end
    end

    if ENV.has_key?("http_proxy")
      (proxy,proxy_port) = ENV['http_proxy'].split(':')
      http = Net::HTTP::Proxy(proxy,proxy_port).new(@host, @port.to_i)
    else
      http = Net::HTTP.new(@host, @port.to_i)
    end

    http.use_ssl = true
    http.verify_mode = @verify_ssl ? OpenSSL::SSL::VERIFY_PEER : OpenSSL::SSL::VERIFY_NONE
    http.set_debug_output $stderr

    messages_list.each do |source_name, messages|
      request = Net::HTTP::Post.new(@path)
      request['X-Sumo-Name'] = source_name unless source_name.empty?
      request.body = messages.join("\n")
      response = http.request(request)
      unless response.is_a?(Net::HTTPSuccess)
        raise "Failed to send data to #{@host}. #{response.code} #{response.message}"
      end
    end
  end
end
