# encoding: utf-8
require "logstash/inputs/base"
require "logstash/namespace"
require "logstash/timestamp"
require "date"
require "thread"
require "yaml"


# The input logstash plugin is for decoding Netflow v9 flows.
class LogStash::Inputs::Netflow < LogStash::Inputs::Base
  config_name "netflow"

  # If undefined, Logstash will complain, even if codec is unused.
  default :codec, "plain"

  # The address which logstash will listen on.
  config :host, :validate => :string, :default => "0.0.0.0"

  # The port which logstash will listen on. Remember that ports less
  # than 1024 (privileged ports) may require root or elevated privileges to use.
  config :port, :validate => :number, :required => true

  # The maximum packet size to read from the network
  config :buffer_size, :validate => :number, :default => 8192

  # Number of threads processing packets
  config :workers, :validate => :number, :default => 2

  # This is the number of unprocessed UDP packets you can hold in memory
  # before packets will start dropping.
  config :queue_size, :validate => :number, :default => 2000

  # Specify into what field you want the Netflow data.
  config :target, :validate => :string, :default => "netflow"

  # Specify kind of exporters you will use.
  config :exporters, :validate => :array, :default => ["fnf"]

  # Override YAML file containing Netflow field definitions
  #
  # Each Netflow field is defined like so:
  #
  #    ---
  #    id:
  #    - default length in bytes
  #    - :name
  #    id:
  #    - :ip4_addr or :ip6_addr or :mac_addr or :string
  #    - :name
  #    id:
  #    - :skip
  #
  config :definitions, :validate => :path

  public
  def initialize(params)
    super
    BasicSocket.do_not_reverse_lookup = true
  end # def initialize

  #attr_reader :templates, :options_data

  public
  def register
    require "logstash/inputs/netflow/util"

    @fields = {}
    # Load to default Flexible Netflow v9 field definitions
    load_definitions(@fields, "netflow/netflow.yaml")
    # Load additional field definitions for Cisco ASA
    load_definitions(@fields, "netflow/netflow_asa.yaml") if @exporters.include?("asa")
    # Load additional field definitions for Cisco WLC
    load_definitions(@fields, "netflow/netflow_wlc.yaml") if @exporters.include?("wlc")

    @scope_fields = {}
    # Load to default Netflow v9 scope field definitions
    load_definitions(@scope_fields, "netflow/netflow_scope.yaml")

   # Allow the user to augment/override/rename the supported Netflow fields
    if @definitions
      raise "#{self.class.name}: definitions file #{@definitions} does not exists" unless File.exists?(@definitions)
      load_definitions(@fields, @definitions)
    end

    # Caches and mutexes for templates
    @templates = Hash.new
    @options_data = Hash.new
    @options_data[:app_names] = Hash.new
    @options_mutex = Mutex.new

  end # def register

  private
  def load_definitions(fields, file_name)
    # Path to definitions file
    filename = ::File.expand_path(file_name, ::File.dirname(__FILE__))
    begin
      fields.merge!(YAML.load_file(filename))
    rescue Exception => e
      raise "#{self.class.name}: Bad syntax in definitions file #{filename}. Exception Message: #{e.to_s}"
    end
  end # def load_definitions


  public
  def run(queue)
  @output_queue = queue
  @udp = nil
    begin
      # start UDP listener
      udp_listener()
    rescue LogStash::ShutdownSignal
      # do nothing, shutdown was requested.
    rescue => e
      @logger.warn("UDP listener died", :exception => e, :backtrace => e.backtrace)
      sleep(5)
      retry
    end # begin
  end # def run

  private
  def udp_listener()
    @logger.info("Starting UDP listener", :address => "#{@host}:#{@port}")

    if @udp && ! @udp.closed?
      @udp.close
    end

    @udp = UDPSocket.new(Socket::AF_INET)
    @udp.bind(@host, @port)

    @input_to_worker = SizedQueue.new(@queue_size)

    @input_workers = @workers.times do |i|
        @logger.debug("Starting UDP worker thread", :worker => i)
      Thread.new { inputworker(i) }
    end

    loop do
      #collect datagram message and add to queue
      payload, client = @udp.recvfrom(@buffer_size)
      @input_to_worker.push([payload,client])
      if (@input_to_worker.size > @queue_size -1)
          @logger.warn("UDP listener queue is full. Next packets will be dropped.")
      end
    end
  ensure
    if @udp
      @udp.close_read rescue nil
      @udp.close_write rescue nil
    end
  end # def udp_listener

  private
  def inputworker(number)
    LogStash::Util::set_thread_name("<netflow.udp.#{number}")
    begin
      while true
        payload,client = @input_to_worker.pop

        decode(payload, client) do |event|
          decorate(event)
          @output_queue.push(event)
        end
      end
    rescue => e
      @logger.error("Exception in inputworker", "exception" => e, "backtrace" => e.backtrace)
    end
  end # def inputworker

  public
  def teardown
    @udp.close if @udp && !@udp.closed?
  end


  public
  def decode(payload, client, &block)
    header = Header.read(payload)

    if header.version == 9
       flowset = Netflow9PDU.read(payload)
       flowset.records.each do |record|
          decode_v9(client[3], flowset, record).each{|event| yield(event)}
       end
    else
      @logger.warn("Unsupported Netflow version v#{header.version}")
      return
    end
  end

  private
  def decode_v9(host, flowset, record)
    events = []
    case record.flowset_id
    when 0
      # Template flowset
      record.flowset_data.templates.each do |template|
        catch (:field) do
          fields = []
          template.fields.each do |field|
            entry = netflow_field_for(field.field_type, field.field_length)
            if ! entry
              @logger.debug("Throw exception fields", :field_type => field.field_type)
              throw :field
            end
            fields += entry
          end
          # We get this far, we have a list of fields
          key = "#{host}|#{flowset.source_id}|#{template.template_id}"
          @templates[key] = BinData::Struct.new(:endian => :big, :fields => fields)
          @logger.debug? and @logger.debug("Key for template", :key => key, :template => @templates[key].to_s)
        end
      end
    when 1
      # Options template flowset
      record.flowset_data.templates.each do |template|
        catch (:field) do
          fields = []
          template.scope_fields.each do |field|
            entry = netflow_field_for(field.field_type, field.field_length, true)
            if ! entry
              @logger.debug("Throw exception scope_fields", :field_type => field.field_type)
              throw :field
            end
            fields += entry
          end
          template.option_fields.each do |field|
            entry = netflow_field_for(field.field_type, field.field_length)
            if ! entry
              @logger.debug("Throw exception option_fields", :field_type => field.field_type)
              throw :field
            end
            fields += entry
          end
          # We get this far, we have a list of fields
          key = "#{host}|#{flowset.source_id}|#{template.template_id}"
          @templates[key] = BinData::Struct.new(:endian => :big, :fields => fields)
          @logger.debug? and @logger.debug("Key for template", :key => key, :template => @templates[key].to_s)
        end
      end
    when 256..65535
      # Data flowset
      key = "#{host}|#{flowset.source_id}|#{record.flowset_id}"
      @logger.debug("Key for template", :key => key)
      template = @templates[key]

      unless template
        @logger.warn("No matching template for key #{key}")
        next
      end

      length = record.flowset_length - 4

      # Template shouldn't be longer than the record and there should
      # be at most 3 padding bytes
      if template.num_bytes > length or ! (length % template.num_bytes).between?(0, 100)
        @logger.warn("Template length doesn't fit cleanly into flowset", :template_id => record.flowset_id, :template_length => template.num_bytes, :record_length => length)
      next
      end

      array = BinData::Array.new(:type => template, :initial_length => length / template.num_bytes)

      records = array.read(record.flowset_data)
      records.each do |r|

        # if this is a flow record of option application-table
        if template.field_names[0].to_s.start_with?("scope_") and template.field_names[1]==:app_id
          app_id = r[:app_id].snapshot
          @options_mutex.synchronize do
            app_rec = @options_data[:app_names][app_id] ||= {}
            [:app_name,:app_desc,:app_category,:app_category_sub,:app_group,:is_p2p,:is_tunnel,:is_encrypted].each do |f|
              if r.has_key?(f)
                  app_rec[f] = r[f].snapshot
              end
            end #each
          end # mutex.syncronize
        #
        else
          event = {
            LogStash::Event::TIMESTAMP => LogStash::Timestamp.at(flowset.unix_sec),
            @target => {}
          }

          event["host"] = host

          # Fewer fields in the v9 header
          ['version', 'flow_seq_num'].each do |f|
            event[f] = flowset[f].snapshot
          end

          event['flowset_id'] = record.flowset_id.snapshot

          r.each_pair do |k,v|
            ks = k.to_s
            vs = v.snapshot
            case ks
            when /^ipv4_(src|dst)_addr$/
              event[ks] = vs
            when /^l4_(src|dst)_port$/
              event[ks] = vs
            when /^(in_bytes|in_pkts)$/
              event[ks] = vs
            when /^(protocol|direction)$/
              event[ks] = vs
            when /_switched$/
              millis = flowset.uptime - v
              seconds = flowset.unix_sec - (millis / 1000)
              # v9 did away with the nanosecs field
              micros = 1000000 - (millis % 1000)
              #event[@target][ks] = Time.at(seconds, micros).utc.strftime("%Y-%m-%dT%H:%M:%S.%3NZ")
              event[@target][ks] = LogStash::Timestamp.at(seconds, micros).to_iso8601
            when /^app_id$/
              # add details from applications table
              app_rec = nil
              @options_mutex.synchronize { app_rec = @options_data[:app_names][vs] }
              if app_rec
                app_name = app_rec[:app_name]
                [:app_category,:app_category_sub,:app_group,:is_p2p,:is_tunnel,:is_encrypted].each do |f|
                  if app_rec.has_key?(f)
                    event[@target][f.to_s] = app_rec[f]
                  end
                end #each
              end
              app_id = vs.divmod(16777216)
              event[@target]["app_id"] = app_id[0].to_s.rjust(2,'0') +':'+ app_id[1].to_s
              event[@target]["app_name"] = app_name ||= "undefined"
            else
              event[@target][ks] = vs
            end
          end
          # calc in_bytes_dir
          if event.has_key?("in_bytes") and event.has_key?("direction")
            event["in_bytes_dir"] = event["direction"]==0 ? event["in_bytes"] : -event["in_bytes"]
          end
          # calc duration
          if event[@target].has_key?("first_switched") and event[@target].has_key?("last_switched")
            event[@target]["duration"] = DateTime.strptime(event[@target]["last_switched"], '%Y-%m-%dT%H:%M:%S.%L').to_time.to_i - DateTime.strptime(event[@target]['first_switched'], '%Y-%m-%dT%H:%M:%S.%L').to_time.to_i
          end
          events << LogStash::Event.new(event)
        end
      end # records
    else
      @logger.warn("Unsupported flowset id #{record.flowset_id}")
    end
    events
  end # def decode

  private
  def uint_field(length, default)
    # If length is 4, return :uint32, etc. and use default if length is 0
    ("uint" + (((length > 0) ? length : default) * 8).to_s).to_sym
  end # def uint_field

  private
  def netflow_field_for(type, length, scope =false)
    @logger.debug("Field definition ", :field_type => type, :field_length => length, :field_scope => scope, :fields_include => @fields.include?(type), :scope_fields_include => @scope_fields.include?(type))
    if (!scope && @fields.include?(type)) || (scope && @scope_fields.include?(type))
      field = []
      (scope ? @scope_fields[type] : @fields[type]).each {|e| field << e}

      if field[0].is_a?(Integer)
        field[0] = uint_field(length, field[0])
      else
        # Small bit of fixup for skip or string field types where the length
        # is dynamic
        case field[0]
        when :skip
          field += [nil, {:length => length}]
        when :string
          field += [{:length => length, :trim_padding => true}]
        end
      end

      @logger.debug("Definition complete", :field => field)
      [field]
    else
      @logger.warn("Unsupported field", :type => type, :length => length, :scope => scope)
      nil
    end
  end # def netflow_field_for
end # class LogStash::Inputs::Netflow
