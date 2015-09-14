# encoding: utf-8
require "bindata"
require "ipaddr"

class IP4Addr < BinData::Primitive
  endian :big
  uint32 :storage

  def set(val)
    ip = IPAddr.new(val)
    if ! ip.ipv4?
      raise ArgumentError, "invalid IPv4 address '#{val}'"
    end
    self.storage = ip.to_i
  end

  def get
    IPAddr.new_ntoh([self.storage].pack('N')).to_s
  end

  def get_ip
    IPAddr.new_ntoh([self.storage].pack('N'))
  end
end

class IP6Addr < BinData::Primitive
  endian  :big
  uint128 :storage

  def set(val)
    ip = IPAddr.new(val)
    if ! ip.ipv6?
      raise ArgumentError, "invalid IPv6 address `#{val}'"
    end
    self.storage = ip.to_i
  end

  def get
    IPAddr.new_ntoh((0..7).map { |i|
      (self.storage >> (112 - 16 * i)) & 0xffff
    }.pack('n8')).to_s
  end
end

class MacAddr < BinData::Primitive
  array :bytes, :type => :uint8, :initial_length => 6

  def set(val)
    ints = val.split(/:/).collect { |int| int.to_i(16) }
    self.bytes = ints
  end

  def get
    self.bytes.collect { |byte| byte.value.to_s(16).rjust(2,'0') }.join(":")
  end
end

class Header < BinData::Record
  endian :big
  uint16 :version
end

class TemplateFlowset < BinData::Record
  endian :big
  array  :templates, :read_until => lambda { array.num_bytes == flowset_length - 4 } do
    uint16 :template_id
    uint16 :field_count
    array  :fields, :initial_length => :field_count do
      uint16 :field_type
      uint16 :field_length
    end
  end
end

class OptionFlowset < BinData::Record
  endian :big
  array  :templates, :read_until => lambda { flowset_length - 4 - array.num_bytes <= 2 } do
    uint16 :template_id
    uint16 :scope_length
    uint16 :option_length
    array  :scope_fields, :initial_length => lambda { scope_length / 4 } do
      uint16 :field_type
      uint16 :field_length
    end
    array  :option_fields, :initial_length => lambda { option_length / 4 } do
      uint16 :field_type
      uint16 :field_length
    end
  end
  skip :padding, :length => lambda { nbytes = flowset_length - 4; templates.each { |t| nbytes -= 6 + t.scope_length + t.option_length}; nbytes }
end

class Netflow9PDU < BinData::Record
  endian :big
  uint16 :version
  uint16 :flow_records
  uint32 :uptime
  uint32 :unix_sec
  uint32 :flow_seq_num
  uint32 :source_id
  array  :records, :read_until => :eof do
    uint16 :flowset_id
    uint16 :flowset_length
    choice :flowset_data, :selection => :flowset_id do
      template_flowset 0
      option_flowset   1
      string           :default, :read_length => lambda { flowset_length - 4 }
    end
  end
end

