# encoding: utf-8

require "logstash/devutils/rspec/spec_helper"
require_relative "../support/client"
require "logstash/inputs/netflow"
require "logstash/event"

# expose the udp socket so that we can assert, during
# a spec, that it is open and we can start sending data
 class LogStash::Inputs::Netflow
    attr_reader :udp
 end

describe LogStash::Inputs::Netflow do

  let(:json_events) do
    {
      :wlc => <<-WLC,
      {
        "@timestamp":"2015-05-29T16:51:58.000Z",
        "host":"10.10.10.10",
        "version":9,
        "flow_seq_num":702777,
        "flowset_id":259,
        "client_mac_addr":"98:f1:70:19:00:29",
        "client_ipv4_addr":"10.98.9.34",
        "app_id":"03:80",
        "app_name":"http",
        "wlan_ssid":"AC",
        "direction":0,
        "in_bytes":446,
        "in_pkts":2,
        "in_dscp":0,
        "out_dscp":0,
        "ap_mac_addr":"24:01:c7:ac:31:50",
        "@version":"1"
      }
      WLC
      :fnf => <<-FNF,
      {
        "@timestamp":"2015-06-11T15:57:10.000Z",
        "host":"10.10.10.10",
        "version":9,
        "flow_seq_num":7404748,
        "flowset_id":258,
        "ipv4_src_addr":"10.98.9.251",
        "ipv4_dst_addr":"17.253.48.247",
        "app_id":"03:123",
        "app_name":"ntp",
        "input_snmp":3,
        "l4_src_port":123,
        "l4_dst_port":123,
        "direction":1,
        "src_tos":0,
        "protocol":17,
        "is_multicast":0,
        "icmp_type":0,
        "icmp_code":0,
        "mul_igmp_type":0,
        "tcp_flags":0,
        "out_dscp":0,
        "tcp_winsize":0,
        "in_bytes":380,
        "in_pkts":5,
        "first_switched":"2015-06-11T15:56:47.999Z",
        "last_switched":"2015-06-11T15:56:55.999Z",
        "output_snmp":2,
        "ipv4_ident":38811,
        "duration":8,
        "@version":"1"
      }
      FNF
      :asa => <<-ASA,
      {
        "@timestamp":"2015-09-14T20:55:28.000Z",
        "host":"127.0.0.1",
        "version":9,
        "flow_seq_num":578,
        "flowset_id":256,
        "conn_id":28057252,
        "ipv4_src_addr":"10.98.10.50",
        "l4_src_port":16177,
        "input_snmp":16,
        "ipv4_dst_addr":"10.98.206.10",
        "l4_dst_port":0,
        "output_snmp":15,
        "protocol":1,
        "icmp_type":8,
        "icmp_code":0,
        "xlate_src_addr_ipv4":"10.98.10.50",
        "xlate_dst_addr_ipv4":"10.98.206.10",
        "xlate_src_port":16177,
        "xlate_dst_port":0,
        "fw_event":1,
        "fw_ext_event":0,
        "event_time_msec":1442264127945,
        "flow_create_time_msec":1442264127945,
        "ingress_acl_id":0,
        "egress_acl_id":4822082937111445504,
        "aaa_username":"",
        "@version":"1"
      }
      ASA
      :smth => "place for a event from smth"
    }
  end

  before {json_events.each { |k, v| json_events[k] = v.gsub(/\s+/, "") }}

  let(:dir_to_files) do
      File.dirname(__FILE__)
  end

  let(:clientip) do
    ["", "", "", "10.10.10.10"]
  end

  let(:port) { 9999 }

  subject(:netflow) do
    LogStash::Inputs::Netflow.new(
        "port" => port,
        "host" => "127.0.0.1",
        "exporters" => ["fnf" , "wlc", "asa"]).tap do |this|
          expect {this.register}.not_to raise_error
    end
  end

  after :each do
    netflow.close rescue nil
  end

  let(:decode) do
    [].tap do |events|
      data.each do |payload|
        netflow.decode(payload,clientip){|event| events << event}
      end
    end
  end

  context "when exporter is wlc" do

    let(:data) do
      [].tap do |data|
        data << IO.read(File.join(dir_to_files, "wlc_templates.dat"), :mode => "rb")
        data << IO.read(File.join(dir_to_files, "wlc_options.dat"), :mode => "rb")
        data << IO.read(File.join(dir_to_files, "wlc_flows.dat"), :mode => "rb")
      end
    end

    it "decodes wlc netflow" do
      expect(decode[4].to_json).to eq(json_events[:wlc])
    end
  end

  context "when exporter is fnf" do

    let(:data) do
      [].tap do |data|
        data << IO.read(File.join(dir_to_files, "fnf_templates.dat"), :mode => "rb")
        data << IO.read(File.join(dir_to_files, "fnf_options.dat"), :mode => "rb")
        data << IO.read(File.join(dir_to_files, "fnf_flows.dat"), :mode => "rb")
      end
    end

    it "decodes fnf netflow" do
      expect(decode[4].to_json).to eq(json_events[:fnf])
    end
  end

  subject(:client) { LogStash::Inputs::Test::UDPClient.new(port) }

  context "when exporter is asa" do

    let(:data) do
      [].tap do |data|
        data << IO.read(File.join(dir_to_files, "asa_templates1.dat"), :mode => "rb")
        data << IO.read(File.join(dir_to_files, "asa_templates2.dat"), :mode => "rb")
        data << IO.read(File.join(dir_to_files, "asa_flows.dat"), :mode => "rb")
      end
    end
    let(:send) do
      queue = Queue.new
      input_thread = Thread.new do
        netflow.run(queue)
      end
      puts "netflow start running"
      # because the udp socket is created and bound during #run
      # we must ensure that it is open before sending data
      sleep 2 until (netflow.udp && !netflow.udp.closed?)
      data.each do |payload|
          client.send(payload)
      end
      begin
        size = queue.size
        sleep 2
      end until size = queue.size
      netflow.do_stop
      queue.pop
    end
    it "decodes asa netflow" do
      expect(send.to_json).to eq(json_events[:asa])
    end
  end

  # it_behaves_like "an interruptible input plugin" do
  #   let(:config) { { "port" => port } }
  # end

end
