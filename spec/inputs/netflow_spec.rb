# encoding: utf-8

require "logstash/devutils/rspec/spec_helper"
require "logstash/inputs/netflow"
require "logstash/event"


describe LogStash::Inputs::Netflow do

  let(:json_events) do
    {
      :wlc => <<-WLC,
      {
        "@timestamp":"2015-05-29T16:51:58.000Z",
        "netflow": {
          "client_mac_addr":"98:f1:70:19:00:29",
          "client_ipv4_addr":"10.98.9.34",
          "app_id":"03:80",
          "app_name":"http",
          "wlan_ssid":"AC",
          "in_dscp":0,
          "out_dscp":0,
          "ap_mac_addr":"24:01:c7:ac:31:50"
          },
        "host":"10.10.10.10",
        "version":9,
        "flow_seq_num":702777,
        "flowset_id":259,
        "direction":0,
        "in_bytes":446,
        "in_pkts":2,
        "in_bytes_dir":446,
        "@version":"1"
      }
      WLC
      :fnf => <<-FNF,
      {
        "@timestamp":"2015-06-11T15:57:10.000Z",
        "netflow": {
          "app_id":"03:123",
          "app_name":"ntp",
          "input_snmp":3,
          "src_tos":0,
          "is_multicast":0,
          "icmp_type":0,
          "icmp_code":0,
          "mul_igmp_type":0,
          "tcp_flags":0,
          "out_dscp":0,
          "tcp_winsize":0,
          "first_switched":"2015-06-11T15:56:47.999Z",
          "last_switched":"2015-06-11T15:56:55.999Z",
          "output_snmp":2,
          "ipv4_ident":38811,
          "duration":8
          },
        "host":"10.10.10.10",
        "version":9,
        "flow_seq_num":7404748,
        "flowset_id":258,
        "ipv4_src_addr":"10.98.9.251",
        "ipv4_dst_addr":"17.253.48.247",
        "l4_src_port":123,
        "l4_dst_port":123,
        "direction":1,
        "protocol":17,
        "in_bytes":380,
        "in_pkts":5,
        "in_bytes_dir":-380,
        "@version":"1"
      }
      FNF
      :asa => "place for a event from asa"
    }
  end

  before {json_events.each { |k, v| json_events[k] = v.gsub(/\s+/, "") }}

  let(:dir_to_files) do
      File.dirname(__FILE__)
  end

  let(:client) do
    ["", "", "", "10.10.10.10"]
  end

  subject do
    LogStash::Inputs::Netflow.new(
        "port" => 9999,
        "exporters" => ["fnf" , "wlc"]).tap do |subj|
          expect {subj.register}.not_to raise_error
    end
  end

  let(:decode) do
    [].tap do |events|
      data.each do |payload|
        subject.decode(payload,client){|event| events << event}
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

    it "should decode wlc netflow" do
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

    it "should decode fnf netflow" do
      expect(decode[4].to_json).to eq(json_events[:fnf])
    end
  end
end