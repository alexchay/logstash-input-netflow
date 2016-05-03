# encoding: utf-8
require_relative "../spec_helper"
require_relative "../support/client"

describe LogStash::Inputs::Netflow do

  before do
    srand(RSpec.configuration.seed)
  end

  let(:port)   { rand(1024..65535) }

  it_behaves_like "an interruptible input plugin" do
    let(:config) { { "port" => port } }
  end
end
