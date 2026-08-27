cask "bytetrawl" do
  version "1.0.3"
  sha256 "f3930b9e1e7992d64faff077870d85e9f23a79d9bc014cf16024e340f0a675e4"

  url "https://github.com/everettjf/homebrew-tap/releases/download/bytetrawl-v#{version}/ByteTrawl-#{version}-macos.zip"
  name "ByteTrawl"
  desc "Application, package, and binary inspection workbench"
  homepage "https://github.com/everettjf/bytetrawl"

  depends_on macos: :ventura
  depends_on arch: :arm64

  app "ByteTrawl.app"

  zap trash: "~/Library/Application Support/ByteTrawl"
end
