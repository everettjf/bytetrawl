cask "bytetrawl" do
  version "1.1.4"
  sha256 "3b7da2bd47c3a8a1b719c2d6180497908c32aa181f6109278ddc95f3846440ee"

  url "https://github.com/everettjf/homebrew-tap/releases/download/bytetrawl-v#{version}/ByteTrawl-#{version}-macos.zip"
  name "ByteTrawl"
  desc "Application, package, and binary inspection workbench"
  homepage "https://github.com/everettjf/bytetrawl"

  depends_on macos: :ventura
  depends_on arch: :arm64

  app "ByteTrawl.app"

  zap trash: "~/Library/Application Support/ByteTrawl"
end
