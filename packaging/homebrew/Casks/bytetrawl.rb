cask "bytetrawl" do
  version "0.1.0"
  sha256 "9e9a8508da02b9b757a5e3f08e2edf4bc0085703334b9d4bead11ea3ae342bdb"

  url "https://github.com/everettjf/bytetrawl/releases/download/v#{version}/ByteTrawl-#{version}-macos.zip"
  name "ByteTrawl"
  desc "Application, package, and binary inspection workbench"
  homepage "https://github.com/everettjf/bytetrawl"

  depends_on macos: ">= :ventura"
  depends_on arch: :arm64

  app "ByteTrawl.app"

  zap trash: "~/Library/Application Support/ByteTrawl"
end
