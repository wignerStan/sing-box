class SingBoxWigner < Formula
  desc "Universal proxy platform with native DAE and Tailscale integrations"
  homepage "https://github.com/wignerStan/sing-box"
  url "https://github.com/wignerStan/sing-box.git",
      revision: "9b472cfd6731db200886b7a010d053a235290ac6"
  version "1.14.0-wigner.2"
  license "GPL-3.0-or-later"
  version_scheme 1

  depends_on "go" => :build

  conflicts_with "sing-box", because: "both install a sing-box executable"

  def install
    ENV["CGO_ENABLED"] = "0"
    ENV["GOPROXY"] = "off"
    ENV["GOSUMDB"] = "off"
    ENV["GOTOOLCHAIN"] = "local"

    tags = %w[
      with_dae
      with_gvisor
      with_quic
      with_wireguard
      with_utls
      with_clash_api
      with_tailscale
    ]
    ldflags = "-s -w -X github.com/sagernet/sing-box/constant.Version=#{version}"

    system "go", "build",
           "-mod=vendor",
           "-trimpath",
           "-buildvcs=false",
           "-tags", tags.join(","),
           "-ldflags", ldflags,
           "-o", bin/"sing-box",
           "./cmd/sing-box"
    generate_completions_from_executable(bin/"sing-box", shell_parameter_format: :cobra)
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/sing-box version")

    (testpath/"config.json").write <<~JSON
      {"inbounds":[{"type":"mixed","listen":"127.0.0.1","listen_port":1080}]}
    JSON
    system bin/"sing-box", "check", "-c", testpath/"config.json"
    assert_match "tailscale", shell_output("#{bin}/sing-box api tailscale --help").downcase
  end
end
