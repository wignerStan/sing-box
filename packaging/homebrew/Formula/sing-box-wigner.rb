class SingBoxWigner < Formula
  desc "Universal proxy platform with native DAE and Tailscale integrations"
  homepage "https://github.com/wignerStan/sing-box"
  url "https://github.com/wignerStan/sing-box/releases/download/v1.14.0-wigner.1/sing-box-v1.14.0-wigner.1-source.tar.gz"
  version "1.14.0-wigner.1"
  sha256 "0f268c47e7e9603fcb1e83237ecd28646921a08b93a374df8bc24c7e4d4f4085"
  license "GPL-3.0-or-later"

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
