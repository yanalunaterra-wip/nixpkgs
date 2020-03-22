# TODO: Test services.acme-dns.server.api.tls once
# https://github.com/joohoi/acme-dns/issues/214 is fixed.

let
  ipOf = node: node.config.networking.primaryIPAddress;

  common = { lib, nodes, ... }: {
    networking.nameservers = lib.mkForce [ (ipOf nodes.coredns) ];
  };
in

import ./make-test-python.nix {
  name = "acme-dns";

  nodes = {
    acme.imports = [ ./common/acme/server common ];

    acme_dns = { nodes, pkgs, ... }: {
      imports = [ common ];

      networking.firewall = {
        allowedTCPPorts = [ 53 8053 ];
        allowedUDPPorts = [ 53 ];
      };

      services.acme-dns.server = {
        enable = true;
        api.ip = "0.0.0.0";
        general = {
          domain = "acme-dns.test";
          nsadmin = "hostmaster.acme-dns.test";
          records = [
            "acme-dns.test. A ${ipOf nodes.acme_dns}"
            "acme-dns.test. NS acme-dns.test."
          ];
        };
      };
    };

    coredns = { nodes, pkgs, ... }:
      let
        zoneFile = pkgs.writeText "db.webserver.test" ''
          $ORIGIN webserver.test.
          @     3600 SOA coredns.test. hostmaster. ( 2020032201 1 1 1 1 )
          hello   60 A   ${ipOf nodes.webserver}
        '';
      in
      {
        imports = [ common ];

        networking.firewall = {
          allowedTCPPorts = [ 53 ];
          allowedUDPPorts = [ 53 ];
        };

        services.coredns = {
          enable = true;
          config = ''
            acme.test {
              template IN A {
                answer "{{ .Name }} 60 A ${ipOf nodes.acme}"
              }
            }

            acme-dns.test {
              forward . ${ipOf nodes.acme_dns}
            }

            webserver.test {
              file db.webserver.test {
                reload 1s
              }
            }
          '';
        };

        systemd.services.coredns.serviceConfig.ExecStartPre = [
          "${pkgs.coreutils}/bin/cp --no-preserve=mode ${zoneFile} ${zoneFile.name}"
        ];
      };

    webclient.imports = [ ./common/acme/client common ];

    webserver = { config, pkgs, ... }: {
      imports = [ ./common/acme/client common ];

      security.acme.server = "https://acme.test/dir";

      services.acme-dns.client = {
        enable = true;
        domains."webserver.test" = { server = "http://acme-dns.test:8053"; };
      };

      security.acme.certs."webserver.test" = {
        domain = "*.webserver.test";
        user = "nginx";
        group = "nginx";
      };

      services.nginx.enable = true;

      nesting.clone = [
        {
          networking.firewall.allowedTCPPorts = [ 443 ];

          services.nginx.virtualHosts."hello.webserver.test" =
            let
              certDir = config.security.acme.certs."webserver.test".directory;
            in
            {
              onlySSL = true;
              sslCertificate = "${certDir}/cert.pem";
              sslTrustedCertificate = "${certDir}/full.pem";
              sslCertificateKey = "${certDir}/key.pem";
              locations."/".root = pkgs.runCommand "root" {} ''
                mkdir $out
                echo "hello world" > $out/index.html
              '';
            };
        }
      ];
    };
  };

  testScript = ''
    import json


    def wait_for_acme_dns_challenge(_) -> bool:
        return webserver.get_unit_info("acme-webserver.test")["ActiveState"] == "failed"


    start_all()

    acme.wait_for_unit("pebble.service")
    acme_dns.wait_for_unit("acme-dns.service")
    coredns.wait_for_unit("coredns.service")

    retry(wait_for_acme_dns_challenge)

    acme_dns_data = webserver.succeed("cat /var/lib/acme/webserver.test/acme-dns.json")
    acme_dns_domain = json.loads(acme_dns_data)["webserver.test"]["FullDomain"]

    webserver_zone_file = "/var/lib/coredns/db.webserver.test"
    coredns.succeed(
        f"echo _acme-challenge 60 CNAME {acme_dns_domain}. >> {webserver_zone_file}"
    )
    coredns.succeed(f"sed -i s/2020032201/2020032202/ {webserver_zone_file}")

    webserver.start_job("acme-webserver.test")
    webserver.wait_for_unit("acme-webserver.test")

    webserver.succeed(
        "/run/current-system/fine-tune/child-1/bin/switch-to-configuration test"
    )

    webclient.wait_for_unit("default.target")

    webclient.succeed("curl https://acme.test:15000/roots/0 > /tmp/ca.crt")
    webclient.succeed("curl https://acme.test:15000/intermediate-keys/0 >> /tmp/ca.crt")
    webclient.succeed(
        "curl --cacert /tmp/ca.crt https://hello.webserver.test | grep -qF 'hello world'"
    )
  '';
}
