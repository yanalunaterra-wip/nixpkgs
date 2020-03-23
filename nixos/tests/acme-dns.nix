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
    acme.imports = [ common ./common/acme/server ];

    acmedns = { nodes, pkgs, ... }: {
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
            "acme-dns.test. A ${ipOf nodes.acmedns}"
            "acme-dns.test. NS acme-dns.test."
          ];
        };
      };
    };

    coredns = { nodes, pkgs, ... }: {
      imports = [ common ];

      networking.firewall = {
        allowedTCPPorts = [ 53 ];
        allowedUDPPorts = [ 53 ];
      };

      environment.etc."coredns/zones/db.webserver.test" = {
        text = ''
          $ORIGIN webserver.test.
          @ 3600 SOA coredns.test. hostmaster.webserver.test. (
            1 ; serial
            86400 7200 600000 1
          )
          hello 3600 A ${ipOf nodes.webserver}
        '';
        mode = "0644";
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
            forward . ${ipOf nodes.acmedns}
          }

          webserver.test {
            auto {
              directory /etc/coredns/zones
              reload 1s
            }
          }
        '';
      };
    };

    webserver = { config, pkgs, ... }: {
      imports = [ common ./common/acme/client ];

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

          services.nginx.virtualHosts."hello.webserver.test" = {
            onlySSL = true;
            useACMEHost = "webserver.test";
            locations."/".root = pkgs.runCommand "root" {} ''
              mkdir $out
              echo "hello world" > $out/index.html
            '';
          };
        }
      ];
    };

    webclient.imports = [ common ./common/acme/client ];
  };

  testScript = ''
    import json

    start_all()

    acme.wait_for_unit("pebble.service")
    acmedns.wait_for_unit("acme-dns.service")
    coredns.wait_for_unit("coredns.service")


    def wait_for_acme_dns_check(_) -> bool:
        info = webserver.get_unit_info("acme-dns-webserver.test-check.service")
        return info["ActiveState"] == "failed"


    # Get the required CNAME record from the acme-dns-*-check.service
    # error message.
    retry(wait_for_acme_dns_check)
    print(
        webserver.succeed(
            "journalctl -fu acme-dns-webserver.test-check.service | grep -m 1 CNAME"
        )
    )
    askdjasd

    zone_file = "/etc/coredns/zones/db.webserver.test"
    coredns.succeed(
        f"echo '_acme-challenge 1 CNAME {acme_dns_domain}.' >> {zone_file}",
        f"sed -i 's/1 ; serial/2 ; serial/' {zone_file}",
    )

    webserver.start_job("acme-webserver.test.service")
    webserver.wait_for_unit("acme-webserver.test.service")
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
